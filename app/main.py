# app/main.py
import subprocess
import sys
import shutil
import time
import zipfile
import datetime
import json
import asyncio
import functools
import uuid
from pathlib import Path
from typing import List, Optional, Annotated, Dict
from datetime import timedelta

import os
import signal

import httpx
from fastapi.responses import StreamingResponse
from fastapi import (
    Depends, FastAPI, File, UploadFile, Form, HTTPException, Query,
    WebSocket, WebSocketDisconnect, Request, Response, BackgroundTasks
)
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

import re

# --- Импорты из нашего пакета 'app' ---
from .config import (
    APPS_BASE_DIR, BACKUPS_DIR, NGINX_MAIN_CONF_FILE, NGINX_RELOAD_CMD,
    NSSM_PATH, BASE_PORT, ACCESS_TOKEN_EXPIRE_MINUTES, DB_FILE,
    PYTHON_EXECUTABLES, DEFAULT_PYTHON_EXECUTABLE, NGINX_SITES_DIR,
    NGINX_DIR, SSL_DIR, NGINX_LOCATIONS_DIR
)
# Используем новую базу данных SQLite
from .database_sqlite import (
    init_db, get_all_apps, get_app_by_name, add_or_update_app, delete_app,
    get_user_by_username
)
from .models import (
    App, AppAction, NginxConfig, DeploymentHistory, RestoreRequest,
    AppLogs, Token, AppCreate, AppConfigUpdate, NginxConfigList,
    SSLCertificateFile, DeployerSettingsUpdate, DeployerSettings
)
# Добавляем асинхронный и синхронный запуск команд
from .utils import run_command_sync, find_free_port, run_command_async
from .auth import verify_password, create_access_token, get_current_active_user, get_optional_current_user, User
from starlette.responses import RedirectResponse

# Инициализация приложения и шаблонов
app = FastAPI(title="Python Deployer API")
# Указываем Jinja2, где искать шаблоны. Важно, чтобы это было относительно папки, откуда запускается uvicorn.
templates = Jinja2Templates(directory="templates")  # Предполагаем, что HTML-файлы лежат в корне или доступны FastAPI.

# Инициализация БД (создание таблиц) при старте приложения
init_db()
client = httpx.AsyncClient()


# --- Управление WebSocket-соединениями для логов деплоя ---

class ConnectionManager:
    """Управляет активными WebSocket-соединениями и событиями готовности."""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        # НОВИНКА: Словарь для ожидания подключения клиента
        self.client_ready_events: Dict[str, asyncio.Event] = {}

    def register_task(self, task_id: str) -> asyncio.Event:
        """Регистрирует новую задачу и создает для нее событие ожидания."""
        event = asyncio.Event()
        self.client_ready_events[task_id] = event
        return event

    async def connect(self, websocket: WebSocket, task_id: str):
        """Принимает соединение и активирует событие готовности."""
        await websocket.accept()
        self.active_connections[task_id] = websocket
        # Если для этой задачи есть ожидающее событие, активируем его
        if task_id in self.client_ready_events:
            self.client_ready_events[task_id].set()

    def disconnect(self, task_id: str):
        """Отключает клиента и очищает связанные с ним данные."""
        if task_id in self.active_connections:
            del self.active_connections[task_id]
        if task_id in self.client_ready_events:
            del self.client_ready_events[task_id]

    async def send_message(self, message: str, task_id: str):
        """Отправляет сообщение клиенту, подключенному к этой задаче."""
        if task_id in self.active_connections:
            try:
                await self.active_connections[task_id].send_text(message)
            except RuntimeError as e:
                print(f"Failed to send message to task {task_id}: {e}")
                self.disconnect(task_id)


manager = ConnectionManager()


@app.websocket("/ws/deploy/{task_id}")
async def websocket_endpoint(websocket: WebSocket, task_id: str):
    """WebSocket-эндпоинт для стриминга логов деплоя."""
    await manager.connect(websocket, task_id)
    try:
        # Держим соединение открытым, пока клиент не отключится или сервер не закроет его
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(task_id)


@app.api_route("/api/proxy/{app_name}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_app(
        app_name: str,
        path: str,
        request: Request,
        current_user: User = Depends(get_current_active_user)
):
    """
    Эндпоинт, который работает как обратный прокси.
    Он принимает запрос, находит нужный порт приложения и перенаправляет
    запрос на http://localhost:<port>/<path>, а затем возвращает ответ.
    """
    app_info = get_app_by_name(app_name)
    if not app_info:
        raise HTTPException(status_code=404, detail="App to proxy not found")

    target_url = f"http://localhost:{app_info.port}/{path}"

    headers = dict(request.headers)
    headers["host"] = f"localhost:{app_info.port}"

    try:
        proxied_request = client.build_request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.query_params,
            content=await request.body()
        )

        proxied_response = await client.send(proxied_request, stream=True)

        return StreamingResponse(
            proxied_response.aiter_raw(),
            status_code=proxied_response.status_code,
            headers=proxied_response.headers
        )
    except httpx.ConnectError:
        raise HTTPException(status_code=502,
                            detail=f"Could not connect to the application '{app_name}' on port {app_info.port}. Is it running?")


# --- Эндпоинты аутентификации и UI ---

@app.post("/api/token", response_model=Token)
async def login_for_access_token(
        response: Response,
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """Эндпоинт для входа в систему, получения JWT и установки cookie."""
    user = get_user_by_username(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    response.set_cookie(
        key="deployer_token",
        value=access_token,
        httponly=True,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=False,  # Установите True, если используете HTTPS
        path="/"
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/logout")
async def logout(response: Response):
    """Удаляет аутентификационный cookie."""
    response.delete_cookie("deployer_token")
    return {"message": "Successfully logged out"}


def _get_app_final_status(app_name: str) -> str:
    """
    (СИНХРОННЫЙ HELPER)
    Проверяет статус службы Windows с помощью 'sc query' в цикле до 15 секунд.
    Возвращает 'running' или 'stopped' при успешном определении,
    или 'error', если статус не удалось определить за все попытки.
    """
    max_attempts = 15
    initial_delay = 3  # Задержка в 3 секунды перед первой проверкой
    poll_interval = 2  # Интервал между попытками

    print(f"DEBUG: Initial delay of {initial_delay}s before first status check for '{app_name}'.")
    time.sleep(initial_delay)

    for attempt in range(1, max_attempts + 1):
        print(f"DEBUG: Checking status for '{app_name}' (attempt {attempt}/{max_attempts})...")

        # Попытка 1: NSSM status (если вдруг заработает или даст полезную инфу)
        nssm_code, nssm_out, nssm_err = run_command_sync(f'"{NSSM_PATH}" status "{app_name}"', timeout=5)
        nssm_status_clean = nssm_out.strip().upper()
        if nssm_status_clean.startswith("'") and nssm_status_clean.endswith("'"):
            nssm_status_clean = nssm_status_clean[1:-1]
        elif nssm_status_clean.startswith('"') and nssm_status_clean.endswith('"'):
            nssm_status_clean = nssm_status_clean[1:-1]

        print(
            f"DEBUG: NSSM status raw: Code={nssm_code}, Out='{nssm_out}', Err='{nssm_err}', Clean='{nssm_status_clean}'")
        if nssm_code == 0:
            if nssm_status_clean == "SERVICE_RUNNING":
                print(f"DEBUG: NSSM reported SERVICE_RUNNING for '{app_name}'. Returning 'running'.")
                return "running"
            elif nssm_status_clean == "SERVICE_STOPPED":
                print(f"DEBUG: NSSM reported SERVICE_STOPPED for '{app_name}'. Returning 'stopped'.")
                return "stopped"
            # Если NSSM вернул 0, но статус не "RUNNING"/"STOPPED", то он не очень полезен, пробуем дальше

        # Попытка 2: sc query (более надежный метод)
        # sc query выдает информацию о службе, нам нужна строка STATE
        sc_code, sc_out, sc_err = run_command_sync(f'sc query "{app_name}"', timeout=5)
        print(f"DEBUG: SC query raw: Code={sc_code}, Out='{sc_out}', Err='{sc_err}'")

        if sc_code == 0:
            # Ищем строку "        STATE              : 4  RUNNING" или "        Состояние          : 4  RUNNING"
            # ИЗМЕНЕНИЕ ЗДЕСЬ: Добавляем 'Состояние' в регулярное выражение
            match = re.search(r"(STATE|СОСТОЯНИЕ)\s+:\s+\d+\s+(RUNNING|STOPPED)", sc_out, re.IGNORECASE)
            if match:
                sc_state = match.group(2).upper()  # Изменено на group(2) т.к. group(1) теперь "STATE" или "СОСТОЯНИЕ"
                print(f"DEBUG: SC query found state '{sc_state}' for '{app_name}'.")
                if sc_state == "RUNNING":
                    return "running"
                elif sc_state == "STOPPED":
                    return "stopped"
            else:

                # Если служба не найдена, sc query обычно возвращает 1060 ошибку.
                # Если найдена, но STATE не RUNNING/STOPPED, то это необычно.
                if "1060" in sc_err or "1060" in sc_out:  # Служба не существует
                    print(
                        f"WARNING: Service '{app_name}' not found by 'sc query'. It might not have been installed correctly yet. Retrying...")
                    # Продолжаем попытки, так как она может быть в процессе создания
                else:
                    print(
                        f"WARNING: 'sc query' for '{app_name}' returned Code=0 but could not parse state from output. Retrying...")

        else:
            # sc query вернет ненулевой код, если служба не найдена (ошибка 1060)
            if "1060" in sc_err or "1060" in sc_out:
                print(
                    f"WARNING: Service '{app_name}' not found by 'sc query' (error 1060). It might not have been installed correctly yet. Retrying...")
            else:
                print(f"ERROR: 'sc query' command failed for '{app_name}' (code={sc_code}): {sc_err}. Retrying...")

        time.sleep(poll_interval)  # Ждем перед следующей попыткой

    print(
        f"ERROR: Service status for '{app_name}' could not be determined after {max_attempts} attempts. Defaulting to 'error'.")
    return "error"


@app.get("/", response_class=HTMLResponse)
async def read_index(request: Request, current_user: Optional[User] = Depends(get_optional_current_user)):
    """
    Рендерит главную страницу. Если пользователь не авторизован,
    перенаправляет на страницу входа.
    """
    if current_user is None:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "python_versions": PYTHON_EXECUTABLES,
        "default_python_executable": DEFAULT_PYTHON_EXECUTABLE,  # Добавлено
        "current_user": current_user
    })


@app.get("/login", response_class=HTMLResponse)
async def read_login_page(request: Request):
    """Рендерит страницу входа."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/history", response_class=HTMLResponse)
async def read_history_page(request: Request, current_user: Optional[User] = Depends(get_optional_current_user)):
    """Рендерит страницу истории. Требует авторизации."""
    if current_user is None:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("history.html", {"request": request, "current_user": current_user})


@app.get("/logs", response_class=HTMLResponse)
async def read_logs_page(request: Request, current_user: Optional[User] = Depends(get_optional_current_user)):
    """Рендерит страницу логов. Требует авторизации."""
    if current_user is None:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("logs.html", {"request": request, "current_user": current_user})


# --- Логика развертывания (фоновые задачи) ---

async def perform_deployment(task_id: str, app_data: AppCreate, zip_file_path: Path):
    """
    Асинхронно выполняет весь процесс деплоя, безопасно запуская блокирующие
    операции в отдельных потоках.
    """
    name = app_data.name
    app_path = APPS_BASE_DIR / name
    backup_dir = BACKUPS_DIR / name
    logs_dir = app_path / "logs"
    log_file_path = logs_dir / "service.log"
    service_name = name
    nginx_conf_path = NGINX_SITES_DIR / f"{name}.conf"

    # Флаги для умного отката
    service_created = False
    nginx_config_created = False

    loop = asyncio.get_running_loop()

    # Даем WebSocket-клиенту время на подключение
    ready_event = manager.register_task(task_id)
    try:
        # Ждем подключения клиента не более 10 секунд
        await asyncio.wait_for(ready_event.wait(), timeout=10.0)
    except asyncio.TimeoutError:
        print(f"ERROR: WebSocket client for task {task_id} did not connect in time.")
        manager.disconnect(task_id)  # Очистка
        return  # Прерываем деплой

    try:
        # --- НОВЫЙ БЛОК: ПРОВЕРКА И УДАЛЕНИЕ "МЕРТВОЙ" СЛУЖБЫ ---
        await manager.send_message(f"=== Проверка на наличие существующей службы '{name}'... ===", task_id)

        # Вспомогательная функция для запуска синхронной команды в потоке
        async def run_sync_in_thread(command, cwd=None):
            return await loop.run_in_executor(None, functools.partial(run_command_sync, command, cwd=cwd))

        # Пробуем остановить и удалить, игнорируя ошибки (если службы нет, команда просто вернет ошибку)
        await run_sync_in_thread(f'"{NSSM_PATH}" stop "{service_name}"')
        await asyncio.sleep(1)  # Небольшая пауза
        code, out, err = await run_sync_in_thread(f'"{NSSM_PATH}" remove "{service_name}" confirm')
        if code == 0:
            await manager.send_message(f"[INFO] Обнаружена и удалена существующая служба '{name}'.", task_id)
        else:
            await manager.send_message("[INFO] Существующая служба не найдена, продолжаем.", task_id)
        # --- КОНЕЦ НОВОГО БЛОКА ---

        await asyncio.sleep(1.5)
        await manager.send_message(f"=== Начало развертывания приложения '{name}' (ID задачи: {task_id}) ===", task_id)

        # 1. Подготовка директорий (быстрая операция, можно оставить)
        app_path.mkdir(parents=True, exist_ok=True)
        backup_dir.mkdir(parents=True, exist_ok=True)
        logs_dir.mkdir(exist_ok=True)
        await manager.send_message("[1/7] Директории подготовлены.", task_id)

        # 2. Распаковка архива (блокирующая операция)
        await manager.send_message(f"[2/7] Распаковка ZIP-архива '{zip_file_path.name}'...", task_id)
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            await loop.run_in_executor(None, zip_ref.extractall, app_path)
        await manager.send_message("Архив успешно распакован.", task_id)

        # 3. Создание виртуального окружения (используем асинхронную версию)
        python_executable = app_data.python_executable or DEFAULT_PYTHON_EXECUTABLE
        venv_path = app_path / "venv"
        await manager.send_message(f"[3/7] Создание venv с помощью '{python_executable}'...", task_id)
        try:
            # yield from (async for) для потоковой передачи логов
            async for log_line in run_command_async(f'{python_executable} -m venv "{venv_path}"', cwd=str(app_path)):
                await manager.send_message(log_line, task_id)
        except subprocess.CalledProcessError:
            raise Exception("Не удалось создать виртуальное окружение. Проверьте путь к Python и права доступа.")

        # 4. Установка зависимостей (используем асинхронную версию)
        if (app_path / "requirements.txt").exists():
            pip_path = venv_path / "Scripts" / "pip.exe"
            await manager.send_message("[4/7] Установка зависимостей из requirements.txt...", task_id)
            try:
                # yield from (async for) для потоковой передачи логов
                async for log_line in run_command_async(f'"{pip_path}" install -r requirements.txt', cwd=str(app_path)):
                    await manager.send_message(log_line, task_id)
            except subprocess.CalledProcessError:
                raise Exception("Не удалось установить зависимости (pip install провалился).")
        else:
            await manager.send_message("[4/7] requirements.txt не найден, шаг пропущен.", task_id)

        # 5. Настройка службы Windows (NSSM)
        await manager.send_message("[5/7] Настройка службы Windows (NSSM)...", task_id)
        python_in_venv = venv_path / "Scripts" / "python.exe"

        final_start_script = app_data.start_script
        if 'uvicorn' in final_start_script:
            # Убеждаемся, что Uvicorn привязан к localhost
            final_start_script = re.sub(r'\s--host\s+\S+', '', final_start_script)  # Удаляем существующий --host
            final_start_script += ' --host 127.0.0.1'  # Добавляем принудительно
            await manager.send_message("[INFO] Обнаружен Uvicorn. Принудительная привязка к 127.0.0.1.", task_id)

        async def run_sync_in_thread(command, cwd=None):
            # Вспомогательная функция для запуска синхронной команды в потоке
            return await loop.run_in_executor(None, functools.partial(run_command_sync, command, cwd=cwd))

        code, _, err = await run_sync_in_thread(f'"{NSSM_PATH}" install "{service_name}" "{python_in_venv}"')
        if code != 0: raise Exception(f"NSSM install failed: {err}")
        service_created = True

        code, _, err = await run_sync_in_thread(
            f'"{NSSM_PATH}" set "{service_name}" AppParameters "{final_start_script}"')
        if code != 0: raise Exception(f"NSSM set AppParameters failed: {err}")

        code, _, err = await run_sync_in_thread(f'"{NSSM_PATH}" set "{service_name}" AppDirectory "{app_path}"')
        if code != 0: raise Exception(f"NSSM set AppDirectory failed: {err}")

        env_vars_str = f"PORT={app_data.port}"
        if app_data.env_vars:
            for key, value in app_data.env_vars.items():
                env_vars_str += f' {key}="{value}"'

        code, _, err = await run_sync_in_thread(
            f'"{NSSM_PATH}" set "{service_name}" AppEnvironmentExtra "{env_vars_str}"')
        if code != 0: raise Exception(f"NSSM set AppEnvironmentExtra failed: {err}")
        await manager.send_message("Переменные окружения установлены.", task_id)

        code, _, err = await run_sync_in_thread(f'"{NSSM_PATH}" set "{service_name}" AppStdout "{log_file_path}"')
        if code != 0: raise Exception(f"NSSM set AppStdout failed: {err}")

        code, _, err = await run_sync_in_thread(f'"{NSSM_PATH}" set "{service_name}" AppStderr "{log_file_path}"')
        if code != 0: raise Exception(f"NSSM set AppStderr failed: {err}")

        await manager.send_message("Служба NSSM настроена.", task_id)

        # 6. Автоматизация Nginx
        if app_data.nginx_proxy_target:
            await manager.send_message(f"[6/7] Настройка Nginx для '{app_data.nginx_proxy_target}'...", task_id)
            await loop.run_in_executor(None, _update_nginx_config_for_app,
                                       name,
                                       app_data.nginx_proxy_target,
                                       app_data.port,
                                       app_data.ssl_certificate_name,
                                       app_data.parent_domain)
            nginx_config_created = True  # Флаг того, что конфиг создан
            await manager.send_message(f"Конфигурация Nginx сохранена в {nginx_conf_path}", task_id)
            code, out, err = await run_sync_in_thread(NGINX_RELOAD_CMD)
            if code != 0:
                await manager.send_message(
                    f"[WARNING] Не удалось перезагрузить Nginx: {err or out}. Возможно, доступ будет некорректным.",
                    task_id)
            else:
                await manager.send_message("Nginx успешно перезагружен.", task_id)
        else:
            await manager.send_message("[6/7] Цель Nginx не указана, настройка Nginx пропущена.", task_id)

        # 7. Запуск службы
        await manager.send_message("[7/7] Запуск службы...", task_id)
        code, _, err = await run_sync_in_thread(f'"{NSSM_PATH}" start "{service_name}"')
        if code != 0:
            # Если NSSM start вернул ошибку, но сервис уже запущен, это не критическая ошибка
            if "already running" in err.lower() or "уже запущена" in err.lower():
                await manager.send_message(f"[WARNING] Служба '{service_name}' уже была запущена.", task_id)
            else:
                raise Exception(f"NSSM start failed: {err}")

        # Надежно получаем финальный статус
        final_status = await loop.run_in_executor(None, _get_app_final_status, name)

        # Сохранение в БД
        new_app = App(
            app_type="python_app",  # <-- РЕКОМЕНДАЦИЯ: Явно указываем тип приложения
            name=name, port=app_data.port, app_path=str(app_path), log_path=str(log_file_path),
            start_script=final_start_script,
            status=final_status, python_executable=python_executable, nginx_proxy_target=app_data.nginx_proxy_target,
            env_vars=app_data.env_vars, ssl_certificate_name=app_data.ssl_certificate_name,
            parent_domain=app_data.parent_domain
        )
        add_or_update_app(new_app)
        await manager.send_message(
            f"\n=== РАЗВЕРТЫВАНИЕ УСПЕШНО ЗАВЕРШЕНО! Финальный статус: {final_status.upper()} ===", task_id)

    except Exception as e:
        await manager.send_message(f"\n--- !!! ОШИБКА РАЗВЕРТЫВАНИЯ: {e} ---", task_id)

        # Диагностический блок: читаем логи приложения для отладки
        if log_file_path.exists() and log_file_path.stat().st_size > 0:
            await manager.send_message("\n--- Чтение лог-файла приложения для диагностики: ---", task_id)
            ready_event = manager.register_task(task_id)
            try:
                # Ждем подключения клиента не более 10 секунд
                await asyncio.wait_for(ready_event.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                print(f"ERROR: WebSocket client for task {task_id} did not connect in time.")
                manager.disconnect(task_id)  # Очистка
                return  # Прерываем деплой
            try:
                # Читаем последние строки лога (до 2000 символов)
                with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    log_content = f.read()
                if log_content:
                    # ИЗМЕНЕНИЕ ЗДЕСЬ: Добавляем task_id
                    await manager.send_message("==================== СОДЕРЖИМОЕ ЛОГА ====================", task_id)
                    await manager.send_message(log_content[-2000:], task_id)
                    await manager.send_message("=========================================================", task_id)
                else:
                    await manager.send_message("[Лог-файл пуст]", task_id)  # Добавляем task_id
            except Exception as log_e:
                await manager.send_message(f"[Не удалось прочитать лог-файл: {log_e}]", task_id)
        else:
            await manager.send_message("\n[Диагностика] Лог-файл приложения не создан или пуст.", task_id)

        await manager.send_message("\nВыполняется откат изменений...", task_id)

        # Откат: блокирующие операции также запускаем в потоке
        if service_created:
            await manager.send_message("Удаление службы NSSM...", task_id)
            await run_sync_in_thread(f'"{NSSM_PATH}" remove "{service_name}" confirm')

        await loop.run_in_executor(None, shutil.rmtree, app_path, True)

        if nginx_config_created:
            await manager.send_message("Удаление конфигурации Nginx...", task_id)
            if nginx_conf_path.exists():
                nginx_conf_path.unlink()
                await run_sync_in_thread(NGINX_RELOAD_CMD)

        await manager.send_message("Откат завершен. Закройте это окно.", task_id)
    finally:
        await asyncio.sleep(2)  # Даем клиенту время увидеть последние сообщения
        await manager.send_message("CLOSE_CONNECTION", task_id)
        manager.disconnect(task_id)


async def perform_static_deployment(task_id: str, app_data: AppCreate, zip_file_path: Path):
    """Асинхронно выполняет процесс деплоя статического сайта с полным логированием."""
    name = app_data.name
    app_path = APPS_BASE_DIR / name
    backup_dir = BACKUPS_DIR / name

    # Мы не можем заранее знать точный путь к конфигу, так как он зависит от домена/пути.
    # Поэтому будем управлять флагом, а не путем.
    nginx_config_created = False
    loop = asyncio.get_running_loop()

    # Даем WebSocket-клиенту время на подключение
    ready_event = manager.register_task(task_id)
    try:
        # Ждем подключения клиента не более 10 секунд
        await asyncio.wait_for(ready_event.wait(), timeout=10.0)
    except asyncio.TimeoutError:
        print(f"ERROR: WebSocket client for task {task_id} did not connect in time.")
        manager.disconnect(task_id)  # Очистка
        return  # Прерываем деплой

    try:
        await manager.send_message(f"=== Начало развертывания статического сайта '{name}' ===", task_id)

        # 1. Подготовка директорий
        await manager.send_message("[1/3] Подготовка директорий...", task_id)
        app_path.mkdir(parents=True, exist_ok=True)
        backup_dir.mkdir(parents=True, exist_ok=True)
        await manager.send_message(" -> Директории успешно подготовлены.", task_id)

        # 2. Распаковка архива
        await manager.send_message(f"[2/3] Распаковка архива '{zip_file_path.name}'...", task_id)
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            await loop.run_in_executor(None, zip_ref.extractall, app_path)
        await manager.send_message(" -> Архив успешно распакован.", task_id)

        # 3. Настройка Nginx
        if not app_data.nginx_proxy_target:
            raise Exception("Для статического сайта обязательно должен быть указан 'Путь или Домен (Nginx)'.")

        await manager.send_message(f"[3/3] Настройка Nginx для '{app_data.nginx_proxy_target}'...", task_id)
        await loop.run_in_executor(None, _update_nginx_config_for_app, name,
                                   app_data.nginx_proxy_target,
                                   None,  # Порт не нужен
                                   app_data.ssl_certificate_name,
                                   app_data.parent_domain,
                                   "static_site")
        nginx_config_created = True
        await manager.send_message(" -> Конфигурация Nginx создана. Перезагрузка...", task_id)

        code, out, err = await loop.run_in_executor(None, functools.partial(run_command_sync, NGINX_RELOAD_CMD))
        if code != 0:
            await manager.send_message(f" -> [WARNING] Не удалось перезагрузить Nginx: {err or out}", task_id)
        else:
            await manager.send_message(" -> Nginx успешно перезагружен.", task_id)

        # Сохранение в БД
        new_app = App(
            app_type="static_site",
            name=name,
            app_path=str(app_path),
            status="running",
            nginx_proxy_target=app_data.nginx_proxy_target,
            ssl_certificate_name=app_data.ssl_certificate_name,
            parent_domain=app_data.parent_domain,
            port=0,
            start_script=""
        )
        add_or_update_app(new_app)
        await manager.send_message(f"\n=== РАЗВЕРТЫВАНИЕ УСПЕШНО ЗАВЕРШЕНО! ===", task_id)

    except Exception as e:
        await manager.send_message(f"\n--- !!! ОШИБКА РАЗВЕРТЫВАНИЯ: {e} ---", task_id)
        await manager.send_message("\nВыполняется откат изменений...", task_id)

        await loop.run_in_executor(None, shutil.rmtree, app_path, True)

        # Умный откат конфига Nginx
        if nginx_config_created:
            await manager.send_message("Откат конфигурации Nginx...", task_id)
            # Вызываем ту же функцию, но с пустыми параметрами, чтобы она удалила конфиги
            try:
                await loop.run_in_executor(None, _update_nginx_config_for_app,
                                           name, None, None, None, app_data.parent_domain, "static_site")
                await loop.run_in_executor(None, functools.partial(run_command_sync, NGINX_RELOAD_CMD))
                await manager.send_message(" -> Конфигурация Nginx удалена.", task_id)
            except Exception as nginx_err:
                await manager.send_message(f" -> [WARNING] Ошибка при откате конфига Nginx: {nginx_err}", task_id)

        await manager.send_message("Откат завершен.", task_id)
    finally:
        await asyncio.sleep(2)
        await manager.send_message("CLOSE_CONNECTION", task_id)
        manager.disconnect(task_id)

def _redeploy_from_zip(app_info: App, zip_path: Path):
    """
    (СИНХРОННЫЙ) Вспомогательный helper для обновления/восстановления из ZIP.
    Предполагает, что сервис уже остановлен.
    """
    app_path = Path(app_info.app_path)
    venv_path = app_path / "venv"
    pip_path = venv_path / "Scripts" / "pip.exe"

    # 1. Очищаем директорию приложения, но СОХРАНЯЕМ venv и logs
    for item in app_path.iterdir():
        if item.is_dir() and item.name not in ["venv", "logs"]:
            shutil.rmtree(item)
        elif item.is_file():
            item.unlink()

    # 2. Распаковываем новый архив
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(app_path)
    except zipfile.BadZipFile:
        raise Exception("Provided file is not a valid ZIP archive.")

    # 3. Устанавливаем зависимости из нового requirements.txt (если есть)
    if (app_path / "requirements.txt").exists():
        code, _, err = run_command_sync(f'"{pip_path}" install -r requirements.txt', cwd=str(app_path))
        if code != 0:
            raise Exception(f"Failed to install dependencies: {err}. Please check logs.")


# --- НОВАЯ HELPER-ФУНКЦИЯ для управления конфигом Nginx ---
def _update_nginx_config_for_app(
        app_name: str,
        nginx_proxy_target: Optional[str],
        port: Optional[int],
        ssl_certificate_name: Optional[str],
        parent_domain: Optional[str] = None,
        app_type: str = "python_app"
):
    """
    Создает/обновляет конфиг Nginx.
    - Для доменов: создает файл в nginx-sites с include на свою папку в nginx-locations.
    - Для путей: требует parent_domain и создает файл в папке nginx-locations/parent_domain/.
    """
    # Полная очистка старых конфигов
    site_conf_path = NGINX_SITES_DIR / f"{app_name}.conf"
    if site_conf_path.exists(): site_conf_path.unlink()

    # Для путей нужно найти и удалить старый файл в его старой родительской папке.
    # Это более сложная логика, пока что просто удаляем по новому parent_domain.
    if parent_domain and nginx_proxy_target and nginx_proxy_target.startswith('/'):
        old_location_folder = NGINX_LOCATIONS_DIR / parent_domain
        old_location_conf = old_location_folder / f"{app_name}.conf"
        if old_location_conf.exists(): old_location_conf.unlink()

    if not nginx_proxy_target:
        return

    is_path_target = nginx_proxy_target.startswith('/')
    app_path = APPS_BASE_DIR / app_name  # Определяем путь к файлам здесь

    if is_path_target:
        if not parent_domain:
            raise ValueError("Parent domain is required for path-based routing.")

        location_folder = NGINX_LOCATIONS_DIR / parent_domain
        location_folder.mkdir(exist_ok=True)
        location_conf_path = location_folder / f"{app_name}.conf"

        path_prefix = nginx_proxy_target.rstrip('/')

        # --- ИСПРАВЛЕНИЕ ЗДЕСЬ ---
        location_content = ""
        if app_type == "static_site":
            # --- ИСПОЛЬЗУЕМ БОЛЕЕ НАДЕЖНЫЙ 'root' ВМЕСТО 'alias' ---
            # root указывает на родительскую папку 'apps', а Nginx сам достраивает путь из URI.
            apps_root_dir = APPS_BASE_DIR.as_posix()

            location_content = f"""
            # Config for static site {app_name} at location {path_prefix}
            location {path_prefix} {{
                root {apps_root_dir};
                index  index.html index.htm;
                try_files $uri $uri/ {path_prefix}/index.html =404;
            }}
            """
        else:  # python_app
            if not path_prefix.endswith('/'): path_prefix += '/'
            location_content = f"""
    # Config for {app_name} at location {path_prefix}
    location {path_prefix} {{
        proxy_pass http://localhost:{port}/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
    """
        location_conf_path.write_text(location_content, encoding="utf-8")

    else:  # is_domain_target
        server_name = nginx_proxy_target
        location_folder_for_domain = NGINX_LOCATIONS_DIR / server_name
        location_folder_for_domain.mkdir(exist_ok=True)

        content_block = ""
        app_path = APPS_BASE_DIR / app_name

        if app_type == "static_site":
            # Конфиг для статики
            content_block = f"""
            location / {{
                root   {app_path.as_posix()};
                index  index.html index.htm;
                try_files $uri $uri/ /index.html; # Для SPA-приложений
            }}"""
        else:
            # Существующий конфиг для проксирования
            content_block = f"""
            location / {{
                proxy_pass http://localhost:{port};
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
            }}"""

        use_ssl = False
        ssl_config_block = ""
        if ssl_certificate_name:
            cert_dir = SSL_DIR / ssl_certificate_name
            cert_path = cert_dir / "fullchain.pem"
            key_path = cert_dir / "privkey.pem"
            if cert_path.exists() and key_path.exists():
                use_ssl = True
                ssl_config_block = f"""
    listen 443 ssl;
    ssl_certificate {cert_path.as_posix()};
    ssl_certificate_key {key_path.as_posix()};
    ssl_protocols TLSv1.2 TLSv1.3;
"""

        include_line = f"    include {location_folder_for_domain.as_posix()}/*.conf;"

        final_config = ""
        if use_ssl:
            final_config += f"""
server {{
    listen 80;
    server_name {server_name};
    location / {{
        return 301 https://$host$request_uri;
    }}
}}

server {{
    {ssl_config_block}
    server_name {server_name};
    {content_block}
    {include_line}
}}
"""
        else:
            final_config += f"""
server {{
    listen 80;
    server_name {server_name};
    {content_block}
    {include_line}
}}
"""
        site_conf_path.write_text(final_config, encoding="utf-8")

# --- Эндпоинты API для управления приложениями ---

@app.get("/api/apps", response_model=List[App])
async def get_apps_api(current_user: Annotated[User, Depends(get_current_active_user)]):
    """
    Получает список всех развернутых приложений. Для Python-приложений
    выполняет живую проверку статуса. Статические сайты возвращаются как есть.
    """
    apps_from_db = get_all_apps()

    python_apps_to_check = []
    static_apps = []

    # Разделяем приложения на два типа
    for app_info in apps_from_db:
        if app_info.app_type == "python_app":
            python_apps_to_check.append(check_and_update_app_status(app_info))
        else:  # static_site
            static_apps.append(app_info)

    # Запускаем проверки параллельно только для Python-приложений
    if python_apps_to_check:
        updated_python_apps = await asyncio.gather(*python_apps_to_check)
        # Объединяем результаты
        return updated_python_apps + static_apps
    else:
        # Если Python-приложений нет, просто возвращаем статические
        return static_apps


async def check_and_update_app_status(app_info: App) -> App:
    """
    Вспомогательная асинхронная функция для проверки статуса одного приложения.
    Обрабатывает больше типов ошибок соединения как 'stopped'.
    """
    live_status = "stopped"  # Статус по умолчанию
    target_url = f"http://localhost:{app_info.port}/"

    try:
        # 1. Отправляем GET-запрос с коротким тайм-аутом
        await client.get(target_url, timeout=2.0)
        live_status = "running"

    except (httpx.ConnectError, httpx.ConnectTimeout):
        live_status = "stopped"

    except httpx.ReadTimeout:
        # Приложение запущено, но "зависло". Это явная ошибка.
        live_status = "error"
    except Exception as e:
        # Ловим все остальные непредвиденные ошибки
        print(f"Unexpected error during health check for {app_info.name}: {e}")
        live_status = "error"

    # 2. Если статус в БД отличается от реального, обновляем его
    if app_info.status != live_status:
        print(
            f"Health check for '{app_info.name}': DB says '{app_info.status}', reality is '{live_status}'. Updating DB.")
        app_info.status = live_status
        add_or_update_app(app_info)  # Сохраняем актуальный статус в БД

    return app_info


@app.post("/api/deploy")
async def deploy_app(
        current_user: Annotated[User, Depends(get_current_active_user)],
        app_type: str = Form("python_app"),
        name: str = Form(...),
        start_script: str = Form("main.py"),
        port: Optional[int] = Form(None),
        python_executable: Optional[str] = Form(None),
        nginx_proxy_target: Optional[str] = Form(None),
        ssl_certificate_name: Optional[str] = Form(None),
        parent_domain: Optional[str] = Form(None),
        env_vars_str: Optional[str] = Form(None),
        zip_file: UploadFile = File(...)
):
    """
    Легковесный эндпоинт для запуска процесса развертывания.
    Валидирует данные, сохраняет zip, запускает фоновую задачу и немедленно возвращает task_id.
    """
    if get_app_by_name(name):
        raise HTTPException(status_code=400, detail=f"App with name '{name}' already exists.")

    if nginx_proxy_target and nginx_proxy_target.strip().startswith('/'):
        if not parent_domain:
            raise HTTPException(status_code=400, detail="A parent domain must be selected for path-based routing.")

        all_apps = get_all_apps()
        for app in all_apps:
            if app.nginx_proxy_target == nginx_proxy_target.strip() and app.parent_domain == parent_domain:
                raise HTTPException(
                    status_code=409,
                    detail=f"Path '{nginx_proxy_target}' is already in use by app '{app.name}' on domain '{parent_domain}'. Please choose a different path."
                )

    if nginx_proxy_target:
        nginx_proxy_target = nginx_proxy_target.strip()
        if not nginx_proxy_target.startswith('/'):
            if not re.match(r"^[a-zA-Z0-9.-]+$", nginx_proxy_target):
                raise HTTPException(status_code=400,
                                    detail="Invalid Nginx domain name. Use only letters, numbers, hyphens, and dots.")

    apps = get_all_apps()
    existing_ports = {app.port for app in apps if app.port is not None} # Добавлена проверка на None
    final_port = None
    if app_type == "python_app":
        if port and port in existing_ports:
            raise HTTPException(status_code=400, detail=f"Port {port} is already used.")
        final_port = port if port else find_free_port(BASE_PORT, existing_ports)

    env_vars = {}
    if env_vars_str:
        for line in env_vars_str.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                env_vars[key.strip()] = value.strip()

    backup_dir = BACKUPS_DIR / name
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"deploy_{timestamp}_{zip_file.filename}"
    backup_zip_path = backup_dir / backup_filename

    try:
        with open(backup_zip_path, "wb") as buffer:
            while content := await zip_file.read(1024 * 1024):
                buffer.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not save uploaded file: {e}")
    finally:
        await zip_file.close()

    app_data = AppCreate(
        app_type=app_type,
        name=name, start_script=start_script, port=final_port,
        python_executable=python_executable,
        nginx_proxy_target=nginx_proxy_target,
        ssl_certificate_name=ssl_certificate_name,
        parent_domain=parent_domain,
        env_vars=env_vars
    )

    task_id = str(uuid.uuid4())
    if app_type == "static_site":
        asyncio.create_task(perform_static_deployment(task_id, app_data, backup_zip_path))
    else:
        asyncio.create_task(perform_deployment(task_id, app_data, backup_zip_path))

    # --- ИСПРАВЛЕНИЕ ЗДЕСЬ ---
    # Этот return должен быть на том же уровне, что и if/else, чтобы выполняться для обоих случаев.
    return JSONResponse(status_code=202, content={"message": "Deployment process started", "task_id": task_id})


@app.put("/api/apps/{app_name}/config")
def update_app_config(
        app_name: str,
        config: AppConfigUpdate,
        current_user: Annotated[User, Depends(get_current_active_user)]
):
    """Обновляет конфигурацию существующего приложения (Python или статика)."""
    app_info = get_app_by_name(app_name)
    if not app_info:
        raise HTTPException(status_code=404, detail="App not found")

    # --- Общая валидация для обоих типов ---
    if config.nginx_proxy_target and config.nginx_proxy_target.strip().startswith('/'):
        if not config.parent_domain:
            raise HTTPException(status_code=400, detail="A parent domain must be selected for path-based routing.")

        all_apps = get_all_apps()
        for app in all_apps:
            if app.name != app_name:
                if app.nginx_proxy_target == config.nginx_proxy_target.strip() and app.parent_domain == config.parent_domain:
                    raise HTTPException(
                        status_code=409,
                        detail=f"Path '{config.nginx_proxy_target}' is already in use by app '{app.name}' on domain '{config.parent_domain}'. Please choose a different path."
                    )

    # Уточненная проверка изменений в конфиге Nginx
    nginx_config_changed = (
            app_info.port != config.port or
            app_info.nginx_proxy_target != config.nginx_proxy_target or
            app_info.ssl_certificate_name != config.ssl_certificate_name or
            app_info.parent_domain != config.parent_domain
    )

    # --- Логика для статического сайта ---
    if app_info.app_type == "static_site":
        if nginx_config_changed:
            _update_nginx_config_for_app(app_name,
                                         config.nginx_proxy_target,
                                         None,  # port is always None
                                         config.ssl_certificate_name,
                                         config.parent_domain,
                                         "static_site")
            run_command_sync(NGINX_RELOAD_CMD, cwd=str(NGINX_DIR))

        # Обновляем данные в БД
        app_info.nginx_proxy_target = config.nginx_proxy_target
        app_info.ssl_certificate_name = config.ssl_certificate_name
        app_info.parent_domain = config.parent_domain
        add_or_update_app(app_info)
        return {"message": f"Configuration for static site '{app_name}' updated successfully."}

    # --- Логика для Python-приложения (существующий код с улучшениями) ---
    if config.port != app_info.port:
        apps = get_all_apps()
        existing_ports = {app.port for app in apps if app.name != app_name and app.port is not None}
        if config.port in existing_ports:
            raise HTTPException(status_code=400, detail=f"Port {config.port} is already used by another app.")

    original_status_was_running = (app_info.status == "running")

    try:
        if original_status_was_running:
            run_command_sync(f'"{NSSM_PATH}" stop "{app_name}"')
            time.sleep(2)

        final_start_script = config.start_script
        if 'uvicorn' in final_start_script:
            final_start_script = re.sub(r'\s--host\s+\S+', '', final_start_script)
            final_start_script += ' --host 127.0.0.1'

        run_command_sync(f'"{NSSM_PATH}" set "{app_name}" AppParameters "{final_start_script}"')
        env_vars_str = f"PORT={config.port}"
        if config.env_vars:
            for key, value in config.env_vars.items():
                env_vars_str += f' {key}="{value}"'
        run_command_sync(f'"{NSSM_PATH}" set "{app_name}" AppEnvironmentExtra "{env_vars_str}"')

        if nginx_config_changed:
            _update_nginx_config_for_app(app_name,
                                         config.nginx_proxy_target,
                                         config.port,
                                         config.ssl_certificate_name,
                                         config.parent_domain,
                                         "python_app")  # Явно указываем тип
            run_command_sync(NGINX_RELOAD_CMD, cwd=str(NGINX_DIR))

        app_info.port = config.port
        app_info.start_script = final_start_script
        app_info.nginx_proxy_target = config.nginx_proxy_target
        app_info.ssl_certificate_name = config.ssl_certificate_name
        app_info.env_vars = config.env_vars
        app_info.parent_domain = config.parent_domain  # Добавлено обновление этого поля

        if original_status_was_running:
            run_command_sync(f'"{NSSM_PATH}" start "{app_name}"')
            app_info.status = _get_app_final_status(app_name)
        else:
            app_info.status = "stopped"

        add_or_update_app(app_info)

        return {"message": f"Configuration for '{app_name}' updated successfully."}

    except Exception as e:
        if original_status_was_running:
            run_command_sync(f'"{NSSM_PATH}" start "{app_name}"')
            app_info.status = _get_app_final_status(app_name)
            add_or_update_app(app_info)
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {str(e)}")


# --- НОВЫЕ ЭНДПОИНТЫ ДЛЯ УПРАВЛЕНИЯ SSL ---

@app.get("/api/ssl/certificates", response_model=List[SSLCertificateFile])
async def list_ssl_certificates(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Возвращает список загруженных SSL-сертификатов (по их именам)."""
    if not SSL_DIR.exists():
        return []

    certs = []
    for item in SSL_DIR.iterdir():
        if item.is_dir():
            # Проверяем, что внутри есть файлы сертификата и ключа
            if (item / "fullchain.pem").exists() and (item / "privkey.pem").exists():
                certs.append(SSLCertificateFile(name=item.name))
    return sorted(certs, key=lambda c: c.name)


@app.post("/api/ssl/certificates")
async def upload_ssl_certificate(
        current_user: Annotated[User, Depends(get_current_active_user)],
        name: str = Form(...),
        cert_file: UploadFile = File(..., description="Файл сертификата (fullchain.pem)"),
        key_file: UploadFile = File(..., description="Файл приватного ключа (privkey.pem)")
):
    """Загружает новый SSL сертификат."""
    # Валидация имени, чтобы избежать '..' и других опасных символов
    if not re.match(r"^[a-zA-Z0-9._-]+$", name):
        raise HTTPException(status_code=400,
                            detail="Invalid certificate name. Use only letters, numbers, dots, underscores, and hyphens.")

    cert_dir = SSL_DIR / name
    if cert_dir.exists():
        raise HTTPException(status_code=400, detail=f"Certificate with name '{name}' already exists.")

    try:
        cert_dir.mkdir(parents=True, exist_ok=True)

        # Сохраняем файлы с предсказуемыми именами
        cert_path = cert_dir / "fullchain.pem"
        key_path = cert_dir / "privkey.pem"

        with open(cert_path, "wb") as buffer:
            shutil.copyfileobj(cert_file.file, buffer)

        with open(key_path, "wb") as buffer:
            shutil.copyfileobj(key_file.file, buffer)

        return {"message": f"Certificate '{name}' uploaded successfully."}

    except Exception as e:
        # Откат в случае ошибки
        if cert_dir.exists():
            shutil.rmtree(cert_dir)
        raise HTTPException(status_code=500, detail=f"Failed to save certificate files: {e}")


@app.delete("/api/ssl/certificates/{cert_name}")
async def delete_ssl_certificate(cert_name: str, current_user: Annotated[User, Depends(get_current_active_user)]):
    """Удаляет SSL сертификат."""
    if not re.match(r"^[a-zA-Z0-9._-]+$", cert_name):
        raise HTTPException(status_code=400, detail="Invalid certificate name.")

    cert_dir = SSL_DIR / cert_name
    if not cert_dir.is_dir():
        raise HTTPException(status_code=404, detail=f"Certificate '{cert_name}' not found.")

    try:
        shutil.rmtree(cert_dir)
        return {"message": f"Certificate '{cert_name}' deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete certificate: {e}")

@app.post("/api/apps/{app_name}/actions")
def control_app(app_name: str, payload: AppAction, current_user: Annotated[User, Depends(get_current_active_user)]):
    """Управляет службой (start, stop, restart)."""
    app_info = get_app_by_name(app_name)
    if not app_info:
        raise HTTPException(status_code=404, detail="App not found")

    action = payload.action
    if action == "restart":
        run_command_sync(f'"{NSSM_PATH}" stop "{app_info.name}"')
        time.sleep(2)  # Ждем, чтобы служба гарантированно остановилась
        code, out, err = run_command_sync(f'"{NSSM_PATH}" start "{app_info.name}"')
    else:
        code, out, err = run_command_sync(f'"{NSSM_PATH}" {action} "{app_info.name}"')

    # Обработка случая, когда сервис уже запущен, а мы даем команду start
    if action == "start" and code != 0 and ("уже запущена" in err.lower() or "already running" in err.lower()):
        app_info.status = "running"  # В этом случае, он действительно запущен
        add_or_update_app(app_info)
        return {"message": f"App '{app_name}' is already running.", "status": app_info.status}

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to {action} app: {err or out}")

    # Надежно получаем финальный статус
    app_info.status = _get_app_final_status(app_name)
    add_or_update_app(app_info)
    return {"message": f"App '{app_name}' {action}ed successfully.", "status": app_info.status}


@app.delete("/api/apps/{app_name}")
def delete_app_api(app_name: str, background_tasks: BackgroundTasks, current_user: Annotated[User, Depends(get_current_active_user)]):
    """Полное удаление приложения с принудительным завершением процесса."""
    app_info = get_app_by_name(app_name)
    if not app_info:
        raise HTTPException(status_code=404, detail="App not found")

    backup_dir = BACKUPS_DIR / app_name

    try:
        # Шаги 1 и 2: Управление сервисом, применимо только к Python-приложениям
        if app_info.app_type == "python_app":
            # 1. Остановить и принудительно завершить процесс
            run_command_sync(f'"{NSSM_PATH}" stop "{app_name}"')
            time.sleep(1)
            try:
                netstat_cmd = f'netstat -aon | findstr "LISTENING" | findstr ":{app_info.port}"'
                code, out, err = run_command_sync(netstat_cmd)
                if code == 0 and out:
                    pid = int(out.strip().split()[-1])
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.5)
                    os.kill(pid, signal.SIGKILL)
            except Exception:
                pass  # Игнорируем ошибки, если процесс уже завершен

            # 2. Удалить службу NSSM
            run_command_sync(f'"{NSSM_PATH}" remove "{app_name}" confirm')

        # 3. Удалить файлы приложения (общий шаг)
        if Path(app_info.app_path).exists():
            shutil.rmtree(app_info.app_path)

        # 4. Удалить бекапы
        if backup_dir.exists():
            shutil.rmtree(backup_dir)

        # --- НАЧАЛО ИСПРАВЛЕНИЙ ---
        # 5. Умное удаление конфига Nginx
        config_deleted = False
        # Если это домен, удаляем файл из nginx-sites и папку из nginx-locations
        if app_info.nginx_proxy_target and not app_info.nginx_proxy_target.startswith('/'):
            site_conf_path = NGINX_SITES_DIR / f"{app_name}.conf"
            if site_conf_path.exists():
                site_conf_path.unlink()
                config_deleted = True

            location_folder = NGINX_LOCATIONS_DIR / app_info.nginx_proxy_target
            if location_folder.exists():
                shutil.rmtree(location_folder)

        # Если это путь, находим его конфиг в папке родительского домена и удаляем
        elif app_info.parent_domain:
            location_folder = NGINX_LOCATIONS_DIR / app_info.parent_domain
            location_conf_path = location_folder / f"{app_name}.conf"
            if location_conf_path.exists():
                location_conf_path.unlink()
                config_deleted = True

        if config_deleted:
            # --- ИСПРАВЛЕНИЕ: Перезагружаем Nginx в фоне ПОСЛЕ отправки ответа ---
            background_tasks.add_task(run_command_sync, NGINX_RELOAD_CMD, cwd=str(NGINX_DIR))
            # --- КОНЕЦ ИСПРАВЛЕНИЙ ---

            # 6. Удалить из БД
        delete_app(app_name)
        return {"message": f"App '{app_name}' and its configs, backups, and service deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete app: {str(e)}")


@app.post("/api/apps/{app_name}/update")
def update_app(app_name: str, current_user: Annotated[User, Depends(get_current_active_user)],
               zip_file: UploadFile = File(...)):
    """Обновляет приложение из нового ZIP-архива."""
    app_info = get_app_by_name(app_name)
    if not app_info:
        raise HTTPException(status_code=404, detail="App not found")

    # 1. Сохраняем новый zip как бекап
    backup_dir = BACKUPS_DIR / app_name
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"update_{timestamp}_{zip_file.filename}"
    backup_zip_path = backup_dir / backup_filename
    with open(backup_zip_path, "wb") as buffer:
        shutil.copyfileobj(zip_file.file, buffer)

    try:
        # --- НАЧАЛО ИЗМЕНЕНИЙ ---
        if app_info.app_type == "python_app":
            # Логика обновления для Python приложения
            run_command_sync(f'"{NSSM_PATH}" stop "{app_name}"')
            time.sleep(2)
            _redeploy_from_zip(app_info, backup_zip_path)
            run_command_sync(f'"{NSSM_PATH}" start "{app_name}"')
            app_info.status = _get_app_final_status(app_name)
            add_or_update_app(app_info)
            return {
                "message": f"App '{app_name}' updated and restarted successfully. Final status: {app_info.status.upper()}"
            }

        elif app_info.app_type == "static_site":
            # Логика обновления для статического сайта
            app_path = Path(app_info.app_path)
            # 1. Полностью очищаем папку
            shutil.rmtree(app_path)
            app_path.mkdir()
            # 2. Распаковываем новый архив
            with zipfile.ZipFile(backup_zip_path, 'r') as zip_ref:
                zip_ref.extractall(app_path)
            # 3. Перезагружаем Nginx, чтобы он подхватил новые файлы
            run_command_sync(NGINX_RELOAD_CMD)
            # Статус у статики не меняется, но можно пересохранить на всякий случай
            add_or_update_app(app_info)
            return {"message": f"Static site '{app_name}' updated successfully."}
        # --- КОНЕЦ ИЗМЕНЕНИЙ ---
    except Exception as e:
        # В случае ошибки пытаемся запустить Python-приложение обратно
        if app_info.app_type == "python_app":
            run_command_sync(f'"{NSSM_PATH}" start "{app_name}"')
            app_info.status = _get_app_final_status(app_name)
            add_or_update_app(app_info)
        raise HTTPException(status_code=500, detail=f"Failed to update app: {str(e)}")


@app.get("/api/apps/{app_name}/history", response_model=List[DeploymentHistory])
def get_deployment_history(app_name: str, current_user: Annotated[User, Depends(get_current_active_user)]):
    """Получает историю деплоев (сканируя папку с бекапами)."""
    backup_dir = BACKUPS_DIR / app_name
    if not backup_dir.exists():
        return []

    history = []
    files = sorted(backup_dir.glob('*.zip'), key=lambda p: p.stat().st_mtime, reverse=True)
    for f in files:
        history.append(DeploymentHistory(
            filename=f.name,
            deployed_at=datetime.datetime.fromtimestamp(f.stat().st_mtime)
        ))
    return history


@app.post("/api/apps/{app_name}/restore")
def restore_deployment(app_name: str, request: RestoreRequest,
                       current_user: Annotated[User, Depends(get_current_active_user)]):
    """Восстанавливает приложение из выбранного файла бекапа."""
    app_info = get_app_by_name(app_name)
    if not app_info:
        raise HTTPException(status_code=404, detail="App not found")

    backup_zip_path = BACKUPS_DIR / app_name / request.filename
    if not backup_zip_path.exists():
        raise HTTPException(status_code=404, detail=f"Backup file '{request.filename}' not found.")

    try:
        # 1. Останавливаем сервис
        code, _, err = run_command_sync(f'"{NSSM_PATH}" stop "{app_name}"')
        if code != 0: raise Exception(f"NSSM stop failed: {err}")
        time.sleep(2)  # Ждем остановки

        # 2. Выполняем переразвертывание из ВЫБРАННОГО бекапа
        _redeploy_from_zip(app_info, backup_zip_path)

        # 3. Запускаем сервис
        code, _, err = run_command_sync(f'"{NSSM_PATH}" start "{app_name}"')
        if code != 0: raise Exception(f"NSSM start failed: {err}")

        # 4. Обновляем статус в БД
        app_info.status = _get_app_final_status(app_name)  # Надежная проверка статуса
        add_or_update_app(app_info)
        return {
            "message": f"App '{app_name}' restored successfully from '{request.filename}'. Final status: {app_info.status.upper()}"}
    except Exception as e:
        run_command_sync(f'"{NSSM_PATH}" start "{app_name}"')
        app_info.status = _get_app_final_status(app_name)  # Обновляем статус в БД
        add_or_update_app(app_info)
        raise HTTPException(status_code=500, detail=f"Failed to restore app: {str(e)}")


@app.get("/api/apps/{app_name}/logs", response_model=AppLogs)
def get_app_logs(app_name: str, current_user: Annotated[User, Depends(get_current_active_user)],
                 lines: int = Query(100, ge=1, le=1000)):
    """Читает N последних строк из лог-файла приложения."""
    app_info = get_app_by_name(app_name)
    if not app_info:
        raise HTTPException(status_code=404, detail="App not found")

    if not app_info.log_path or not Path(app_info.log_path).exists():
        return AppLogs(logs=[f"Log file not found for app '{app_name}'. It may not have been created yet."])

    log_file_path = Path(app_info.log_path)
    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines = f.readlines()
            last_lines = all_lines[-lines:]
        return AppLogs(logs=[line.strip() for line in last_lines])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read log file: {str(e)}")


# --- Эндпоинты для Nginx (ЗАЩИЩЕНЫ + ВАЛИДАЦИЯ ПУТИ) ---

def validate_nginx_path(target_path: Path, for_delete: bool = False):
    """
    Helper: разрешает редактировать/удалять только конфиги сайтов, путей или главный конфиг.
    ЗАПРЕЩАЕТ УДАЛЯТЬ ГЛАВНЫЙ КОНФИГ.
    """
    try:
        abs_target_str = str(target_path.absolute())
        abs_main_conf_str = str(NGINX_MAIN_CONF_FILE.absolute())
        abs_sites_dir_str = str(NGINX_SITES_DIR.absolute())
        abs_locations_dir_str = str(NGINX_LOCATIONS_DIR.absolute()) # <-- НОВАЯ СТРОКА
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid path format.")

    is_main_conf = (abs_target_str.lower() == abs_main_conf_str.lower())
    is_sites_conf = abs_target_str.lower().startswith(abs_sites_dir_str.lower())
    is_locations_conf = abs_target_str.lower().startswith(abs_locations_dir_str.lower()) # <-- НОВАЯ СТРОКА

    # ЗАЩИТА: Запрещаем удалять главный nginx.conf
    if for_delete and is_main_conf:
        raise HTTPException(status_code=403, detail="Deleting the main nginx.conf is forbidden.")

    # РАЗРЕШАЕМ ЛЮБУЮ ИЗ ТРЕХ ЛОКАЦИЙ
    if not (is_main_conf or is_sites_conf or is_locations_conf):
        raise HTTPException(
            status_code=403,
            detail="Editing this path is not allowed. Only main config, site configs, or location configs are permitted."
        )

    # Если это новый файл, убедимся, что его родительская директория существует и это ОДНА ИЗ РАЗРЕШЕННЫХ
    if not target_path.exists():
        allowed_parent_dirs = [NGINX_SITES_DIR, NGINX_LOCATIONS_DIR]
        if not any(target_path.parent.samefile(d) for d in allowed_parent_dirs):
             raise HTTPException(
                status_code=403,
                detail="New config files can only be created in the Nginx sites or locations directory."
            )


@app.get("/api/nginx/configs/list", response_model=NginxConfigList)
async def list_nginx_configs(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Возвращает список доступных для редактирования конфигов Nginx."""

    files = []
    seen_files = set()  # Чтобы избежать дубликатов, если вдруг они появятся

    # Функция-помощник для добавления файлов
    def add_file(path_str):
        if path_str not in seen_files:
            files.append(path_str)
            seen_files.add(path_str)

    # 1. Добавляем основной файл
    if NGINX_MAIN_CONF_FILE.exists():
        add_file(str(NGINX_MAIN_CONF_FILE))

    # 2. Сканируем папку с конфигами сайтов (server блоки)
    if NGINX_SITES_DIR.exists():
        for p in sorted(NGINX_SITES_DIR.glob("*.conf")):
            add_file(str(p))

    # 3. Сканируем папку с конфигами путей (location блоки)
    if NGINX_LOCATIONS_DIR.exists():
        for p in sorted(NGINX_LOCATIONS_DIR.glob("**/*.conf")):  # <--- ПРАВИЛЬНО
            add_file(str(p))

    return NginxConfigList(files=files)


@app.get("/api/nginx/config")
async def get_nginx_config(current_user: Annotated[User, Depends(get_current_active_user)], path: Optional[str] = None):
    """Получает конфиг Nginx с проверкой безопасности пути."""
    target_path = Path(path) if path else NGINX_MAIN_CONF_FILE

    # Валидация здесь для существующего или нового файла в sites_dir
    validate_nginx_path(target_path)

    if not target_path.exists() or not target_path.is_file():
        # Если файл не существует, но находится в разрешенной директории для новых файлов, возвращаем шаблон.
        if target_path.parent.samefile(NGINX_SITES_DIR):  # Проверяем, что это директория Nginx sites
            return {"path": str(target_path),
                    "content": f"# New file: {target_path.name}\n\nserver {{\n    listen 80;\n    server_name new.domain.com;\n\n    location / {{\n        proxy_pass http://localhost:8001;\n    }}\n}}"}
        raise HTTPException(status_code=404, detail=f"Config file not found at '{target_path}'")

    content = target_path.read_text(encoding="utf-8")
    return {"path": str(target_path), "content": content}


@app.post("/api/nginx/config")
async def save_nginx_config(config: NginxConfig, current_user: Annotated[User, Depends(get_current_active_user)]):
    """Сохраняет конфиг Nginx с проверкой безопасности пути."""
    target_path = Path(config.path)

    # ВАЛИДАЦИЯ: Разрешаем сохранять только в разрешенные места
    validate_nginx_path(target_path)

    try:
        # Создаем бэкап только для существующего файла
        if target_path.exists():
            backup_path = target_path.with_suffix(f"{target_path.suffix}.bak.{int(time.time())}")
            shutil.copy(target_path, backup_path)
            msg_suffix = f" Backup created at {backup_path.name}"
        else:
            msg_suffix = " New file created."

        target_path.write_text(config.content, encoding="utf-8")
        return {"message": f"Nginx config saved to '{target_path}'.{msg_suffix}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save Nginx config: {e}")


@app.delete("/api/nginx/config")
async def delete_nginx_config(current_user: Annotated[User, Depends(get_current_active_user)], path: str = Query(...)):
    """Удаляет указанный файл конфигурации Nginx."""
    target_path = Path(path)

    # ВАЛИДАЦИЯ: Проверяем, можно ли удалять этот файл
    validate_nginx_path(target_path, for_delete=True)

    if not target_path.exists() or not target_path.is_file():
        raise HTTPException(status_code=404, detail=f"Config file not found at '{target_path}'")

    try:
        target_path.unlink()
        # После удаления файла рекомендуется перезагрузить Nginx
        run_command_sync(NGINX_RELOAD_CMD, cwd=str(NGINX_DIR))
        return {"message": f"Config file '{target_path.name}' deleted and Nginx reloaded successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete config file: {e}")


@app.post("/api/nginx/reload")
def reload_nginx(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Перезагружает Nginx."""
    code, out, err = run_command_sync(NGINX_RELOAD_CMD, cwd=str(NGINX_DIR))
    if code != 0:
        # Nginx часто выводит ошибки в stdout, поэтому объединяем
        raise HTTPException(status_code=500, detail=f"Failed to reload Nginx: {err or out}")
    return {"message": "Nginx reloaded successfully."}


def _update_deployer_nginx_config(domain: Optional[str], ssl_cert_name: Optional[str]):
    """
    (HELPER) Создает или обновляет главный конфиг Nginx для самого Deployer'а.
    Версия 2.1: Исправлена опечатка в TLS протоколе и уточнена логика include.
    """
    config_path = NGINX_SITES_DIR / "deployer-main.conf"
    deployer_port = os.getenv("PORT", "7999")

    # --- Сценарий 1: Нет домена (доступ по IP) ---
    if not domain:
        config_content = f"""
# Main configuration for Python Deployer UI (IP Access)
server {{
    listen 80;
    server_name _;

    location / {{
        proxy_pass http://127.0.0.1:{deployer_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }}
}}
"""
        config_path.write_text(config_content, encoding="utf-8")
        return  # Завершаем выполнение

    # --- Сценарий 2: Есть домен ---
    # Общие блоки, которые мы будем использовать
    proxy_block_for_deployer = f"""
    location / {{
        proxy_pass http://127.0.0.1:{deployer_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }}"""

    # ИСПРАВЛЕНИЕ ЗДЕСЬ: Уточняем путь для include, чтобы он был специфичен для текущего домена
    include_line_for_apps = f"    include {(NGINX_LOCATIONS_DIR / domain).as_posix()}/*.conf;"

    # Проверяем, есть ли валидный SSL сертификат
    use_ssl = False
    ssl_config_block = ""
    if ssl_cert_name:
        cert_dir = SSL_DIR / ssl_cert_name
        cert_path = cert_dir / "fullchain.pem"
        key_path = cert_dir / "privkey.pem"
        if cert_path.exists() and key_path.exists():
            use_ssl = True
            ssl_config_block = f"""
    listen 443 ssl;
    ssl_certificate {cert_path.as_posix()};
    ssl_certificate_key {key_path.as_posix()};
    ssl_protocols TLSv1.2 TLSv1.3;
"""

    # Собираем финальный конфиг в зависимости от наличия SSL
    final_config = ""
    if use_ssl:
        # --- Сценарий 2.1: Домен с SSL ---
        final_config = f"""
# Main configuration for Python Deployer UI ({domain} with SSL)
# HTTP redirect to HTTPS
server {{
    listen 80;
    server_name {domain};
    location / {{
        return 301 https://$host$request_uri;
    }}
}}

# HTTPS server
server {{
    {ssl_config_block}
    server_name {domain};

    {proxy_block_for_deployer}

    {include_line_for_apps}
}}
"""
    else:
        # --- Сценарий 2.2: Домен БЕЗ SSL ---
        final_config = f"""
# Main configuration for Python Deployer UI ({domain} HTTP-only)
server {{
    listen 80;
    server_name {domain};

    {proxy_block_for_deployer}

    {include_line_for_apps}
}}
"""
    config_path.write_text(final_config, encoding="utf-8")


@app.post("/api/deployer/settings")
async def update_deployer_settings(
        settings: DeployerSettingsUpdate,
        background_tasks: BackgroundTasks,
        current_user: Annotated[User, Depends(get_current_active_user)]
):
    """
    Обновляет настройки доступа к самому Deployer'у.
    Перезагрузка Nginx выполняется в фоновом режиме ПОСЛЕ отправки ответа.
    """
    try:
        # 1. Обновляем конфиг (это быстрая операция)
        _update_deployer_nginx_config(settings.domain, settings.ssl_certificate_name)

        # 2. Добавляем ДОЛГУЮ и ОПАСНУЮ команду в фоновые задачи
        # Она выполнится ПОСЛЕ того, как мы отправим ответ клиенту.
        background_tasks.add_task(run_command_sync, NGINX_RELOAD_CMD, cwd=str(NGINX_DIR))

        # 3. Немедленно возвращаем ответ, не дожидаясь перезагрузки
        return {"message": "Settings update command accepted. Nginx will be reloaded in the background."}

    except Exception as e:
        # Если ошибка произошла на этапе записи конфига
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/deployer/settings", response_model=DeployerSettings)
async def get_deployer_settings(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Получает текущие настройки доступа к Deployer'у из конфига Nginx."""
    config_path = NGINX_SITES_DIR / "deployer-main.conf"
    domain = None
    ssl_cert_name = None

    if config_path.exists():
        try:
            content = config_path.read_text(encoding="utf-8")

            # Ищем домен (server_name), но игнорируем плейсхолдер "_"
            domain_match = re.search(r"server_name\s+([^;]+);", content)
            if domain_match:
                found_domain = domain_match.group(1).strip()
                if found_domain != "_":
                    domain = found_domain

            # Ищем путь к сертификату и извлекаем из него имя
            cert_match = re.search(r"ssl_certificate\s+.*?/ssl/([^/]+)/", content)
            if cert_match:
                ssl_cert_name = cert_match.group(1).strip()

        except Exception as e:
            print(f"Error parsing deployer-main.conf: {e}")
            # В случае ошибки просто вернем пустые значения

    return DeployerSettings(domain=domain, ssl_certificate_name=ssl_cert_name)

@app.get("/api/nginx/domains", response_model=List[str])
async def list_nginx_domains(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Возвращает список доменов из файлов в nginx-sites."""
    if not NGINX_SITES_DIR.exists():
        return []
    domains = []
    for conf_file in NGINX_SITES_DIR.glob("*.conf"):
        # Пропускаем конфиг самого деплоера

        content = conf_file.read_text(encoding="utf-8")
        match = re.search(r"server_name\s+([^;]+);", content)
        if match:
            # Берем первое имя, если их несколько
            domain = match.group(1).strip().split()[0]
            if domain != "_":
                domains.append(domain)
    return sorted(list(set(domains)))