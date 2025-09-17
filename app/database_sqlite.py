# database_sqlite.py
import sqlite3
import json
from typing import Dict, List, Optional
from .config import DB_FILE
from .models import App, UserInDB

def get_db_connection():
    """Возвращает соединение с базой данных SQLite."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Инициализирует базу данных, создает таблицы, если их нет."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS apps (
                name TEXT PRIMARY KEY,
                port INTEGER NOT NULL,
                app_path TEXT NOT NULL,
                start_script TEXT NOT NULL,
                log_path TEXT,
                status TEXT NOT NULL,
                python_executable TEXT,
                nginx_proxy_target TEXT,
                env_vars TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                hashed_password TEXT NOT NULL,
                disabled INTEGER NOT NULL DEFAULT 0
            )
        ''')

        # Обновление схемы БД
        try:
            cursor.execute("ALTER TABLE apps ADD COLUMN ssl_certificate_name TEXT")
            conn.commit()
            print("INFO: Column 'ssl_certificate_name' added to 'apps' table.")
        except sqlite3.OperationalError: pass # Колонка уже существует
        try:
            cursor.execute("ALTER TABLE apps ADD COLUMN parent_domain TEXT")
            conn.commit()
            print("INFO: Column 'parent_domain' added to 'apps' table.")
        except sqlite3.OperationalError:
            pass  # Колонка уже существует
        try:
            cursor.execute("ALTER TABLE apps ADD COLUMN app_type TEXT NOT NULL DEFAULT 'python_app'")
            conn.commit()
            print("INFO: Column 'app_type' added to 'apps' table.")
        except sqlite3.OperationalError:
            pass  # Колонка уже существует

def row_to_app_model(row: sqlite3.Row) -> App:
    """Преобразует строку из БД в Pydantic модель App."""
    if not row:
        return None
    data = dict(row)
    # Pydantic ожидает env_vars как dict, а в БД это JSON-строка
    if 'env_vars' in data and data['env_vars']:
        data['env_vars'] = json.loads(data['env_vars'])
    else:
        data['env_vars'] = {}
    return App(**data)


def get_all_apps() -> List[App]:
    """Получает все приложения из БД."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM apps")
        rows = cursor.fetchall()
        return [row_to_app_model(row) for row in rows]

def get_app_by_name(name: str) -> Optional[App]:
    """Получает одно приложение по имени."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM apps WHERE name = ?", (name,))
        row = cursor.fetchone()
        return row_to_app_model(row)

def add_or_update_app(app: App):
    """Добавляет или обновляет приложение в БД."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        env_vars_json = json.dumps(app.env_vars) if app.env_vars else None
        data = (
            app.name, app.port, app.app_path, app.start_script, app.log_path, app.status,
            app.python_executable, app.nginx_proxy_target, env_vars_json, app.ssl_certificate_name,
            app.parent_domain, app.app_type
        )
        cursor.execute('''
            INSERT INTO apps (name, port, app_path, start_script, log_path, status, python_executable, nginx_proxy_target, env_vars, ssl_certificate_name, parent_domain, app_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                port=excluded.port,
                app_path=excluded.app_path,
                start_script=excluded.start_script,
                log_path=excluded.log_path,
                status=excluded.status,
                python_executable=excluded.python_executable,
                nginx_proxy_target=excluded.nginx_proxy_target,
                env_vars=excluded.env_vars,
                ssl_certificate_name=excluded.ssl_certificate_name,
                parent_domain=excluded.parent_domain,
                app_type=excluded.app_type
        ''', data)
        conn.commit()

def delete_app(name: str):
    """Удаляет приложение из БД."""
    with get_db_connection() as conn:
        conn.execute("DELETE FROM apps WHERE name = ?", (name,))
        conn.commit()

# --- Функции для работы с пользователями ---

def get_user_by_username(username: str) -> Optional[UserInDB]:
    """Получает пользователя из БД."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return UserInDB(
                username=row['username'],
                hashed_password=row['hashed_password'],
                disabled=bool(row['disabled'])
            )
    return None

def add_user(user: UserInDB):
    """Добавляет нового пользователя в БД."""
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, hashed_password, disabled) VALUES (?, ?, ?)",
            (user.username, user.hashed_password, int(user.disabled))
        )
        conn.commit()