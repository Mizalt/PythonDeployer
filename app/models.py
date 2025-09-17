# app/models.py
from pydantic import BaseModel, Field
from typing import Literal, List, Optional, Dict
from datetime import datetime


# --- Модели для Приложений ---

class App(BaseModel):
    app_type: Literal["python_app", "static_site"] = "python_app"
    name: str = Field(..., description="Уникальное имя приложения (имя сервиса)")
    port: Optional[int] = Field(None, description="Порт, на котором работает приложение")
    start_script: Optional[str] = Field(None, description="Команда для запуска приложения")
    app_path: str = Field(..., description="Путь к основной папке приложения")
    log_path: Optional[str] = Field(None, description="Путь к лог-файлу сервиса")
    status: Literal["running", "stopped", "deploying", "error"] = "stopped"
    python_executable: Optional[str] = Field(None, description="Путь к исполняемому файлу Python")
    nginx_proxy_target: Optional[str] = Field(None, description="Цель для Nginx (подпуть или домен)")
    env_vars: Optional[Dict[str, str]] = Field(default_factory=dict, description="Переменные окружения")
    ssl_certificate_name: Optional[str] = Field(None, description="Имя SSL сертификата для Nginx")
    parent_domain: Optional[str] = Field(None, description="Родительский домен для приложений с путем")


class AppCreate(BaseModel):
    app_type: Literal["python_app", "static_site"] = "python_app"
    name: str
    start_script: Optional[str] = "main.py"
    port: Optional[int] = None
    python_executable: Optional[str] = None
    nginx_proxy_target: Optional[str] = None
    env_vars: Optional[Dict[str, str]] = None
    ssl_certificate_name: Optional[str] = None
    parent_domain: Optional[str] = None


class AppConfigUpdate(BaseModel):
    port: Optional[int] = None
    start_script: Optional[str] = None
    nginx_proxy_target: Optional[str] = None
    env_vars: Optional[Dict[str, str]] = Field(default_factory=dict)
    ssl_certificate_name: Optional[str] = None
    parent_domain: Optional[str] = None

class AppAction(BaseModel):
    action: Literal["start", "stop", "restart"]


class AppLogs(BaseModel):
    logs: List[str]


# --- Модели для Истории и Восстановления ---

class DeploymentHistory(BaseModel):
    filename: str
    deployed_at: datetime


class RestoreRequest(BaseModel):
    filename: str


# --- Модели для Nginx ---

class NginxConfig(BaseModel):
    path: str
    content: str


class NginxConfigList(BaseModel):
    files: List[str]


# --- НОВЫЕ МОДЕЛИ для SSL ---
class SSLCertificateFile(BaseModel):
    name: str


# --- Модели для Пользователей и Аутентификации (ПЕРЕНЕСЕНЫ СЮДА) ---

class User(BaseModel):
    username: str
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class DeployerSettingsUpdate(BaseModel):
    domain: Optional[str] = None
    ssl_certificate_name: Optional[str] = None

class DeployerSettings(BaseModel):
    domain: Optional[str] = None
    ssl_certificate_name: Optional[str] = None