# config.py
from pathlib import Path

# --- Основные пути ---
# Директория для хранения данных приложения (БД, бекапы и т.д.)
DATA_DIR = Path("C:\\deployer-data")
DATA_DIR.mkdir(exist_ok=True)

# Директория для хранения развернутых веб-приложений
APPS_BASE_DIR = DATA_DIR / "apps"
# Директория для хранения ZIP-архивов (бекапов)
BACKUPS_DIR = DATA_DIR / "backups"
# Путь к файлу базы данных SQLite
DB_FILE = DATA_DIR / "deployer.db"
# --- НОВОЕ: Директория для SSL-сертификатов ---
SSL_DIR = DATA_DIR / "ssl"
SSL_DIR.mkdir(exist_ok=True)


# --- Настройки Nginx ---
NGINX_DIR = Path("C:\\tools\\nginx-1.29.1")

# Путь к ОСНОВНОМУ файлу конфигурации Nginx
NGINX_MAIN_CONF_FILE = NGINX_DIR / "conf" / "nginx.conf"
# !!! ВАЖНО: Директория для АВТОМАТИЧЕСКИ создаваемых конфигов
# Убедитесь, что в nginx.conf есть строка: include C:/deployer-data/nginx-sites/*.conf;
NGINX_SITES_DIR = DATA_DIR / "nginx-sites"
NGINX_SITES_DIR.mkdir(exist_ok=True)
# --- НОВАЯ КОНСТАНТА ---
NGINX_LOCATIONS_DIR = DATA_DIR / "nginx-locations"
NGINX_LOCATIONS_DIR.mkdir(exist_ok=True)

# ИЗМЕНЕНО: Команда для перезагрузки Nginx теперь использует новую переменную
NGINX_RELOAD_CMD = "net stop nginx && net start nginx"

# --- Настройки NSSM ---
NSSM_PATH = "C:\\ProgramData\\chocolatey\\bin\\nssm.exe"

# --- Настройки сети ---
BASE_PORT = 8001

# --- Настройки безопасности и JWT ---
SECRET_KEY = "e8b5e6e3f4a3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120 # Увеличим время жизни токена

# --- Управление версиями Python ---
# Укажите пути к исполняемым файлам разных версий Python на вашем сервере.
# Это позволит пользователям выбирать версию при деплое.
PYTHON_EXECUTABLES = {
    "Python 3.12 (System)": "C:\\Python312\\python.exe",
}
# Версия по умолчанию, если не выбрана
DEFAULT_PYTHON_EXECUTABLE = list(PYTHON_EXECUTABLES.values())[0]