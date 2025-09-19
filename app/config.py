# config.py
from pathlib import Path
import secrets

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
# --- Директория для SSL-сертификатов ---
SSL_DIR = DATA_DIR / "ssl"
SSL_DIR.mkdir(exist_ok=True)


# --- Настройки Nginx ---
NGINX_DIR = Path("C:\\tools\\nginx-1.29.1")

# Путь к ОСНОВНОМУ файлу конфигурации Nginx
NGINX_MAIN_CONF_FILE = NGINX_DIR / "conf" / "nginx.conf"
NGINX_SITES_DIR = DATA_DIR / "nginx-sites"
NGINX_SITES_DIR.mkdir(exist_ok=True)
NGINX_LOCATIONS_DIR = DATA_DIR / "nginx-locations"
NGINX_LOCATIONS_DIR.mkdir(exist_ok=True)

# Команда для перезагрузки Nginx
NGINX_RELOAD_CMD = ["cmd.exe", "/c", "net stop nginx & timeout /t 3 /nobreak > NUL & net start nginx"]

# --- Настройки NSSM ---
NSSM_PATH = "C:\\ProgramData\\chocolatey\\bin\\nssm.exe"

# --- Настройки Let's Encrypt / win-acme ---
WIN_ACME_PATH = "C:\\tools\\win-acme\\wacs.exe"
ACME_CHALLENGE_DIR = DATA_DIR / "acme-challenges"
ACME_CHALLENGE_DIR.mkdir(exist_ok=True)


# --- Настройки сети ---
BASE_PORT = 8001

def get_or_create_secret_key(path: Path) -> str:
    """
    Проверяет наличие файла с секретным ключом. Если файл есть, читает ключ из него.
    Если файла нет, генерирует новый криптографически стойкий ключ и сохраняет его в файл.
    """
    if path.exists():
        print(f"INFO: Loading secret key from {path}")
        return path.read_text().strip()
    else:
        print(f"INFO: Secret key file not found. Generating a new one at {path}")
        # Генерируем новый 32-байтный ключ (64 шестнадцатеричных символа)
        new_key = secrets.token_hex(32)
        try:
            path.write_text(new_key)
            # В Windows можно добавить атрибут "скрытый"
            # import os
            # os.system(f'attrib +h "{path}"')
            print("INFO: New secret key successfully generated and saved.")
            return new_key
        except Exception as e:
            print(f"CRITICAL: Could not write secret key file to {path}. Please check permissions. Error: {e}")
            raise

# --- Настройки безопасности и JWT ---
# Путь к файлу с ключом
SECRET_KEY_FILE = DATA_DIR / ".secret_key"
# Получаем или создаем ключ
SECRET_KEY = get_or_create_secret_key(SECRET_KEY_FILE)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120 # Увеличим время жизни токена

# --- Управление версиями Python ---
# Пути к исполняемым файлам разных версий Python на сервере.
# Это позволяет пользователям выбирать версию при деплое.
PYTHON_EXECUTABLES = {
    "Python 3.12 (System)": "C:\\Python312\\python.exe",
}
# Версия по умолчанию, если не выбрана
DEFAULT_PYTHON_EXECUTABLE = list(PYTHON_EXECUTABLES.values())[0]