# database.py
import json
from typing import Dict, List
from .config import DB_FILE
from .models import App

def load_db() -> Dict[str, App]:
    """Загружает базу данных приложений из JSON-файла."""
    if not DB_FILE.exists():
        return {}
    with open(DB_FILE, 'r') as f:
        data = json.load(f)
        return {app_name: App(**app_data) for app_name, app_data in data.items()}

def save_db(db: Dict[str, App]):
    """Сохраняет базу данных приложений в JSON-файл."""
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    data_to_save = {app_name: app.dict() for app_name, app in db.items()}
    with open(DB_FILE, 'w') as f:
        json.dump(data_to_save, f, indent=4)