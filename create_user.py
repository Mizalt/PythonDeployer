# create_user.py
import getpass
from pathlib import Path
from passlib.context import CryptContext
# ИЗМЕНЕНО: Импортируем функции для работы с новой БД
from app.database_sqlite import add_user, get_user_by_username, init_db
from app.models import UserInDB

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_user():
    print("--- Создание нового пользователя ---")

    # Инициализируем БД, если она еще не создана
    init_db()

    username = input("Введите имя пользователя: ")
    if not username:
        print("\n[Ошибка] Имя пользователя не может быть пустым.")
        return

    password = getpass.getpass("Введите пароль: ")
    password_confirm = getpass.getpass("Подтвердите пароль: ")

    if password != password_confirm:
        print("\n[Ошибка] Пароли не совпадают!")
        return

    # Проверяем, существует ли пользователь
    if get_user_by_username(username):
        print(f"\n[Ошибка] Пользователь с именем '{username}' уже существует.")
        return

    hashed_password = get_password_hash(password)
    user_in_db = UserInDB(
        username=username,
        hashed_password=hashed_password,
        disabled=False
    )

    try:
        add_user(user_in_db)
        print(f"\n[Успех] Пользователь '{username}' успешно создан в базе данных.")
    except Exception as e:
        print(f"\n[Ошибка] Не удалось создать пользователя: {e}")

if __name__ == "__main__":
    create_user()