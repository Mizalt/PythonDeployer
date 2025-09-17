# auth.py
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pathlib import Path

from .config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from .models import User, UserInDB
from .database_sqlite import get_user_by_username

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token", auto_error=False)


# --- Функции для работы с пользователями и паролями ---

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_user(username: str) -> Optional[UserInDB]:
    return get_user_by_username(username)


# --- Функции для работы с JWT ---

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# --- Зависимость для получения токена (строгая версия, вызывает ошибку) ---

async def get_token(
        request: Request,
        token_from_header: Optional[str] = Depends(oauth2_scheme)
) -> str:
    """
    Пытается получить токен сначала из cookie 'deployer_token', а затем из заголовка.
    Вызывает ошибку 401, если токен не найден.
    Используется для защиты API-эндпоинтов.
    """
    token_from_cookie = request.cookies.get("deployer_token")

    if token_from_cookie:
        return token_from_cookie

    if token_from_header:
        return token_from_header

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )

# --- Зависимость для получения токена (опциональная версия) ---

async def get_optional_token(
    request: Request,
    token_from_header: Optional[str] = Depends(oauth2_scheme)
) -> Optional[str]:
    """
    Пытается получить токен из cookie или заголовка, но НЕ вызывает ошибку,
    если токен не найден. Возвращает None.
    Используется для защиты страниц UI (чтобы перенаправить на /login).
    """
    token_from_cookie = request.cookies.get("deployer_token")
    if token_from_cookie:
        return token_from_cookie
    if token_from_header:
        return token_from_header
    return None


# --- Основная зависимость для защиты API-эндпоинтов ---

async def get_current_active_user(token: str = Depends(get_token)) -> User:
    """
    Декодирует токен, проверяет его и возвращает активного пользователя.
    Вызывает ошибку, если пользователь не аутентифицирован.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user(username)
    if user is None:
        raise credentials_exception

    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")

    return User(username=user.username, disabled=user.disabled)


# --- Зависимость для UI-страниц ---

async def get_optional_current_user(token: Optional[str] = Depends(get_optional_token)) -> Optional[User]:
    """
    Пытается получить текущего пользователя, но не вызывает ошибку 401,
    если токен отсутствует или невалиден. Возвращает None в этом случае.
    Теперь использует правильную логику поиска токена (cookie + header).
    """
    if token is None:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
    except JWTError:
        return None

    user = get_user(username)
    if user is None:
        return None

    if user.disabled:
        return None

    return User(username=user.username, disabled=user.disabled)