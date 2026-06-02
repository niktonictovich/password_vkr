"""
HTTP-клиент для общения с api-сервисом.

Все запросы к бэкенду собраны в одном модуле, чтобы UI-код
не зависел от деталей сети (URL, заголовки, обработка ошибок).
"""

import os
from typing import Any

import httpx

# Адрес api-сервиса. Внутри Docker-сети резолвится по имени сервиса.
API_URL = os.getenv("API_URL", "http://api:8000")

# Таймаут на каждый запрос. Маркова и zxcvbn — быстрые,
# 10 секунд — с большим запасом на старт контейнера.
TIMEOUT = 10.0


def health() -> dict[str, Any]:
    """Проверка состояния api и всех его зависимостей."""
    r = httpx.get(f"{API_URL}/health", timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def check(password: str) -> dict[str, Any]:
    """Комплексная оценка пароля."""
    r = httpx.post(
        f"{API_URL}/check",
        json={"password": password},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def generate_markov(min_length: int = 8, max_length: int = 16) -> dict[str, Any]:
    """Сгенерировать пароль Марковской моделью."""
    r = httpx.post(
        f"{API_URL}/generate/markov",
        json={"min_length": min_length, "max_length": max_length},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def generate_crypto(length: int = 16) -> dict[str, Any]:
    """Сгенерировать криптостойкий пароль."""
    r = httpx.post(
        f"{API_URL}/generate/crypto",
        json={"length": length},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def generate_passphrase(
    word_count: int = 4,
    separator: str = "-",
    add_number: bool = True,
) -> dict[str, Any]:
    """Сгенерировать парольную фразу."""
    r = httpx.post(
        f"{API_URL}/generate/passphrase",
        json={
            "word_count": word_count,
            "separator": separator,
            "add_number": add_number,
        },
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()
