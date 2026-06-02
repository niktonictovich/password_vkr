"""
HTTP-клиент для общения с ml-сервисом.

Инкапсулирует все обращения к ml в одном модуле: api-код вызывает
методы клиента, не зная деталей URL, заголовков, ошибок сети.

Используется httpx — современный HTTP-клиент с поддержкой
асинхронных вызовов, что соответствует асинхронной природе FastAPI.
"""

import logging
import os

import httpx

logger = logging.getLogger(__name__)

# Адрес ml-сервиса. Внутри Docker-сети резолвится по имени сервиса.
ML_URL = os.getenv("ML_URL", "http://ml:8000")


class MLClient:
    """Асинхронный клиент к ml-сервису."""

    def __init__(self, base_url: str = ML_URL, timeout: float = 5.0):
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout)

    async def score(self, password: str) -> dict:
        """Запросить у ml оценку надежности пароля."""
        response = await self._client.post("/score", json={"password": password})
        response.raise_for_status()
        return response.json()

    async def generate(self, min_length: int = 8, max_length: int = 16) -> dict:
        """Запросить у ml сгенерировать новый пароль."""
        response = await self._client.post(
            "/generate",
            json={"min_length": min_length, "max_length": max_length},
        )
        response.raise_for_status()
        return response.json()

    async def health(self) -> dict:
        """Проверить, что ml-сервис жив."""
        response = await self._client.get("/health")
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        """Корректно закрыть клиент при остановке сервиса."""
        await self._client.aclose()
