"""
Локальная база утекших паролей.

Проверяет, встречался ли введенный пароль среди известных утечек.
Используется список топ-100k паролей из SecLists/HIBP.

Реализация:
- При запуске сервиса загружаем файл со списком паролей в память
- Каждый пароль хешируем алгоритмом SHA-1 (как в HIBP API)
- Храним множество хешей для O(1) проверки

Хеш используется по двум причинам:
1. Защита от случайной утечки самих паролей в дампах памяти/логах
   сервиса. Если злоумышленник получит дамп процесса api — он увидит
   только хеши, восстановить пароли из которых невозможно.
2. Совместимость с подходом HIBP (Have I Been Pwned), что упрощает
   переход на полную базу при необходимости масштабирования.
"""

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class BreachDatabase:
    """База известных утекших паролей с быстрой проверкой."""

    def __init__(self, source_path: str | Path):
        self._source_path = Path(source_path)
        self._hashes: set[str] = set()
        self._loaded = False

    def load(self) -> int:
        """
        Загружает пароли из файла, хеширует каждый, сохраняет в множество.
        Возвращает количество загруженных хешей.
        """
        if not self._source_path.exists():
            raise FileNotFoundError(
                f"Файл базы утечек не найден: {self._source_path}"
            )

        count = 0
        # Открываем с errors='ignore' — в дампах утечек встречаются
        # некорректные байты, бросать исключение на них смысла нет.
        with self._source_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                h = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
                self._hashes.add(h)
                count += 1

        self._loaded = True
        logger.info("Загружено %d хешей из %s", count, self._source_path)
        return count

    def check(self, password: str) -> bool:
        """
        Проверяет, есть ли пароль в базе утечек.
        Возвращает True, если пароль найден среди известных утечек.
        """
        if not self._loaded:
            raise RuntimeError("База утечек не загружена. Сначала вызовите load().")

        h = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        return h in self._hashes

    def size(self) -> int:
        """Количество загруженных хешей."""
        return len(self._hashes)

    def is_loaded(self) -> bool:
        return self._loaded
