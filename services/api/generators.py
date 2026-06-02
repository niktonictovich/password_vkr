"""
Генераторы паролей трех типов.

1. crypto — криптографически стойкий генератор на базе secrets.
   Использует CSPRNG (cryptographically secure pseudo-random number generator).
   Подходит для машинной аутентификации, не запоминается человеком.

2. passphrase — парольная фраза из EFF wordlist.
   Случайные слова из выверенного словаря (7776 слов).
   Баланс стойкости и запоминаемости. Подход известен как Diceware.

3. markov — генерация через Марковскую модель (проксирование к ml-сервису).
   Демонстрационный режим: воспроизводит типичный паттерн пользовательских
   паролей. Не рекомендуется для практического использования.
"""

import math
import os
import secrets
from pathlib import Path


# ---------- Загрузка EFF wordlist ----------

WORDLIST_PATH = os.getenv("WORDLIST_PATH", "/data/eff_wordlist.txt")
_wordlist: list[str] = []


def load_wordlist() -> int:
    """
    Загружает EFF wordlist в память.
    Формат файла: <число> <таб> <слово> в каждой строке.
    Возвращает количество загруженных слов.
    """
    global _wordlist
    path = Path(WORDLIST_PATH)
    if not path.exists():
        raise FileNotFoundError(f"EFF wordlist не найден: {path}")

    words = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) == 2:
                words.append(parts[1])

    _wordlist = words
    return len(_wordlist)


def wordlist_size() -> int:
    return len(_wordlist)


# ---------- Криптогенератор ----------

def generate_crypto(length: int = 16) -> dict:
    """
    Генерирует криптографически стойкий пароль.

    Использует secrets.token_urlsafe — CSPRNG, ориентированный на
    безопасное использование (в отличие от random, который для
    аутентификации использовать нельзя).

    Длина выходной строки в символах: token_urlsafe принимает
    число байт, а выдает base64-кодирование, что дает примерно
    1.33 символа на байт. Корректируем входной аргумент.
    """
    byte_count = max(8, int(length * 3 / 4))
    password = secrets.token_urlsafe(byte_count)[:length]

    # Энтропия: log2(64^length) = length * 6 бит для урезанной base64.
    # Это нижняя оценка (реально немного меньше из-за фильтрации).
    entropy_bits = length * 6

    return {
        "password": password,
        "length": len(password),
        "method": "crypto",
        "entropy_bits": entropy_bits,
        "description": (
            "Криптографически стойкий пароль, "
            "сгенерированный CSPRNG. Не запоминается, "
            "рекомендуется хранить в менеджере паролей."
        ),
    }


# ---------- Парольная фраза ----------

def generate_passphrase(
    word_count: int = 4,
    separator: str = "-",
    add_number: bool = True,
) -> dict:
    """
    Генерирует парольную фразу из случайных слов EFF wordlist.

    Подход Diceware (D. Reinhold, 1995). Каждое слово вносит
    log2(7776) ≈ 12.9 бит энтропии. Для 4 слов: ~51 бит.
    Это соответствует современным рекомендациям NIST.

    Опционально добавляет случайную цифру в конец для соответствия
    типичным требованиям систем "хотя бы одна цифра".
    """
    if not _wordlist:
        raise RuntimeError("EFF wordlist не загружен")

    words = [secrets.choice(_wordlist) for _ in range(word_count)]
    password = separator.join(words)

    if add_number:
        password += separator + str(secrets.randbelow(100))

    # Энтропия: каждое слово — выбор из ~7776 = 2^12.92
    entropy_bits = word_count * math.log2(len(_wordlist))
    if add_number:
        entropy_bits += math.log2(100)  # ~6.6 бит

    return {
        "password": password,
        "length": len(password),
        "method": "passphrase",
        "entropy_bits": round(entropy_bits, 1),
        "word_count": word_count,
        "description": (
            f"Парольная фраза из {word_count} случайных слов словаря EFF. "
            "Баланс стойкости и запоминаемости. "
            "Принцип Diceware, рекомендован NIST и EFF."
        ),
    }
