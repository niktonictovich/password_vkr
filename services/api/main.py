"""
Основной API-сервис.

Единая точка входа для веб-интерфейса. Выполняет:
- комплексную оценку пароля через три независимых метрики
  (zxcvbn, Марковская модель, проверка по утечкам)
- генерацию паролей в трех режимах
  (Markov, криптогенератор, парольная фраза)

Эндпоинты:
- GET  /health              — проверка живости и состояния зависимостей
- POST /check               — комплексная оценка пароля
- POST /generate/markov     — генерация Марковской моделью
- POST /generate/crypto     — генерация криптостойкого пароля
- POST /generate/passphrase — генерация парольной фразы
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from zxcvbn import zxcvbn

from breach import BreachDatabase
from generators import (
    generate_crypto,
    generate_passphrase,
    load_wordlist,
    wordlist_size,
)
from ml_client import MLClient

logging.basicConfig(level=logging.INFO, format="[%(name)s] %(message)s")
logger = logging.getLogger("api")

breach_db: BreachDatabase | None = None
ml_client: MLClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Загрузка ресурсов при старте, освобождение при остановке."""
    global breach_db, ml_client

    # Загрузка базы утечек.
    breach_path = os.getenv("BREACH_DB_PATH", "/data/top100k.txt")
    logger.info("Загрузка базы утечек из %s ...", breach_path)
    breach_db = BreachDatabase(breach_path)
    breach_db.load()
    logger.info("База утечек готова: %d хешей", breach_db.size())

    # Загрузка EFF wordlist для парольных фраз.
    logger.info("Загрузка EFF wordlist...")
    count = load_wordlist()
    logger.info("Словарь готов: %d слов", count)

    # HTTP-клиент к ml.
    ml_client = MLClient()
    logger.info("ML-клиент инициализирован")

    yield

    await ml_client.close()
    logger.info("Сервис останавливается")


app = FastAPI(
    title="Password Strength Check API",
    description="Комплексная оценка надежности паролей и генерация в трех режимах",
    version="0.2.0",
    lifespan=lifespan,
)


# ---------- Pydantic-схемы ----------

class CheckRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128)


class ZxcvbnInfo(BaseModel):
    score: int
    warning: str
    suggestions: list[str]
    crack_time: str


class MarkovInfo(BaseModel):
    score: float
    interpretation: str


class BreachInfo(BaseModel):
    found: bool


class CheckResponse(BaseModel):
    password: str
    zxcvbn: ZxcvbnInfo
    markov: MarkovInfo
    breach: BreachInfo
    verdict: str


class MarkovGenerateRequest(BaseModel):
    min_length: int = Field(default=8, ge=4, le=64)
    max_length: int = Field(default=16, ge=4, le=64)


class CryptoGenerateRequest(BaseModel):
    length: int = Field(default=16, ge=8, le=64)


class PassphraseGenerateRequest(BaseModel):
    word_count: int = Field(default=4, ge=3, le=8)
    separator: str = Field(default="-", min_length=1, max_length=3)
    add_number: bool = Field(default=True)


class GenerateResponse(BaseModel):
    password: str
    length: int
    method: str
    description: str
    entropy_bits: float | None = None
    word_count: int | None = None


# ---------- Эндпоинты ----------

@app.get("/health")
async def health():
    """Проверка живости сервиса и доступности зависимостей."""
    try:
        ml_status = await ml_client.health()
    except Exception as e:
        logger.warning("ML-сервис недоступен: %s", e)
        ml_status = {"status": "unreachable", "error": str(e)}

    return {
        "status": "ok",
        "breach_db": {
            "loaded": breach_db.is_loaded(),
            "size": breach_db.size(),
        },
        "wordlist": {
            "loaded": wordlist_size() > 0,
            "size": wordlist_size(),
        },
        "ml_service": ml_status,
    }


@app.post("/check", response_model=CheckResponse)
async def check(req: CheckRequest):
    """Комплексная оценка пароля по трем независимым метрикам."""
    password = req.password

    z = zxcvbn(password)
    is_breached = breach_db.check(password)

    try:
        markov_result = await ml_client.score(password)
    except httpx.HTTPError as e:
        logger.error("Не удалось получить оценку от ml: %s", e)
        raise HTTPException(status_code=503, detail="ML-сервис недоступен")

    z_info = ZxcvbnInfo(
        score=z["score"],
        warning=z["feedback"].get("warning") or "—",
        suggestions=z["feedback"].get("suggestions", []),
        crack_time=str(
            z["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
        ),
    )

    markov_info = MarkovInfo(
        score=markov_result["score"],
        interpretation=markov_result["interpretation"],
    )

    breach_info = BreachInfo(found=is_breached)

    if is_breached:
        verdict = "КРИТИЧЕСКИ СЛАБЫЙ — пароль найден в базе утечек"
    else:
        verdicts_by_score = {
            0: "ОЧЕНЬ СЛАБЫЙ",
            1: "СЛАБЫЙ",
            2: "СРЕДНИЙ",
            3: "СИЛЬНЫЙ",
            4: "ОЧЕНЬ СИЛЬНЫЙ",
        }
        verdict = verdicts_by_score.get(z_info.score, "НЕИЗВЕСТНО")

    return CheckResponse(
        password=password,
        zxcvbn=z_info,
        markov=markov_info,
        breach=breach_info,
        verdict=verdict,
    )


@app.post("/generate/markov", response_model=GenerateResponse)
async def generate_markov_endpoint(req: MarkovGenerateRequest):
    """
    Генерация пароля Марковской моделью.
    Демонстрационный режим: воспроизводит типичный паттерн пользователей.
    Не рекомендуется для практического использования.
    """
    try:
        result = await ml_client.generate(
            min_length=req.min_length,
            max_length=req.max_length,
        )
    except httpx.HTTPError as e:
        logger.error("Не удалось получить пароль от ml: %s", e)
        raise HTTPException(status_code=503, detail="ML-сервис недоступен")

    return GenerateResponse(
        password=result["password"],
        length=result["length"],
        method="markov",
        description=(
            "Пароль, сгенерированный Марковской моделью на основе RockYou. "
            "Воспроизводит типичные паттерны пользовательских паролей. "
            "Демонстрационный режим: получаемые пароли стилизованы под "
            "реальные, но не гарантируют криптостойкости."
        ),
    )


@app.post("/generate/crypto", response_model=GenerateResponse)
async def generate_crypto_endpoint(req: CryptoGenerateRequest):
    """
    Генерация криптографически стойкого пароля.
    Источник энтропии: secrets.token_urlsafe (CSPRNG).
    """
    return GenerateResponse(**generate_crypto(length=req.length))


@app.post("/generate/passphrase", response_model=GenerateResponse)
async def generate_passphrase_endpoint(req: PassphraseGenerateRequest):
    """
    Генерация парольной фразы из EFF wordlist.
    Подход Diceware. Баланс стойкости и запоминаемости.
    """
    return GenerateResponse(**generate_passphrase(
        word_count=req.word_count,
        separator=req.separator,
        add_number=req.add_number,
    ))


import httpx  # noqa: E402
