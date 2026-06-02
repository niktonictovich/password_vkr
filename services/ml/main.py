"""
HTTP-сервис генерации и оценки паролей.

Оборачивает MarkovModel в REST API на FastAPI.
Эндпоинты:
- POST /generate — сгенерировать новый пароль
- POST /score    — оценить надежность заданного пароля
- GET  /health   — проверка живости сервиса

При запуске сервиса:
1. Если найден файл с обученной моделью (/data/markov.pkl) — загружаем его.
2. Иначе — обучаем модель на встроенном демо-корпусе.

Для обучения на полном корпусе RockYou используется скрипт train.py:
    docker compose run --rm ml python train.py
"""

import os
import pickle
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel, Field

from markov import MarkovModel


# Глобальный объект модели. Загружается один раз при старте сервиса.
model: MarkovModel | None = None

# Источник модели: pickle-файл или демо-корпус.
model_source: str = "unknown"


# Путь к сохраненной обученной модели.
MODEL_PATH = os.getenv("MODEL_PATH", "/data/markov.pkl")


# Демо-корпус: используется только если нет обученной модели.
# В production-сценарии всегда должна быть обученная модель из train.py.
DEMO_CORPUS = [
    "password", "password1", "password123", "Password1",
    "qwerty", "qwerty123", "qwertyuiop", "1qaz2wsx",
    "letmein", "letmein123", "admin", "admin123", "administrator",
    "welcome", "welcome1", "welcome123",
    "iloveyou", "monkey", "dragon", "football", "baseball", "superman",
    "trustno1", "sunshine", "princess", "shadow", "master",
    "michael", "jordan", "michelle", "jennifer",
    "abc123", "111111", "123456", "12345678", "123123",
]


def load_or_train_model() -> tuple[MarkovModel, str]:
    """
    Пытается загрузить готовую модель из pickle.
    Если ее нет — обучает на встроенном демо-корпусе.

    Возвращает кортеж (модель, описание источника).
    """
    path = Path(MODEL_PATH)
    if path.exists():
        print(f"[ml] Найдена обученная модель: {path}")
        size_mb = path.stat().st_size / (1024 * 1024)
        print(f"[ml] Размер файла: {size_mb:.1f} МБ")
        with path.open("rb") as f:
            m = pickle.load(f)
        print(f"[ml] Модель загружена. "
              f"Порядок: {m.order}, префиксов: {len(m.transitions):,}")
        return m, f"pretrained ({path.name})"

    print(f"[ml] Обученная модель не найдена по пути {path}")
    print(f"[ml] Использую демо-корпус для запуска ({len(DEMO_CORPUS)} паролей).")
    print(f"[ml] Для production-качества выполните: "
          f"docker compose run --rm ml python train.py")
    m = MarkovModel(order=2)
    m.fit(DEMO_CORPUS)
    return m, f"demo corpus ({len(DEMO_CORPUS)} passwords)"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Загрузка модели при старте, освобождение при остановке."""
    global model, model_source
    print("[ml] Инициализация сервиса...")
    model, model_source = load_or_train_model()
    print(f"[ml] Сервис готов. Источник модели: {model_source}")
    yield
    print("[ml] Сервис останавливается.")


app = FastAPI(
    title="ML-сервис генерации и оценки паролей",
    description="Внутренний сервис с моделью Маркова",
    version="0.2.0",
    lifespan=lifespan,
)


# ----- Схемы запросов и ответов -----

class GenerateRequest(BaseModel):
    """Параметры запроса на генерацию пароля."""
    min_length: int = Field(default=8, ge=4, le=64)
    max_length: int = Field(default=16, ge=4, le=64)


class GenerateResponse(BaseModel):
    """Ответ с сгенерированным паролем."""
    password: str
    length: int


class ScoreRequest(BaseModel):
    """Параметры запроса на оценку пароля."""
    password: str = Field(min_length=1, max_length=128)


class ScoreResponse(BaseModel):
    """Ответ с оценкой надежности."""
    password: str
    score: float
    interpretation: str


# ----- Эндпоинты -----

@app.get("/health")
def health():
    """Проверка живости сервиса. Используется для healthchecks."""
    return {
        "status": "ok",
        "model_loaded": model is not None,
        "model_source": model_source,
        "model_order": model.order if model else None,
        "prefixes": len(model.transitions) if model else None,
    }


@app.post("/generate", response_model=GenerateResponse)
def generate(req: GenerateRequest):
    """Сгенерировать новый пароль с заданными ограничениями длины."""
    password = model.generate(
        min_length=req.min_length,
        max_length=req.max_length,
    )
    return GenerateResponse(password=password, length=len(password))


@app.post("/score", response_model=ScoreResponse)
def score(req: ScoreRequest):
    """
    Оценить надежность пароля с точки зрения Марковской модели.
    Возвращает лог-правдоподобие на символ и текстовую интерпретацию.
    """
    s = model.score(req.password)

    # Эмпирические пороги. После обучения на полном RockYou
    # будут перекалиброваны на основе перцентилей распределения.
    if s > -4:
        interpretation = "Пароль типичен, легко угадывается статистическими методами"
    elif s > -8:
        interpretation = "Пароль средней предсказуемости"
    elif s > -14:
        interpretation = "Пароль малопредсказуем для Марковской модели"
    else:
        interpretation = "Пароль крайне нетипичен, устойчив к статистическим атакам"

    return ScoreResponse(
        password=req.password,
        score=round(s, 4),
        interpretation=interpretation,
    )
