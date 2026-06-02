# Базовый образ — облегченный Python 3.11.
FROM python:3.11-slim

# Стандартные настройки Python для контейнеров.
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Зависимости — отдельным слоем для кэширования.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Код сервиса.
COPY . .

# Документируем порт FastAPI.
EXPOSE 8000

# Запуск ASGI-сервера uvicorn, обслуживающего FastAPI-приложение.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
