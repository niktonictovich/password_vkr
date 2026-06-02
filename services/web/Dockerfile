# Базовый образ Python 3.11 в облегченной версии.
FROM python:3.11-slim

# Стандартные настройки Python для контейнеров.
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Зависимости — отдельным слоем для кэширования.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Код сервиса (включая ассеты — папка assets/).
COPY . .

# Документируем порт Streamlit.
EXPOSE 8501

# Запуск Streamlit-приложения.
# --server.address 0.0.0.0 — слушать на всех интерфейсах (нужно для Docker).
# --server.headless true — не открывать браузер автоматически.
# --browser.gatherUsageStats false — отключить телеметрию Streamlit.
CMD ["streamlit", "run", "main.py", \
     "--server.address", "0.0.0.0", \
     "--server.port", "8501", \
     "--server.headless", "true", \
     "--browser.gatherUsageStats", "false"]
