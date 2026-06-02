"""
Вкладка "О системе".

Краткое описание архитектуры, использованных технологий,
проверка состояния сервисов через API.
"""

import httpx
import streamlit as st

import api_client


def _section_architecture() -> None:
    """Описание архитектуры."""
    st.subheader("Архитектура системы")
    st.write("""
    Приложение построено в виде трех независимых микросервисов,
    запускаемых в Docker-контейнерах:

    | Сервис | Назначение | Технология | Доступ |
    |--------|-----------|------------|--------|
    | `web` | Пользовательский интерфейс (этот) | Streamlit | Внешний (порт 8501) |
    | `api` | Бизнес-логика, агрегация метрик | FastAPI + zxcvbn | Внешний (порт 8000) |
    | `ml` | Модель Маркова на корпусе RockYou | FastAPI | Только внутренний |

    Сервисы общаются между собой по HTTP через внутреннюю Docker-сеть.
    ML-сервис изолирован от внешнего мира — обращение к нему возможно
    только через `api`.

    **Принципы безопасности:**
    - Пароли пользователей **не сохраняются** ни на одном этапе.
    - База утечек хранится в **хешированном виде** (SHA-1).
    - ML-сервис и обучающие данные изолированы от внешней сети.
    - Применен принцип эшелонированной защиты.
    """)


def _section_tech_stack() -> None:
    """Технологический стек."""
    st.subheader("Технологический стек")
    st.write("""
    **Бэкенд:**
    - Python 3.11
    - FastAPI 0.115 — современный веб-фреймворк с автогенерацией OpenAPI/Swagger
    - Uvicorn — ASGI-сервер для FastAPI
    - Pydantic — декларативная валидация входов и выходов
    - httpx — асинхронный HTTP-клиент для межсервисной коммуникации

    **Машинное обучение:**
    - Собственная реализация символьной Марковской модели
      порядка 3 на чистом Python (без сторонних ML-библиотек)
    - Обучена на 1 миллионе паролей из RockYou (фильтрация по длине 6–20)
    - Сглаживание Лапласа (add-one smoothing)
    - Лог-правдоподобие как метрика оценки

    **Оценка надежности:**
    - zxcvbn (Dropbox) — эвристический анализ паттернов
    - SecLists/HIBP top-100k — локальная база утечек

    **Генерация:**
    - Марковская модель (демонстрационный режим)
    - `secrets.token_urlsafe` — криптостойкий генератор
    - EFF Diceware wordlist (7776 слов) — парольные фразы

    **Фронтенд:**
    - Streamlit 1.39 — фреймворк для быстрой сборки веб-UI на Python

    **Инфраструктура:**
    - Docker, Docker Compose — контейнеризация и оркестрация
    - WSL2 (на Windows) для нативного запуска контейнеров
    """)


def _section_status() -> None:
    """Текущий статус сервисов — живой health check."""
    st.subheader("Состояние сервисов")
    st.caption("Данные получены в реальном времени через `/health` API.")

    try:
        health = api_client.health()
    except httpx.HTTPError as e:
        st.error(f"API-сервис недоступен: {e}")
        return

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("API-сервис", "✅ работает")
        st.caption(f"Статус: {health['status']}")

    with col2:
        breach = health["breach_db"]
        st.metric(
            "База утечек",
            f"{breach['size']:,}".replace(",", " "),
            help="Количество хешей паролей из базы известных утечек",
        )

    with col3:
        wordlist = health["wordlist"]
        st.metric(
            "Словарь EFF",
            f"{wordlist['size']:,}".replace(",", " "),
            help="Количество слов в словаре для парольных фраз",
        )

    ml = health["ml_service"]
    if ml.get("status") == "ok":
        col4, col5, col6 = st.columns(3)
        with col4:
            st.metric("ML-сервис", "✅ работает")
        with col5:
            st.metric(
                "Источник модели",
                ml.get("model_source", "—"),
                help="pretrained — загружена из pickle; demo — обучена на демо-корпусе",
            )
        with col6:
            order = ml.get("model_order")
            prefixes = ml.get("prefixes")
            if order and prefixes:
                st.metric(
                    "Параметры модели",
                    f"order={order}, {prefixes:,} префиксов".replace(",", " "),
                )
    else:
        st.error(f"ML-сервис недоступен: {ml.get('error', 'unknown')}")


def _section_references() -> None:
    """Ссылки на источники и литературу."""
    st.subheader("Источники")
    st.write("""
    **Стандарты и нормативная база:**
    - ГОСТ Р 58833-2020 «Защита информации. Идентификация и аутентификация»
    - ГОСТ Р 57580.1-2017 «Безопасность финансовых операций»
    - NIST SP 800-63B «Digital Identity Guidelines»
    - Приказы ФСТЭК России №117, 21, 31, 239

    **Научная литература по теме:**
    - Castelluccia C., Dürmuth M., Perito D. *Adaptive Password-Strength
      Meters from Markov Models*. NDSS 2012.
    - Narayanan A., Shmatikov V. *Fast Dictionary Attacks on Passwords
      Using Time-Space Tradeoff*. CCS 2005.
    - Munroe R. *Password Strength*. xkcd #936, 2011.
      [xkcd.com/936](https://xkcd.com/936/)

    **Инструменты и базы данных:**
    - zxcvbn: [github.com/dropbox/zxcvbn](https://github.com/dropbox/zxcvbn)
    - Have I Been Pwned: [haveibeenpwned.com](https://haveibeenpwned.com/)
    - SecLists: [github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
    - EFF Diceware: [eff.org/dice](https://www.eff.org/dice)
    - Hashcat (использует Марковские модели): [hashcat.net](https://hashcat.net/)

    **Документация фреймворков:**
    - FastAPI: [fastapi.tiangolo.com](https://fastapi.tiangolo.com/)
    - Streamlit: [streamlit.io](https://streamlit.io/)
    - Docker: [docs.docker.com](https://docs.docker.com/)
    """)


def render() -> None:
    """Главная функция рендеринга вкладки."""
    st.header("О системе")
    st.write(
        "Информация о реализации, использованных технологиях, текущем "
        "состоянии сервисов и источниках. Эта вкладка предназначена в "
        "первую очередь для технической аудитории."
    )

    _section_architecture()
    st.divider()
    _section_tech_stack()
    st.divider()
    _section_status()
    st.divider()
    _section_references()
