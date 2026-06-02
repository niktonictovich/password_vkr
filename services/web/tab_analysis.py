"""
Вкладка "Анализ пароля".

Показывает поле ввода и при нажатии "Проверить" отображает
комплексную оценку: zxcvbn, Марковская модель, проверка по утечкам.
"""

import httpx
import streamlit as st

import api_client


# Цвета для итогового вердикта.
VERDICT_COLORS = {
    "КРИТИЧЕСКИ СЛАБЫЙ": "#d32f2f",
    "ОЧЕНЬ СЛАБЫЙ": "#e64a19",
    "СЛАБЫЙ": "#f57c00",
    "СРЕДНИЙ": "#fbc02d",
    "СИЛЬНЫЙ": "#7cb342",
    "ОЧЕНЬ СИЛЬНЫЙ": "#388e3c",
}

# Эталонные пароли для шкалы сравнения Markov-score.
SCALE_ANCHORS = [
    ("password", "очень типичный", "#d32f2f"),
    ("qwerty123", "типичный", "#f57c00"),
    ("Hello2024!", "средний", "#fbc02d"),
    ("Xj7#pL!9mQwK2nR8", "случайный", "#388e3c"),
]


def _get_verdict_color(verdict: str) -> str:
    """Подбирает цвет под вердикт. По умолчанию — серый."""
    for key, color in VERDICT_COLORS.items():
        if key in verdict:
            return color
    return "#757575"


def _render_verdict_banner(verdict: str) -> None:
    """Цветной баннер с итоговой оценкой."""
    color = _get_verdict_color(verdict)
    st.markdown(
        f"""
        <div style="
            background-color: {color};
            color: white;
            padding: 1.2em;
            border-radius: 8px;
            text-align: center;
            font-size: 1.3em;
            font-weight: bold;
            margin: 1em 0;
        ">
            Итоговая оценка: {verdict}
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_zxcvbn_block(z: dict) -> None:
    """Блок результатов эвристической оценки zxcvbn."""
    st.subheader("Эвристический анализ (zxcvbn)")

    score = z["score"]
    # Прогресс-бар 0-4. Streamlit принимает 0-100, нормализуем.
    st.progress(score / 4, text=f"Оценка: {score} из 4")

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Время взлома", z["crack_time"])
    with col2:
        warning = z["warning"]
        if warning and warning != "—":
            st.warning(f"⚠️ {warning}")
        else:
            st.info("Замечаний нет")

    if z["suggestions"]:
        st.write("**Рекомендации:**")
        for s in z["suggestions"]:
            st.write(f"- {s}")


def _render_markov_block(m: dict) -> None:
    """Блок результатов Марковской модели + шкала сравнения."""
    st.subheader("Статистический анализ (Марковская модель)")

    score = m["score"]
    interpretation = m["interpretation"]

    col1, col2 = st.columns([1, 2])
    with col1:
        st.metric(
            "Лог-правдоподобие",
            f"{score:.2f}",
            help=(
                "Логарифм условной вероятности пароля под моделью, "
                "обученной на корпусе RockYou. "
                "Чем ближе к нулю — тем типичнее пароль для реальных "
                "пользователей и тем легче он угадывается."
            ),
        )
    with col2:
        st.info(interpretation)

    # Шкала сравнения с эталонами.
    st.write("**Положение на шкале (по сравнению с эталонными паролями):**")
    st.caption(
        "Чем левее — тем типичнее (легко угадать). "
        "Чем правее — тем нетипичнее (сложно угадать)."
    )

    # Простая визуализация на основе HTML.
    # Диапазон значений score: примерно от -1 (очень типичный) до -22 (случайный).
    # Преобразуем в проценты для позиционирования на шкале.
    min_score = -22
    max_score = 0
    pct = max(0, min(100, (score - min_score) / (max_score - min_score) * 100))
    # Инвертируем: типичные (близкие к 0) должны быть слева.
    pct = 100 - pct

    anchor_html = ""
    for pwd, label, color in SCALE_ANCHORS:
        anchor_scores = {
            "password": -1.3,
            "qwerty123": -1.6,
            "Hello2024!": -8.0,
            "Xj7#pL!9mQwK2nR8": -21.2,
        }
        a_pct = 100 - max(0, min(100, (anchor_scores[pwd] - min_score) / (max_score - min_score) * 100))
        anchor_html += (
            f'<div style="position: absolute; left: {a_pct}%; top: 0; transform: translateX(-50%);">'
            f'<div style="width: 2px; height: 12px; background: {color};"></div>'
            f'<div style="font-size: 0.7em; color: {color}; white-space: nowrap; '
            f'transform: translateX(-50%); margin-left: 50%; text-align: center;">{label}</div>'
            f'</div>'
        )

    st.markdown(
        f'<div style="position: relative; margin: 1em 0 3em 0;">'
        f'<div style="height: 6px; background: linear-gradient(to right, '
        f'#d32f2f 0%, #f57c00 30%, #fbc02d 60%, #388e3c 100%); border-radius: 3px;"></div>'
        f'{anchor_html}'
        f'<div style="position: absolute; left: {pct}%; top: -12px; transform: translateX(-50%);">'
        f'<div style="font-size: 1.5em;">▼</div>'
        f'<div style="font-size: 0.85em; font-weight: bold; text-align: center; '
        f'transform: translateX(-50%); margin-left: 50%;">Ваш пароль</div>'
        f'</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def _render_breach_block(b: dict) -> None:
    """Блок проверки по базе утечек."""
    st.subheader("Проверка по базе утечек")
    if b["found"]:
        st.error(
            "🚨 **Пароль найден в базе известных утечек!**\n\n"
            "Это означает, что ваш пароль уже скомпрометирован и доступен "
            "злоумышленникам в публичных дампах. **Срочно смените его** "
            "везде, где он используется."
        )
    else:
        st.success(
            "✅ **Пароль не найден в базе утечек.**\n\n"
            "В нашей базе из ~100 тыс. наиболее распространенных утекших "
            "паролей вашего нет. Это не гарантирует абсолютной безопасности, "
            "но снимает наиболее острый риск."
        )


def render() -> None:
    """Главная функция рендеринга вкладки."""
    st.header("Проверка надежности пароля")
    st.write(
        "Введите пароль ниже. Он будет проанализирован по трем независимым "
        "метрикам и **не сохранится** — все вычисления происходят в памяти "
        "и не записываются в журналы или хранилище."
    )


    col_input, col_button = st.columns([3, 1], vertical_alignment="bottom")
    with col_input:
        password = st.text_input(
            "Пароль для проверки",
            type="password",
            label_visibility="collapsed",
            placeholder="Введите пароль...",
            key="password_input",
        )
    with col_button:
        check_clicked = st.button("Проверить", type="primary", use_container_width=True)

    # Выполняем проверку, если кнопка нажата и поле не пустое.
    if check_clicked:
        if not password:
            st.warning("Введите пароль перед проверкой.")
            return

        with st.spinner("Анализирую..."):
            try:
                result = api_client.check(password)
            except httpx.HTTPError as e:
                st.error(f"Ошибка обращения к API: {e}")
                return

        # Сохраняем результат в session_state, чтобы он не пропадал
        # при ре-рендере страницы.
        st.session_state["check_result"] = result

    # Если есть результат — показываем его.
    if "check_result" in st.session_state:
        result = st.session_state["check_result"]
        _render_verdict_banner(result["verdict"])
        _render_zxcvbn_block(result["zxcvbn"])
        st.divider()
        _render_markov_block(result["markov"])
        st.divider()
        _render_breach_block(result["breach"])
