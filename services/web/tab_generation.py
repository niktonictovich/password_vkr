"""
Вкладка "Генерация паролей".

Три режима, каждый с пояснением и автоматической проверкой
сгенерированного пароля через api/check.
"""

import httpx
import streamlit as st

import api_client


# Описания режимов: краткое + подробное.
MODE_DESCRIPTIONS = {
    "markov": {
        "title": "Марковская модель",
        "short": "Воспроизводит паттерны типичных пользовательских паролей",
        "long": (
            "Демонстрационный режим. Использует символьную модель Маркова "
            "порядка 3, обученную на 1 миллионе паролей из корпуса RockYou. "
            "Генерирует пароли, **похожие на реальные пользовательские**, что "
            "делает их относительно слабыми по криптостойкости. **Не предназначен** "
            "для практического использования — служит исключительно для иллюстрации "
            "того, какие пароли создают обычные пользователи."
        ),
    },
    "crypto": {
        "title": "Криптогенератор",
        "short": "Криптостойкий пароль на основе CSPRNG",
        "long": (
            "Использует `secrets.token_urlsafe` — криптографически стойкий "
            "генератор псевдослучайных чисел (CSPRNG) из стандартной библиотеки "
            "Python. Энтропия близка к теоретическому максимуму (≈6 бит на "
            "символ при использовании URL-safe Base64). **Максимально стойкий**, "
            "но **не запоминается человеком** — предполагает хранение в менеджере "
            "паролей."
        ),
    },
    "passphrase": {
        "title": "Парольная фраза",
        "short": "Запоминаемая фраза из словаря EFF (Diceware)",
        "long": (
            "Случайные слова из выверенного словаря EFF (7776 слов), разделенные "
            "символом. Подход известен как Diceware (А. Рейнхольд, 1995). "
            "Каждое слово дает log₂(7776) ≈ 12.9 бит энтропии — 4 слова обеспечивают "
            "~51 бит, что превосходит большинство 10-символьных паролей. **Сочетает "
            "высокую стойкость с приемлемой запоминаемостью**, рекомендован NIST и "
            "Electronic Frontier Foundation. Парадокс XKCD в действии."
        ),
    },
}


def _render_password_card(result: dict, check_result: dict | None = None) -> None:
    """
    Отображает сгенерированный пароль в виде карточки
    с автоматической оценкой надежности.
    """
    # Большое поле с самим паролем — моноширинным шрифтом.
    st.code(result["password"], language="text")

    # Метрики пароля.
    cols = st.columns(3)
    with cols[0]:
        st.metric("Длина", result["length"])
    with cols[1]:
        if result.get("entropy_bits") is not None:
            st.metric("Энтропия", f"{result['entropy_bits']:.0f} бит")
        else:
            st.metric("Энтропия", "—", help="Для Маркова не вычисляется")
    with cols[2]:
        if result.get("word_count") is not None:
            st.metric("Слов", result["word_count"])
        else:
            st.metric("Метод", result["method"])

    # Автоматическая проверка через /check.
    if check_result:
        verdict = check_result["verdict"]
        z_score = check_result["zxcvbn"]["score"]
        crack_time = check_result["zxcvbn"]["crack_time"]

        st.write(
            f"**Автопроверка:** {verdict} · "
            f"zxcvbn {z_score}/4 · "
            f"время взлома: {crack_time}"
        )


def _render_mode_section(mode: str, render_controls) -> None:
    """
    Универсальный блок для одного режима генерации.
    Принимает функцию render_controls для специфичных параметров.
    """
    desc = MODE_DESCRIPTIONS[mode]
    st.subheader(desc["title"])
    st.write(desc["short"])

    with st.expander("Подробнее"):
        st.write(desc["long"])

    # Специфичные для режима параметры и кнопка.
    result = render_controls()

    # Если что-то сгенерировано — показать.
    if result is not None:
        # Сразу проверяем сгенерированный пароль.
        try:
            check_result = api_client.check(result["password"])
        except httpx.HTTPError:
            check_result = None
        _render_password_card(result, check_result)


def _markov_controls() -> dict | None:
    """Параметры и кнопка для Марковской генерации."""
    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        min_length = st.number_input(
            "Мин. длина", min_value=4, max_value=64, value=8, key="m_min"
        )
    with col2:
        max_length = st.number_input(
            "Макс. длина", min_value=4, max_value=64, value=16, key="m_max"
        )
    with col3:
        st.write("")
        st.write("")
        clicked = st.button("Сгенерировать", key="btn_markov", use_container_width=True)
    if clicked:
        try:
            return api_client.generate_markov(min_length=min_length, max_length=max_length)
        except httpx.HTTPError as e:
            st.error(f"Ошибка: {e}")
    return None


def _crypto_controls() -> dict | None:
    """Параметры и кнопка для крипто-генерации."""
    col1, col2 = st.columns([1, 1])
    with col1:
        length = st.number_input(
            "Длина", min_value=8, max_value=64, value=16, key="c_len"
        )
    with col2:
        st.write("")
        st.write("")
        clicked = st.button(
            "Сгенерировать", key="btn_crypto", use_container_width=True,
            type="primary",
        )
    if clicked:
        try:
            return api_client.generate_crypto(length=length)
        except httpx.HTTPError as e:
            st.error(f"Ошибка: {e}")
    return None


def _passphrase_controls() -> dict | None:
    """Параметры и кнопка для парольной фразы."""
    col1, col2, col3, col4 = st.columns([1, 1, 1, 1])
    with col1:
        word_count = st.number_input(
            "Слов", min_value=3, max_value=8, value=4, key="p_wc"
        )
    with col2:
        separator = st.selectbox(
            "Разделитель", options=["-", "_", "."], index=0, key="p_sep"
        )
    with col3:
        add_number = st.checkbox("Добавить цифру", value=True, key="p_num")
    with col4:
        st.write("")
        st.write("")
        clicked = st.button(
            "Сгенерировать", key="btn_pass", use_container_width=True,
            type="primary",
        )
    if clicked:
        try:
            return api_client.generate_passphrase(
                word_count=word_count,
                separator=separator,
                add_number=add_number,
            )
        except httpx.HTTPError as e:
            st.error(f"Ошибка: {e}")
    return None


def render() -> None:
    """Главная функция рендеринга вкладки."""
    st.header("Генерация паролей в трех режимах")
    st.write(
        "Три различных подхода к генерации паролей, иллюстрирующих "
        "**компромисс между запоминаемостью и стойкостью**. Сгенерированные "
        "пароли автоматически проверяются по тем же метрикам, что и на "
        "вкладке «Анализ»."
    )

    # Подсказка о рекомендованном режиме.
    st.info(
        "💡 **Рекомендация для практического использования:** парольная фраза. "
        "Сочетает высокую стойкость (≥51 бит энтропии) с запоминаемостью. "
        "Криптогенератор — для случаев, когда пароль хранится в менеджере."
    )

    st.divider()

    # Парольная фраза — первой, потому что рекомендуется.
    _render_mode_section("passphrase", _passphrase_controls)
    st.divider()

    # Криптогенератор.
    _render_mode_section("crypto", _crypto_controls)
    st.divider()

    # Марковская — последней, потому что демонстрационная.
    _render_mode_section("markov", _markov_controls)
