"""
Веб-интерфейс приложения проверки и генерации паролей.

Streamlit-приложение с четырьмя вкладками:
- Анализ        — проверка надежности пароля по трем метрикам
- Генерация     — три режима создания паролей (markov, crypto, passphrase)
- Образование   — теория парольной безопасности, парадокс XKCD, типичные ошибки
- О системе     — архитектура, использованные стандарты, ссылки

Точка входа Streamlit-приложения. Делает только две вещи:
1. Базовая настройка страницы и стилей.
2. Создает четыре вкладки и делегирует рендеринг каждой
   соответствующему модулю tab_*.py.
"""

import streamlit as st

import tab_about
import tab_analysis
import tab_education
import tab_generation


st.set_page_config(
    page_title="Анализ и генерация паролей",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# Заголовок над вкладками — небольшой блок с темой работы.
st.title("🔐 Анализ надежности и генерация паролей")
st.caption(
    "Учебно-исследовательский прототип. Использованы: zxcvbn (Dropbox), "
    "база утечек на основе SecLists/HIBP, Марковская модель на корпусе RockYou, "
    "криптогенератор `secrets`, парольные фразы EFF Diceware."
)

# Четыре вкладки. Streamlit рисует их горизонтальными.
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Анализ пароля",
    "🎲 Генерация",
    "📚 Образование",
    "ℹ️ О системе",
])

with tab1:
    tab_analysis.render()

with tab2:
    tab_generation.render()

with tab3:
    tab_education.render()

with tab4:
    tab_about.render()
