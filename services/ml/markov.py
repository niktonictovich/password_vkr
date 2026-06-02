"""
Модель Маркова для генерации и оценки надежности паролей.

Реализует символьную n-граммную вероятностную модель:
- fit(corpus): обучение на списке паролей,
  построение таблицы условных вероятностей P(c_i | c_{i-n}, ..., c_{i-1})
- generate(): сэмплирование нового пароля из обученного распределения
- score(password): вычисление лог-правдоподобия пароля под моделью

Чем выше оценка пароля (ближе к 0), тем более он "типичен" с точки зрения
обученной модели — а значит, тем легче будет угадан Markov-based атакой
(как в Hashcat или John the Ripper).

Чем ниже (более отрицательная) оценка — тем более пароль необычен
и устойчив к статистическим методам взлома.
"""

import math
import random
from collections import Counter, defaultdict


class MarkovModel:
    """
    Символьная цепь Маркова порядка n для моделирования паролей.

    Порядок n означает, что следующий символ зависит от n предыдущих.
    При n=2 модель учит P(c_i | c_{i-2}, c_{i-1}) — биграммную модель.
    """

    # Служебные символы для маркировки начала и конца пароля.
    # Используются ASCII-управляющие символы, которые не встречаются в паролях.
    START = "\x02"  # STX — start of text
    END = "\x03"    # ETX — end of text

    def __init__(self, order: int = 2):
        if order < 1:
            raise ValueError("order должен быть >= 1")
        self.order = order
        # transitions[prefix] = Counter({char: count, ...})
        # Например: transitions["pa"] = Counter({'s': 89000, 'p': 12000, ...})
        self.transitions: dict[str, Counter] = defaultdict(Counter)
        self._trained = False

    def fit(self, corpus: list[str]) -> None:
        """
        Обучение модели на списке паролей.

        Проходим скользящим окном размера (order + 1) по каждому паролю,
        накапливая статистику переходов префикс -> следующий символ.
        """
        for password in corpus:
            # Дополняем пароль маркерами начала и конца.
            # START повторяется order раз, чтобы первый реальный символ
            # имел контекст нужной длины.
            padded = self.START * self.order + password + self.END

            for i in range(len(padded) - self.order):
                prefix = padded[i : i + self.order]
                next_char = padded[i + self.order]
                self.transitions[prefix][next_char] += 1

        self._trained = True

    def generate(
        self,
        min_length: int = 8,
        max_length: int = 16,
        max_attempts: int = 100,
    ) -> str:
        """
        Генерация нового пароля сэмплированием из обученного распределения.

        Начинаем с префикса из START-маркеров, на каждом шаге выбираем
        следующий символ с вероятностью, пропорциональной его частоте
        в обучающих данных при таком префиксе.

        Делаем до max_attempts попыток получить пароль в нужном диапазоне длин.
        """
        if not self._trained:
            raise RuntimeError("Модель не обучена. Сначала вызовите fit().")

        for _ in range(max_attempts):
            password = ""
            prefix = self.START * self.order

            while len(password) < max_length:
                if prefix not in self.transitions:
                    # Тупик: для такого префикса не было данных.
                    break

                next_char = self._sample_next(prefix)

                if next_char == self.END:
                    # Модель сама решила завершить пароль.
                    break

                password += next_char
                # Окно префикса сдвигается на один символ вправо.
                prefix = (prefix + next_char)[-self.order :]

            if min_length <= len(password) <= max_length:
                return password

        # Если за max_attempts не получили пароль в диапазоне —
        # возвращаем последний сгенерированный.
        return password

    def _sample_next(self, prefix: str) -> str:
        """
        Случайный выбор следующего символа из transitions[prefix],
        взвешенный по частотам.
        """
        counter = self.transitions[prefix]
        chars = list(counter.keys())
        weights = list(counter.values())
        return random.choices(chars, weights=weights, k=1)[0]

    def score(self, password: str) -> float:
        """
        Оценка пароля: среднее лог-правдоподобие на символ под моделью.

        Возвращает отрицательное число. Чем оно ближе к нулю, тем более
        пароль типичен (легко угадывается). Чем сильнее отрицательное,
        тем пароль необычнее с точки зрения распределения утечек.

        Используется лапласовское сглаживание для предотвращения log(0)
        на невиданных переходах.
        """
        if not self._trained:
            raise RuntimeError("Модель не обучена. Сначала вызовите fit().")

        padded = self.START * self.order + password + self.END
        log_prob = 0.0
        count = 0

        # Размер словаря для сглаживания: печатные ASCII-символы.
        vocab_size = 96

        for i in range(len(padded) - self.order):
            prefix = padded[i : i + self.order]
            next_char = padded[i + self.order]

            if prefix not in self.transitions:
                # Полностью невиданный префикс — даем минимальную вероятность.
                log_prob += math.log(1e-10)
            else:
                counter = self.transitions[prefix]
                total = sum(counter.values())
                # Сглаживание Лапласа (add-one smoothing):
                # +1 к числителю, +vocab_size к знаменателю.
                char_count = counter.get(next_char, 0) + 1
                smoothed_prob = char_count / (total + vocab_size)
                log_prob += math.log(smoothed_prob)
            count += 1

        return log_prob / count if count > 0 else 0.0


# Тестовый запуск при прямом исполнении файла:
#   python markov.py
if __name__ == "__main__":
    print("=" * 60)
    print("Smoke-тест модели Маркова")
    print("=" * 60)

    # Маленький тестовый корпус для проверки логики.
    # В реальной работе на его место придет фильтрованный RockYou.
    test_corpus = [
        "password", "password1", "password123",
        "qwerty", "qwerty123", "qwertyuiop",
        "letmein", "letmein123",
        "admin", "admin123", "administrator",
        "welcome", "welcome1", "welcome123",
        "iloveyou", "monkey", "dragon",
        "football", "baseball", "superman",
        "trustno1", "sunshine", "princess",
    ]

    model = MarkovModel(order=2)
    print(f"\nОбучение на {len(test_corpus)} паролях...")
    model.fit(test_corpus)
    print(f"Обучение завершено. Выучено {len(model.transitions)} уникальных префиксов.")

    print("\n--- Генерация 10 паролей ---")
    for i in range(10):
        pwd = model.generate(min_length=6, max_length=14)
        print(f"  {i + 1:2d}. {pwd!r}  (длина: {len(pwd)})")

    print("\n--- Оценка известных и новых паролей ---")
    samples = [
        ("password", "из обучающего набора"),
        ("qwerty123", "из обучающего набора"),
        ("xj7#pL!9mQ", "случайный, не из набора"),
        ("hello", "не из набора, но обычное слово"),
    ]
    for pwd, note in samples:
        s = model.score(pwd)
        print(f"  {pwd!r:15s}  score = {s:7.3f}   ({note})")

    print("\nЧем ближе score к 0, тем пароль типичнее (= легче угадать).")
    print("Чем сильнее отрицательный — тем пароль необычнее.")

    # ================================================================
    # Эксперимент: сравнение order=2 и order=3 на маленьком корпусе.
    # Цель — показать эффект переобучения (overfitting):
    # при большом порядке и малом корпусе модель просто запоминает
    # обучающий набор и теряет способность генерировать новое.
    # ================================================================

    print("\n" + "=" * 60)
    print("Эксперимент: переобучение при увеличении порядка")
    print("=" * 60)

    train_set = set(test_corpus)  # для быстрой проверки "пароль из обучения?"

    for n in [2, 3]:
        print(f"\n--- Order = {n} ---")
        m = MarkovModel(order=n)
        m.fit(test_corpus)
        print(f"Выучено уникальных префиксов: {len(m.transitions)}")

        generated = [m.generate(min_length=4, max_length=14) for _ in range(20)]

        # Сколько сгенерированных паролей дословно совпадают с обучающим набором?
        copies = sum(1 for p in generated if p in train_set)
        unique_outputs = len(set(generated))

        print(f"Сгенерировано: 20 паролей")
        print(f"  из них точных копий обучающего набора: {copies}/20")
        print(f"  уникальных среди сгенерированных:      {unique_outputs}/20")

        print(f"  Примеры:")
        for p in generated[:8]:
            mark = "  [копия из обучения]" if p in train_set else ""
            print(f"    {p!r}{mark}")

    print("\nВыводы эксперимента:")
    print("- Order=2: больше разнообразия, больше 'гибридов' из фрагментов разных паролей.")
    print("- Order=3 на 23 паролях: модель почти всегда воспроизводит обучающий набор.")
    print("- При таком количестве данных order=3 — переобучение.")
    print("- На большом корпусе (RockYou) order=3 наоборот работал бы лучше order=2.")
