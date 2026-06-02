"""
Диагностический скрипт для проверки состояния обученной модели.

Запуск:
    docker compose run --rm ml python inspect_model.py
"""

import pickle
import sys
from pathlib import Path

MODEL_PATH = "/data/models/markov.pkl"


def main():
    path = Path(MODEL_PATH)
    if not path.exists():
        sys.exit(f"Модель не найдена: {path}")

    size_bytes = path.stat().st_size
    size_mb = size_bytes / (1024 * 1024)
    print(f"Файл:        {path}")
    print(f"Размер:      {size_bytes:,} байт ({size_mb:.2f} МБ)")

    with path.open("rb") as f:
        model = pickle.load(f)

    print(f"Класс:       {type(model).__name__}")
    print(f"Order:       {model.order}")
    print(f"Префиксов:   {len(model.transitions):,}")

    total_observations = sum(
        sum(counter.values()) for counter in model.transitions.values()
    )
    print(f"Всего наблюдений переходов: {total_observations:,}")

    avg_per_password = total_observations / 1_000_000
    print(f"В среднем переходов на пароль: {avg_per_password:.1f}")

    # Топ-15 самых частых префиксов.
    print(f"\nТоп-15 самых частых префиксов:")
    prefix_totals = [
        (prefix, sum(counter.values()))
        for prefix, counter in model.transitions.items()
    ]
    prefix_totals.sort(key=lambda x: -x[1])
    for prefix, count in prefix_totals[:15]:
        readable = repr(prefix)
        print(f"  {readable:20s}  встретился {count:>10,} раз")

    # Анализ продолжений типичного контекста.
    # Для модели порядка 3 префикс должен быть длиной 3 символа.
    test_prefix = "pas"  # после "pas" — известный паттерн (password, pass...)
    print(f"\nЧто чаще всего идет после префикса {test_prefix!r}:")
    if test_prefix in model.transitions:
        top = sorted(
            model.transitions[test_prefix].items(),
            key=lambda x: -x[1],
        )[:10]
        total = sum(model.transitions[test_prefix].values())
        for char, count in top:
            pct = 100 * count / total
            char_display = repr(char) if not char.isprintable() else f"'{char}'"
            print(f"  {char_display:>6s}  {count:>10,} раз  ({pct:5.2f}%)")
    else:
        print(f"  (префикс не найден)")


if __name__ == "__main__":
    main()
