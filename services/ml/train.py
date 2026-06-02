"""
Обучение Марковской модели на корпусе RockYou и сохранение в pickle.

Запуск:
    docker compose run --rm ml python train.py

Скрипт:
1. Читает корпус из /data/rockyou.txt
2. Фильтрует и подготавливает пароли
3. Обучает MarkovModel заданного порядка
4. Сохраняет модель в /data/markov.pkl

После завершения api автоматически подхватит модель при следующем
запуске (см. логику в main.py).
"""

import argparse
import os
import pickle
import sys
import time
from pathlib import Path

from markov import MarkovModel


# Параметры по умолчанию. Переопределяются через аргументы командной строки.
DEFAULT_CORPUS_PATH = "/data/rockyou.txt"
DEFAULT_MODEL_PATH = "/data/markov.pkl"
DEFAULT_ORDER = 3
DEFAULT_MIN_LEN = 6
DEFAULT_MAX_LEN = 20
DEFAULT_LIMIT = 1_000_000  # максимум паролей для обучения


def load_corpus(
    path: str,
    min_len: int,
    max_len: int,
    limit: int | None = None,
) -> list[str]:
    """
    Чтение и фильтрация корпуса паролей.

    Фильтры:
    - длина в диапазоне [min_len, max_len]
    - только печатные ASCII-символы (для совместимости с моделью)
    - не пустые строки

    Возвращает список паролей. При limit != None ограничивает первыми N.
    """
    p = Path(path)
    if not p.exists():
        sys.exit(f"Ошибка: файл корпуса не найден: {path}")

    print(f"[train] Чтение корпуса из {path}...")
    passwords: list[str] = []
    skipped_length = 0
    skipped_non_ascii = 0

    # errors='ignore' — в RockYou есть невалидные байты, пропускаем их.
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            password = line.rstrip("\n")

            if not password:
                continue

            if not (min_len <= len(password) <= max_len):
                skipped_length += 1
                continue

            # Только печатные ASCII-символы.
            if not all(32 <= ord(c) < 127 for c in password):
                skipped_non_ascii += 1
                continue

            passwords.append(password)

            if limit and len(passwords) >= limit:
                break

    print(f"[train] Загружено: {len(passwords):,} паролей")
    print(f"[train]   отброшено по длине:    {skipped_length:,}")
    print(f"[train]   отброшено по символам: {skipped_non_ascii:,}")

    return passwords


def main():
    parser = argparse.ArgumentParser(
        description="Обучение Марковской модели на корпусе паролей",
    )
    parser.add_argument(
        "--corpus",
        default=os.getenv("CORPUS_PATH", DEFAULT_CORPUS_PATH),
        help=f"Путь к файлу корпуса (по умолчанию: {DEFAULT_CORPUS_PATH})",
    )
    parser.add_argument(
        "--output",
        default=os.getenv("MODEL_PATH", DEFAULT_MODEL_PATH),
        help=f"Путь сохранения модели (по умолчанию: {DEFAULT_MODEL_PATH})",
    )
    parser.add_argument(
        "--order",
        type=int,
        default=DEFAULT_ORDER,
        help=f"Порядок модели (по умолчанию: {DEFAULT_ORDER})",
    )
    parser.add_argument(
        "--min-len",
        type=int,
        default=DEFAULT_MIN_LEN,
        help=f"Минимальная длина пароля (по умолчанию: {DEFAULT_MIN_LEN})",
    )
    parser.add_argument(
        "--max-len",
        type=int,
        default=DEFAULT_MAX_LEN,
        help=f"Максимальная длина пароля (по умолчанию: {DEFAULT_MAX_LEN})",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"Ограничение числа паролей для обучения (по умолчанию: {DEFAULT_LIMIT:,})",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("Обучение Марковской модели на корпусе паролей")
    print("=" * 60)
    print(f"Корпус:      {args.corpus}")
    print(f"Выход:       {args.output}")
    print(f"Порядок:     {args.order}")
    print(f"Длина:       [{args.min_len}, {args.max_len}]")
    print(f"Лимит:       {args.limit:,}")
    print("=" * 60)

    # 1. Загрузка корпуса.
    t0 = time.perf_counter()
    corpus = load_corpus(
        path=args.corpus,
        min_len=args.min_len,
        max_len=args.max_len,
        limit=args.limit,
    )
    t_load = time.perf_counter() - t0
    print(f"[train] Корпус загружен за {t_load:.1f} с")

    if not corpus:
        sys.exit("Ошибка: после фильтрации не осталось ни одного пароля")

    # 2. Обучение модели.
    print(f"\n[train] Обучение модели порядка {args.order}...")
    t0 = time.perf_counter()
    model = MarkovModel(order=args.order)
    model.fit(corpus)
    t_fit = time.perf_counter() - t0
    print(f"[train] Обучено за {t_fit:.1f} с")
    print(f"[train] Уникальных префиксов: {len(model.transitions):,}")

    # 3. Сохранение модели.
    print(f"\n[train] Сохранение модели в {args.output}...")
    t0 = time.perf_counter()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Записываем во временный файл, затем атомарно переименовываем.
    # Это защищает от поврежденного pickle при прерывании записи.
    tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    with tmp_path.open("wb") as f:
        pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)
    tmp_path.replace(output_path)

    size_mb = output_path.stat().st_size / (1024 * 1024)
    t_save = time.perf_counter() - t0
    print(f"[train] Сохранено за {t_save:.1f} с, размер: {size_mb:.1f} МБ")

    # 4. Быстрая верификация.
    print(f"\n[train] Верификация: генерация 5 примеров и оценка...")
    samples = [model.generate(min_length=8, max_length=14) for _ in range(5)]
    for i, s in enumerate(samples, 1):
        print(f"  {i}. {s!r}  (длина: {len(s)})")

    test_passwords = ["password", "qwerty123", "Xj7#pL!9mQwK2nR8"]
    print(f"\n[train] Оценка эталонных паролей:")
    for pwd in test_passwords:
        s = model.score(pwd)
        print(f"  {pwd!r:20s}  score = {s:7.3f}")

    total = t_load + t_fit + t_save
    print(f"\n[train] Готово. Общее время: {total:.1f} с")


if __name__ == "__main__":
    main()
