import pandas as pd
import csv
import re
from pathlib import Path


def extract_text_from_csv_smart(input_file, output_file=None):
    """
    Извлекает текст из CSV файла формата 'число, текст, число'
    с учётом запятых внутри текста
    """
    print(f"📊 Обработка файла: {input_file}")

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.strip().split('\n')

        extracted_texts = []
        for i, line in enumerate(lines, 1):
            parts = line.split(',')

            res = []

            res.append(parts[0])
            res.append(';')
            res.append(','.join(parts[1:-1]))
            res.append(';')
            res.append(parts[-1])
            res.append(';')

            extracted_texts.append(''.join(res))

        print(extracted_texts[1])

        if extracted_texts:
            print(f"✅ Извлечено {len(extracted_texts)} текстов")
            return _process_and_save(extracted_texts, output_file, input_file)
    except Exception as e:
        print(f"❌ Ошибка: {e}")

    return None


def _process_and_save(texts, output_file, input_file):
    """Обработка и сохранение результатов"""
    # Очистка текстов (убираем лишние кавычки если есть)
    cleaned_texts = []
    for text in texts:
        if isinstance(text, str):
            # Убираем внешние кавычки
            text = text.strip()
            if text.startswith('"') and text.endswith('"'):
                text = text[1:-1]
            if text.startswith("'") and text.endswith("'"):
                text = text[1:-1]
            cleaned_texts.append(text)

    print(texts[1])

    # Если нужно сохранить в файл
    with open(output_file, 'w', encoding='utf-8') as f:
        wr = csv.writer(f, delimiter=";")
        wr.writerows(texts)
    print(f"💾 Тексты сохранены в: {output_file}")

    return cleaned_texts


# Пример использования
if __name__ == "__main__":
    input_csv = "./XSS_dataset.csv"
    output_csv = "./dataset.csv"

    texts = extract_text_from_csv_smart(input_csv, output_csv)

    if texts:
        print(f"\n📝 Примеры извлеченных текстов:")
        for i, text in enumerate(texts[:5], 1):
            print(f"{i}. {text[:100]}..." if len(
                text) > 100 else f"{i}. {text}")
    else:
        print("❌ Не удалось извлечь тексты")
