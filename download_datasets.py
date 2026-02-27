import requests
import pandas as pd
import json
import os
from datetime import datetime


def create_comprehensive_xss_dataset(
        filename: str,
        dataset_dir: str,
        with_label: bool = True
) -> str:
    os.makedirs(dataset_dir, exist_ok=True)

    print(f"📁 Создаю датасет в папке: {dataset_dir}")

    dataset_type = 'основного' if with_label else 'тестового'

    print(f"\n1. Создание {dataset_type} датасета...")

    xss_samples = []
    with open(filename, 'r', encoding='utf-8') as file:
        lines = file.readlines()
        xss_samples = [line.strip() for line in lines if line.strip()
                       and not line.startswith('#')]

    data = []

    for sample in xss_samples:
        data.append({
            "text": sample,
            "label": 1,
            "source": "payloadbox",
            "length": len(sample),
            "timestamp": datetime.now().isoformat()
        } if with_label else {
            "text": sample,
            "source": "payloadbox",
            "length": len(sample),
            "timestamp": datetime.now().isoformat()
        })

    normal_templates = [
        "<div>{content}</div>",
        "<p>{content}</p>",
        "<a href='{url}'>{text}</a>",
        "<img src='{src}' alt='{alt}'>",
        "<span class='{class}'>{text}</span>",
        "<h{level}>{title}</h{level}>",
        "<ul><li>{item}</li></ul>",
        "<input type='{type}' name='{name}'>",
        "<button>{text}</button>",
        "<form action='{action}'>{fields}</form>"
    ]

    normal_content = ["Home", "About", "Contact", "Products", "Services",
                      "Login", "Sign up", "Download", "Read more", "Submit"]

    for i in range(len(xss_samples)):
        template = normal_templates[i % len(normal_templates)]
        content = normal_content[i % len(normal_content)]

        text = template.replace("{content}", content)\
            .replace("{url}", "/page")\
            .replace("{text}", content)\
            .replace("{src}", "image.jpg")\
            .replace("{alt}", "image")\
            .replace("{class}", "class-" + str(i))\
            .replace("{level}", str((i % 6) + 1))\
            .replace("{title}", content)\
            .replace("{item}", content)\
            .replace("{type}", "text")\
            .replace("{name}", "field")\
            .replace("{action}", "/submit")\
            .replace("{fields}", "<input type='text'>")

        data.append({
            "text": text,
            "label": 0,
            "source": "generated",
            "length": len(text),
            "timestamp": datetime.now().isoformat()
        } if with_label else {
            "text": text,
            "source": "generated",
            "length": len(text),
            "timestamp": datetime.now().isoformat()
        })

    df = pd.DataFrame(data)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    main_csv = os.path.join(dataset_dir, "xss_dataset.csv")
    df.to_csv(main_csv, index=False)
    print(f"   ✅ Основной CSV: {main_csv} ({len(df)} записей)")

    if with_label:

        xss_only = df[df['label'] == 1][['text', 'source']]
        xss_csv = os.path.join(dataset_dir, "xss_payloads_only.csv")
        xss_only.to_csv(xss_csv, index=False)
        print(f"   ✅ XSS payloads: {xss_csv} ({len(xss_only)} записей)")

        normal_only = df[df['label'] == 0][['text', 'source']]
        normal_csv = os.path.join(dataset_dir, "normal_html_only.csv")
        normal_only.to_csv(normal_csv, index=False)
        print(f"   ✅ Normal HTML: {normal_csv} ({len(normal_only)} записей)")

    stats = {
        "total_samples": len(df),
        "xss_samples": len(xss_only),
        "normal_samples": len(normal_only),
        "balance_ratio": len(xss_only) / len(df),
        "avg_xss_length": xss_only['text'].str.len().mean(),
        "avg_normal_length": normal_only['text'].str.len().mean(),
        "created_at": datetime.now().isoformat(),
        "sources": list(df['source'].unique())
    } if with_label else {
        "total_samples": len(df),
        "created_at": datetime.now().isoformat(),
        "sources": list(df['source'].unique())
    }

    stats_json = os.path.join(dataset_dir, "dataset_stats.json")
    with open(stats_json, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"   ✅ Статистика: {stats_json}")

    return dataset_dir + "/xss_dataset.csv"


create_comprehensive_xss_dataset(
    './VulnXSS-main/payloads/xss-payload-list(6k).txt',
    './datasets_test',
    True
)
