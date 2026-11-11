# Стенд обнаружения XSS-атак методами машинного обучения

## Архитектура

```text
┌──────────────────┐      POST /api/create          ┌──────────────┐      POST /predict       ┌────────────────┐
│XSSDetector.Client│ ────────────────────────────►  │ XSSDetector  │ ───────────────────────► │ XSSDetector.ML │
│  (React+Vite)    │         port 3000              │   .Server    │        JSON body         │   (FastAPI)    │
│                  │ ◄────────────────────────────  │   port 8000  │ ◄─────────────────────   │   port 8001    │
└──────────────────┘       GET /api/messages        └──────┬───────┘                          └──────┬─────────┘
                                                           │                                         │
                                                           ▼                                         ▼
                                                  ┌─────────────────┐                       ┌─────────────────┐
                                                  │    MySQL 8.0    │                       │   8 ML моделей  │
                                                  │   port 3307     │                       │   (ансамбль)    │
                                                  └─────────────────┘                       └─────────────────┘
```

### Поток инференса (онлайн)

1. Пользователь вводит текст в `XSSDetector.Client` (React+Vite, порт 3000).
2. Клиент отправляет `POST /api/create` на FastAPI-сервер (порт 8000).
3. FastAPI пересылает текст в `XSSDetector.ML` через `POST /predict` (порт 8001).
4. Ансамбль из 8 ML-моделей возвращает вероятность XSS.
5. Результат хранится в MySQL и возвращается клиенту.

---

## Структура проекта

```
SSRW/
├── XSSDetector.Server/         # Backend API (FastAPI + SQLAlchemy + MySQL)
│   ├── app/
│   │   ├── config/             # Настройки (CORS, БД, окружение)
│   │   ├── models/             # SQLAlchemy модели (Message)
│   │   ├── routers/            # API роуты (/messages, /create)
│   │   ├── schemas/            # Pydantic схемы
│   │   ├── services/           # Бизнес-логика (async httpx → XSSDetector.ML)
│   │   └── utils/              # БД, логирование, мок-данные
│   └── main.py
│
├── XSSDetector.Client/         # React 19 + Vite + Bootstrap 5
│   └── src/
│       └── App.tsx             # Главный компонент (пост + комментарии)
│
├── XSSDetector.ML/             # ML-детектор (FastAPI + 8 моделей)
│   ├── main.py                 # API: /predict, /explain, /health
│   ├── ml/                     # ML-пайплайн (CLI: python -m ml)
│   │   ├── config/             # models.yaml, shap_reference_sample.csv
│   │   ├── registry/           # manifest.json, загрузка моделей
│   │   ├── serving/            # Predictor, ансамбль, ленивая инициализация
│   │   ├── models/             # Адаптеры (train/predict/evaluate)
│   │   ├── explainers/         # SHAP + Integrated Gradients
│   │   ├── features/           # Извлечение признаков (XSShield, 80+ фичей)
│   │   ├── datasets/           # raw, processed, test
│   │   ├── artifacts/          # Обученные модели и run-результаты
│   │   ├── evaluation/         # LODO-оценка, CRS-сравнение, SHAP-отчёты
│   │   └── training/           # Состязательное обучение
│   ├── Dockerfile              # Multi-stage, full/lite-сборка
│   ├── requirements*.txt       # requirements.txt + TF/transformer/train
│   └── results/                # LODO-результаты, SHAP-отчёты
│
├── docker-compose.yml          # 4 сервиса: mysql, fastapi, xss-detector, client
├── docker-compose.override.yml # Dev-режим: volume mount + --reload для ML
└── README.md                   # Этот файл
```

## Запуск

### Docker (рекомендуется)

```bash
docker compose up --build   # поднимает все 4 сервиса
```

| Сервис | Порт | Описание |
|--------|------|----------|
| Клиент | 3000 | React-фронтенд |
| API сервер | 8000 | FastAPI + MySQL |
| ML-детектор | 8001 | Ансамбль 8 моделей |

> **Production-режим:** `docker compose -f docker-compose.yml up -d` — запускает образ без volume mount.
> **Dev-режим:** `docker compose up` — автоматически подхватывает `docker-compose.override.yml` с hot-reload.

---

## Модели

| Модель | Тип | Признаки | Метод объяснений |
|--------|-----|----------|-----------------|
| CatBoost | Gradient boosting | 80 фичей | TreeSHAP |
| Random Forest | Ensemble | 80 фичей | TreeSHAP |
| Logistic Regression | Linear | 80 фичей | LinearSHAP |
| SVM (RBF) | Kernel | 80 фичей | KernelSHAP |
| LSTM | Deep learning | Символьные токены | Integrated Gradients |
| BiLSTM | Deep learning | Символьные токены | Integrated Gradients |
| DistilBERT | Transformer | Subword tokens | Integrated Gradients |
| Char-CNN | Символьный CNN | Символьные эмбеддинги | — |

**Ансамбль:** среднее вероятностей всех моделей, порог 0.5.

## Датасеты

| Источник | Роль | Записей |
|----------|------|--------|
| VulnXSS | XSS-пейлоады | ~1500 |
| PayloadBox | XSS-пейлоады | ~6000 |
| Kaggle (S. Hussain) | XSS + benign | ~13000 |
| HttpParams | XSS + hard-negative | ~6000 |
| CSIC 2010 | benign + hard-negative | ~36000 |
| FWAF | benign + hard-negative | ~30000 |
| ECML/PKDD 2007 | benign + hard-negative | ~3000 |
| Hard benign | benign (с кодом) | ~500 |

## API

### Сервер (port 8000)

| Метод | Путь | Описание |
|-------|------|----------|
| GET | /api/messages | Получить все сообщения |
| POST | /api/create | Создать сообщение (проверяется детектором) |

### XSS-детектор (port 8001)

| Метод | Путь | Описание |
|-------|------|----------|
| GET | /health | Статус сервиса и доступные модели |
| POST | /predict | Предсказание XSS |
| POST | /explain | Предсказание + SHAP-объяснение |

**Пример запроса:**
```json
POST /predict
{
  "text": "<script>alert(1)</script>",
  "models": ["catboost", "random_forest", "logistic_regression", "svm", "lstm"]
}
```

## Инструменты

- [OWASP CRS](https://coreruleset.org/) — бейзлайн сигнатурного подхода
- [SHAP](https://github.com/shap/shap) — интерпретируемость моделей
- [XSStrike](https://github.com/s0md3v/XSStrike) — движок обхода XSS
- [WAF-A-MoLE](https://github.com/AvalZ/WAF-A-MoLE) — референс алгоритма (SQLi)
