# Стенд обнаружения XSS-атак методами машинного обучения

## Архитектура

```
┌──────────────┐     POST /api/create     ┌──────────────┐     POST /predict     ┌──────────────┐
│  ssrw-client │ ───────────────────────►  │   FastAPI    │ ───────────────────►  │  xssdetector │
│  (React+Vite)│     GET /api/messages     │   (server)   │     JSON body         │   (FastAPI)  │
│  port 3000   │ ◄───────────────────────  │   port 8000  │ ◄───────────────────  │   port 8001  │
└──────────────┘                           └──────┬───────┘                       └──────────────┘
                                                  │
                                           ┌──────▼───────┐
                                           │  MySQL 8.0   │
                                           │  port 3307   │
                                           └──────────────┘
```

### Принцип работы

1. Клиент отправляет запрос к серверу;
2. Сервер передаёт текст сообщения в модель на анализ (JSON body);
3. Рекурсивное декодирование входа → извлечение признаков → ансамбль 5 моделей;
4. Если не XSS → запись в БД (204). Если XSS → отказ (400).

## Структура проекта

```
SSRW/
├── server/                     # Backend API (FastAPI + SQLAlchemy)
│   ├── app/
│   │   ├── config/             # Настройки (CORS, БД, окружение)
│   │   ├── models/             # SQLAlchemy модели (Message)
│   │   ├── routers/            # API роуты (/messages, /create)
│   │   ├── schemas/            # Pydantic схемы
│   │   ├── services/           # Бизнес-логика (async httpx → xssdetector)
│   │   └── utils/              # DB, логирование
│   └── main.py
│
├── ssrw-client/                # React 19 + Vite + Bootstrap 5
│   └── src/
│       └── App.tsx             # Главный компонент (пост + комментарии)
│
├── xssdetector/                # ML-детектор (FastAPI + 5 моделей)
│   ├── main.py                 # API: /predict, /explain
│   ├── utils/
│   │   ├── preprocess.py       # Рекурсивное декодирование (URL→HTML→Unicode→Hex)
│   │   ├── extract_features.py # Извлечение 80+ признаков (XSShield-based)
│   │   ├── load_models.py      # Кешированная загрузка 5 моделей
│   │   └── shap_explainer.py   # SHAP-интерпретируемость
│   ├── adversarial/            # Состязательное обучение (Раздел 3)
│   │   ├── xss_mutator.py      # Guided mutational fuzzing (10 операторов мутации)
│   │   ├── xss_oracle.py       # Валидация исполняемости (heuristic + Playwright)
│   │   └── adversarial_training.py  # Цикл co-training
│   ├── CatBoost/               # Модель CatBoost + LODO результаты
│   ├── RandomForest/           # Random Forest
│   ├── LogisticRegression/     # Logistic Regression
│   ├── SVM/                    # SVM (RBF kernel)
│   ├── LSTM/                   # Bidirectional LSTM (оригинальный)
│   ├── BiLSTM/                 # BiLSTM на декодированных данных (скрипт обучения)
│   ├── Transformer/            # DistilBERT (скрипт обучения)
│   ├── CRS_baseline/           # Результаты сравнения с OWASP CRS
│   ├── Adversarial/            # Результаты состязательного обучения
│   ├── datasets_train/         # Обучающая выборка
│   ├── datasets_test/          # Тестовая выборка
│   ├── data/                   # Сырые данные (8 источников)
│   ├── train_bilstm_decoded.py # Обучение BiLSTM на декодированных данных
│   ├── train_transformer.py    # Дообучение DistilBERT
│   └── compare_with_crs.py     # Сравнение с OWASP CRS (PL1-PL4)
│
├── docker-compose.yml          # 4 сервиса: mysql, fastapi, xssdetector, client
└── plan_VKR_XSS.md             # План работ ВКР
```

## Запуск

### Docker (рекомендуется)

```bash
docker-compose up --build
```

Сервисы:
- Клиент: http://localhost:3000
- API сервер: http://localhost:8000/docs
- XSS-детектор: http://localhost:8001/docs
- MySQL: localhost:3307

### Локально (разработка)

**Сервер:**
```bash
cd server
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**XSS-детектор:**
```bash
cd xssdetector
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8001 --reload
```

**Клиент:**
```bash
cd ssrw-client
npm install
npm run dev
```

## ML-пайплайн

### Обучение моделей

Все скрипты запускаются из директории `xssdetector/`:

```bash
# BiLSTM на декодированных данных
python train_bilstm_decoded.py

# DistilBERT трансформер (требует GPU)
python train_transformer.py
```

### Сравнение с OWASP CRS

```bash
python compare_with_crs.py
```

Симулирует правила CRS 941xxx (XSS Detection) на 4 уровнях паранойи (PL1-PL4)
и сравнивает с ML-моделями на одних и тех же данных.

### Состязательное обучение

```bash
cd adversarial
python adversarial_training.py
```

Цикл co-training:
1. Генератор (10 операторов мутации) атакует детектор
2. Оракул проверяет исполняемость мутантов
3. Обходящие пейлоады добавляются в обучающую выборку
4. Детектор дообучается, метрики перемеряются

### SHAP-интерпретируемость

Generate the held-out global comparison for CatBoost, RF, LR, and SVM locally from the repository root:

```bash
.venv/Scripts/python -m xssdetector.generate_shap_report
```

The comparison is saved to `xssdetector/results/global_shap_heldout.json`. Transformer and LSTM local Integrated Gradients are reported separately because their token attributions are not directly comparable to engineered features.

```bash
curl -X POST http://localhost:8001/explain \
  -H "Content-Type: application/json" \
  -d '{"text": "<script>alert(1)</script>"}'
```

Ответ включает:
- `decoded_text` — декодированный вход
- `was_decoded` — изменился ли текст после декодирования
- `explanation_model` and `explanation_method` identify the selected local explainer; ensemble scores default to CatBoost
- `top_features` contains signed local SHAP or Integrated Gradients contributions for `explanation_model`
- `transformer` is an optional `/predict` and `/explain` model; it loads only local checkpoint/tokenizer files and uses Integrated Gradients. The checkpoint is stored through Git LFS; `/predict` and `/explain` return `503` if local weights or the declared `torch`/`transformers` dependencies are unavailable
- `global_top_features` contains CatBoost mean absolute SHAP values on a fixed sample stratified by source and label
- `global_sample_size` reports the number of reference rows used
- `global_diagnostic_model` identifies the model used for global bias diagnostics
- `bias_warning` is a heuristic for concentration on length/entropy features, not proof of causality

## API

### Сервер (port 8000)

| Метод | Путь | Описание |
|-------|------|----------|
| GET | /api/messages | Получить все сообщения |
| POST | /api/create | Создать сообщение (проверяется детектором) |

### XSS-детектор (port 8001)

| Метод | Путь | Описание |
|-------|------|----------|
| POST | /predict | Предсказание XSS |
| POST | /explain | Предсказание + SHAP-объяснение |

**Пример запроса:**
```json
POST /predict
{
  "text": "<script>alert(1)</script>",
  "models": ["catboost", "rf", "lr", "svm", "lstm"]
}
```

## Модели

| Модель | Тип | Признаки | Особенность |
|--------|-----|----------|-------------|
| CatBoost | Gradient boosting | 80 фичей (XSShield) | TreeSHAP, категориальные |
| Random Forest | Ensemble | 80 фичей | Интерпретируемый |
| Logistic Regression | Linear | 80 фичей + scaler | Быстрый бейзлайн |
| SVM (RBF) | Kernel | 80 фичей + scaler | Нелинейная граница |
| BiLSTM | Deep learning | Символьные токены | Декодированный вход |
| DistilBERT | Transformer | Subword tokens | Transfer learning |

**Ансамбль:** среднее вероятностей всех моделей, порог 0.35.

## Датасеты

| Источник | Роль | Записей |
|----------|------|--------|
| VulnXSS | XSS-пейлоады | ~1500 |
| PayloadBox | XSS-пейлоады | ~6000 |
| Kaggle (S. Hussain) | XSS + benign | ~13000 |
| HttpParams | XSS + hard-negative | ~6000 |
| CSIC 2010 | benign + hard-negative | ~36000 |
| FWAF | benign + hard-negative | ~30000 |
| Hard benign | benign (с кодом) | ~500 |

## Инструменты

- [OWASP CRS](https://coreruleset.org/) — бейзлайн сигнатурного подхода
- [SHAP](https://github.com/shap/shap) — интерпретируемость моделей
- [XSStrike](https://github.com/s0md3v/XSStrike) — движок обхода XSS
- [WAF-A-MoLE](https://github.com/AvalZ/WAF-A-MoLE) — референс алгоритма (SQLi)
- [Playwright](https://playwright.dev/) — headless-браузер для валидации пейлоадов
