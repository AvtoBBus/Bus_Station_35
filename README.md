# Стенд обнаружения XSS-атак методами машинного обучения

## Архитектура

```text
┌─────────────────┐      POST /api/create       ┌──────────────┐      POST /predict       ┌──────────────┐
│  ssrw-client    │ ─────────────────────────►  │   FastAPI    │ ───────────────────────► │  xssdetector │
│  (React+Vite)   │  port 3000                  │  (server)    │      JSON body           │   (FastAPI)  │
│                 │ ◄─────────────────────────  │   port 8000  │ ◄─────────────────────   │   port 8001  │
└─────────────────┘    GET /api/messages        └──────┬───────┘                          └──────┬───────┘
                                                       │                                         │
                                                       ▼                                         ▼
                                              ┌─────────────────┐                       ┌─────────────────┐
                                              │    MySQL 8.0    │                       │   7 ML моделей  │
                                              │   port 3307     │                       │   (ансамбль)    │
                                              └─────────────────┘                       └─────────────────┘
```

### Поток инференса (онлайн):
1. Пользователь вводит текст в `ssrw-client` (React+Vite, порт 3000).
2. Клиент отправляет `POST /api/create` на FastAPI-сервер (порт 8000).
3. FastAPI пересылает текст в `xssdetector` через `POST /predict` (порт 8001).

---


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
├── xssdetector/                # ML-детектор (FastAPI + 7 моделей)
│   ├── main.py                 # API: /predict, /explain (ансамбль 7 моделей)
│   ├── utils/
│   │   ├── preprocess.py       # Рекурсивное декодирование (URL→HTML→Unicode→Hex)
│   │   ├── extract_features.py # Извлечение 80+ признаков безопасности
│   │   ├── load_models.py      # Кешированная загрузка 7 моделей + warm-up
│   │   └── shap_explainer.py   # SHAP-интерпретируемость (TreeSHAP, LinearSHAP, KernelSHAP)
│   ├── adversarial/            # Состязательное обучение (Раздел 3)
│   │   ├── xss_mutator.py      # Генератор обходящих XSS-пейлоадов (мутации)
│   │   ├── xss_oracle.py       # Оракул валидности (исполнимость в headless-браузере)
│   │   └── adversarial_training.py  # Цикл co-training: G атакует D → оракул → дообучение
│   ├── CatBoost/               # Модель CatBoost + метаданные
│   ├── RandomForest/           # Random Forest (.pkl)
│   ├── LogisticRegression/     # Logistic Regression (.pkl + scaler)
│   ├── SVM/                    # SVM RBF (.pkl + scaler)
│   ├── LSTM/                   # Bidirectional LSTM (.h5 + tokenizer)
│   ├── BiLSTM/                 # BiLSTM на декодированных данных (.h5 + tokenizer)
│   ├── Transformer/            # DistilBERT (checkpoint + tokenizer, Git LFS)
│   ├── CharCNN/                # Char-CNN (.keras + config.json)
│   ├── CRS_baseline/           # Сравнение с OWASP CRS (пункт 2.5)
│   │   ├── crs_evaluation.csv          — результаты CRS по PL1–PL4
│   │   ├── crs_vs_ml_comparison.csv  — сводная таблица ML vs CRS
│   │   ├── crs_vs_ml_roc_pr.png      — сравнительные ROC/PR-кривые
│   │   └── crs_roc_pr_curves.png     — CRS-only кривые
│   ├── Adversarial/            # Результаты состязательного обучения
│   ├── datasets_train/         # Обучающая выборка (8 источников)
│   ├── datasets_test/          # Тестовая выборка
│   └── data/                   # Сырые данные (8 источников)
│   ├── train_bilstm_decoded.py # Обучение BiLSTM на декодированных данных
│   ├── train_transformer.py    # Дообучение DistilBERT
│   └── compare_with_crs.py     # Сравнение с OWASP CRS (regex + HTTP + ML vs CRS)
│
├── docker-compose.yml          # 5 сервисов: mysql, fastapi, xssdetector, client, modsecurity
│
├── plan_VKR_XSS.md             # План работ ВКР (пункты 1-3, пункт 2.5 выполнен)
│
└── README.md                   # Этот файл
```

## Запуск

### Docker (рекомендуется)

```bash
  docker-compose up --build   # (поднимает все 5 сервисов)
```
```bash
  python train_charcnn.py          | → CharCNN
  python train_bilstm_decoded.py   | → BiLSTM
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

Скрипты обучения (`train_bilstm_decoded.py`, `train_transformer.py`) запускаются из `xssdetector/`

```bash
python train_bilstm_decoded.py          # BiLSTM на декодированных данных
python train_transformer.py             # DistilBERT трансформер (требует GPU)
```

### Сравнение с OWASP CRS

```bash
python compare_with_crs.py --mode compare  # ML vs CRS на общих ROC/PR осях
# Режимы: --mode regex (эмуляция), --mode modsec (через HTTP), --mode compare (сводное)
```

Симулирует правила CRS 941xxx (XSS Detection) на 4 уровнях паранойи (PL1-PL4)
и сравнивает с ML-моделями на одних и тех же данных.
`compare_with_crs.py` также лучше запускать из `xssdetector/` (там есть зависимости и данные)

### Состязательное обучение

```bash
cd adversarial
python adversarial_training.py          # Цикл co-training
```

`adversarial_training.py` находится в `xssdetector/adversarial/`, но цикл можно запускать и из корня с `python -m xssdetector.adversarial.adversarial_training`

Цикл co-training:
1. Генератор (10 операторов мутации) атакует детектор
2. Оракул проверяет исполняемость мутантов
3. Обходящие пейлоады добавляются в обучающую выборку
4. Детектор дообучается, метрики перемеряются

### SHAP-интерпретируемость

Сгенерируйте глобальное сравнение на отложенной выборке для CatBoost, RF, LR и SVM локально из корня репозитория:

```bash
.venv/Scripts/python -m xssdetector.generate_shap_report  # Глобальное сравнение
curl -X POST http://localhost:8001/explain \
  -H "Content-Type: application/json" \
  -d '{"text": "<script>alert(1)</script>"}'  # Локальное объяснение
```

Сравнение сохраняется в `xssdetector/results/global_shap_heldout.json`. Локальные Integrated Gradients для Transformer и LSTM приводятся отдельно, поскольку их токенные атрибуции не являются напрямую сопоставимыми с инженерными признаками.

```bash
curl -X POST http://localhost:8001/explain \
  -H "Content-Type: application/json" \
  -d '{"text": "<script>alert(1)</script>"}'
```

Ответ включает:

- **decoded_text** — декодированный вход
- **was_decoded** — изменился ли текст после декодирования
- **explanation_model** и explanation_method — указывают выбранный локальный объяснитель; для ансамблевых оценок по умолчанию используется CatBoost
- **top_features** — содержит локальные вклады SHAP или Integrated Gradients со знаком для explanation_model
- **transformer** — это опциональная модель для /predict и /explain; она загружает только локальные файлы контрольной точки/токенизатора и использует Integrated Gradients. Контрольная точка хранится через Git LFS; /predict и /explain возвращают 503, если локальные веса или объявленные зависимости torch/transformers недоступны
- **global_top_features** — содержит средние абсолютные значения SHAP для CatBoost на фиксированной выборке, стратифицированной по источнику и метке
- **global_sample_size** — сообщает количество использованных референсных строк
- **global_diagnostic_model** — указывает модель, использованную для глобальной диагностики смещения
- **bias_warning** — это эвристика, указывающая на концентрацию на признаках длины/энтропии, а не доказательство причинно-следственной связи

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
| Char-CNN | Символьный CNN | Символьные эмбеддинги + контекст | Transfer learning |

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
| ECML/PKDD 2007 | benign + hard-negative (+XSS-класс) | ~3000 | 
| Hard benign | benign (с кодом) | ~500 |

## Полный пайплайн обучения и оценки

Ниже показано всё, что делается в проекте — от подготовки данных до финальных сравнений:

```text
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           ЭТАП 1: ПОДГОТОВКА ДАННЫХ                                     │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                                                                          │
  8 источников данных                                                                     │
  ┌─────────────┐ ┌──────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────────────┐   │
  │ payloadbox  │ │ VulnXSS      │ │ Kaggle XSS  │ │ HttpParams  │ │ CSIC 2010        │   │
  │ (XSS)       │ │ (XSS)        │ │ (XSS+benign)│ │ (XSS+hard-) │ │ (benign+hard-)   │   │
  │ ECML/PKDD   │ │ FWAF         │ │ ModSec log  │ │ «Трудный»   │ │                  │   │
  │ 2007        │ │ (good/bad)   │ │ (hard-neg)  │ │ benign      │ │                  │   │
  └──────┬──────┘ └──────┬───────┘ └──────┬──────┘ └──────┬──────┘ └──────┬───────────┘   │
         │               │                │               │               │               │
         └───────────────┴────────────────┴───────────────┴───────────────┘               │
                                                                                          ▼
  ┌───────────────────────────────────────────────────────────────────────────────────────┐
  │  data/scripts/normalize_datasets.py — нормализация в unified_dataset.csv              │
  │  (разделение на XSS / benign / hard-negative, классификация контекста инъекции)       │
  └───────────────────────────────────────────────────────────────────────────────────────┘
                                                                                          │
                                                                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           ЭТАП 2: ОБУЧЕНИЕ МОДЕЛЕЙ                                      │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                                                                          │
  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐ │
  │ CatBoost    │   │ RandomForest│   │ LogisticReg │   │     SVM     │   │   LSTM      │ │
  │ (CBM+PKL)   │   │  (PKL)      │   │  (PKL+sc.)  │   │  (PKL+sc.)  │   │  (H5+PKL)   │ │
  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘ │
         │                 │                 │                 │                 │        │
         └─────────────────┴─────────────────┴─────────────────┴─────────────────┘        │
                                                                                          ▼
  ┌───────────────────────────────────────────────────────────────────────────────────────┐
  │  train_charcnn.py        → CharCNN/charcnn_xss.keras      (символьный CNN + контекст) │
  │  train_bilstm_decoded.py → BiLSTM/bilstm_decoded_model.h5 (BiLSTM на декодированном)  │
  │  train_transformer.py    → Transformer/best_model/        (DistilBERT дообучение)     │
  └───────────────────────────────────────────────────────────────────────────────────────┘
                                                                                          │
                                                                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           ЭТАП 3: ЛОДО-ОЦЕНКА                                           │
│                    Leave-One-Dataset-Out (кросс-доменная проверка)                      │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                                                                          
  evaluate_lodo_classical.py  →  CatBoost, RF, LR, SVM   →  results/lodo_classical.csv     
  evaluate_lodo_complex.py    →  Char-CNN, DistilBERT    →  results/lodo_charcnn.csv      
                                                                                          
```

## Инструменты

- [OWASP CRS](https://coreruleset.org/) — бейзлайн сигнатурного подхода
- [SHAP](https://github.com/shap/shap) — интерпретируемость моделей
- [XSStrike](https://github.com/s0md3v/XSStrike) — движок обхода XSS
- [WAF-A-MoLE](https://github.com/AvalZ/WAF-A-MoLE) — референс алгоритма (SQLi)
- [Playwright](https://playwright.dev/) — headless-браузер для валидации пейлоадов
