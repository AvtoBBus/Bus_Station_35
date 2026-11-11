# XSSDetector.ML — ML-детектор XSS-атак

FastAPI-сервис, выполняющий инференс ансамбля из 8 ML-моделей для обнаружения XSS-инъекций. Поддерживает предсказание, локальные объяснения (SHAP / Integrated Gradients) и автоматическую деградацию при отсутствии отдельных моделей.

## Архитектура

```text
              POST /predict /explain /health
                              │
                              ▼
┌─────────────────────────────────────────────────────────┐
│                     main.py (FastAPI)                   │
│  /predict  →  Predictor.predict_ensemble()              │
│  /explain  →  Predictor.predict_ensemble() + Explainer  │
│  /health   →  Status + available_models + loaded_models │
└──────────────────────┬──────────────────────────────────┘
                       │
              ┌────────▼────────┐
              │   Predictor     │
              │  (ml/serving/)  │
              │                 │
              │  predict_ens()  │  ← берёт model_names или
              │  load_model()   │     available_models (registry)
              └────┬────────┬───┘
                   │        │
         ┌─────────▼─┐  ┌───▼──────────────────┐
         │ Classical │  │   Deep Learning      │
         │  Models   │  │   (TF / torch)       │
         │           │  │                      │
         │ CatBoost  │  │ LSTM / BiLSTM        │
         │ Random RF │  │ DistilBERT           │
         │ LR        │  │ Char-CNN             │
         │ SVM       │  │                      │
         └───────────┘  └──────────────────────┘
```

### Ключевые принципы

- **Ленивая загрузка:** модели загружаются по требованию, не при старте.
- **Устойчивость к отсутствующим моделям:** если веса или зависимости отсутствуют, сервис запускается, возвращает `available_models` (только те, чьи артефакты из `manifest.json` есть на диске) и использует ансамбль из доступных.
- **Приоритет объяснителя для `/explain`:** catboost → random_forest → logistic_regression → svm → (deep learning без глобальных SHAP).

## Модели

Артефакты описаны в `ml/registry/manifest.json` (пути относительно `ml/`), список моделей — в `ml/config/models.yaml`.

| Модель | Группа | Артефакты | Метод объяснений |
|--------|--------|-----------|-----------------|
| CatBoost | classical | `catboost_xss_model.cbm` + `model_metadata.pkl` | CatBoost TreeSHAP |
| Random Forest | classical | `random_forest_xss.pkl` | TreeSHAP |
| Logistic Regression | classical | `logistic_regression_xss.pkl` + `lr_scaler.pkl` | LinearSHAP |
| SVM (RBF) | classical | `svm_rbf_xss.pkl` + `svm_scaler.pkl` | KernelSHAP |
| LSTM | complex | `lstm_xss_model.h5` + `lstm_tokenizer.pkl` | Integrated Gradients |
| BiLSTM | complex | `bilstm_decoded_model.h5` + `bilstm_decoded_tokenizer.pkl` | Integrated Gradients |
| DistilBERT | complex | `best_model/` + `tokenizer/` | Integrated Gradients |
| Char-CNN | complex | `charcnn_xss.keras` + `charcnn_config.json` | — |

**Ансамбль:** среднее вероятностей всех моделей, порог 0.5. Для классических моделей используется `predict_proba`, для нейросетей — второй элемент `predict_proba(text)` (если массив) или `predict_proba([text])[0]`.

## API

### `GET /health`

Лёгкая проверка живости: не загружает модели и не читает датасеты.

```json
{
  "status": "ok",
  "available_models": ["catboost", "random_forest", "logistic_regression", "svm", "lstm", "bilstm", "transformer", "char_cnn"],
  "loaded_models": ["catboost", "random_forest"]
}
```

### `POST /predict`

Запрос (`models` — опционально, по умолчанию все доступные):

```json
{
  "text": "<script>alert(1)</script>",
  "models": ["catboost", "random_forest", "logistic_regression"]
}
```

Ответ:

```json
{
  "is_xss": true,
  "probability": 0.9977,
  "threshold": 0.5,
  "code_sample": "<script>alert(1)</script>",
  "risk_level": "CRITICAL"
}
```

Недоступные модели пропускаются молча; если не смогла предсказать ни одна — `500`, если запрошена неизвестная — `422`.

### `POST /explain`

Тело запроса как у `/predict`. Ответ содержит предсказание плюс локальные и глобальные объяснения:

```json
{
  "is_xss": true,
  "probability": 0.9977,
  "risk_level": "CRITICAL",
  "decoded_text": "<script>alert(1)</script>",
  "was_decoded": false,
  "explanation_model": "catboost",
  "explanation_method": "CatBoost TreeSHAP",
  "global_diagnostic_model": "catboost",
  "top_features": [
    { "feature": "has_script_tag", "value": 0.45 },
    { "feature": "event_handler_count", "value": 0.18 }
  ],
  "global_top_features": [],
  "global_sample_size": 0,
  "bias_warning": null
}
```

**Уровни риска:** `CRITICAL` ≥ 0.8, `HIGH` ≥ 0.6, `MEDIUM` ≥ 0.4, `LOW` ≥ 0.2, иначе `SAFE`.

**Методы объяснений:** CatBoost — `CatBoost TreeSHAP`, Random Forest — `TreeSHAP`, Logistic Regression — `LinearSHAP`, SVM — `KernelSHAP`, LSTM/BiLSTM/Transformer — `Integrated Gradients`, Char-CNN — локальных атрибуций нет. Если объяснение не удалось, `explanation_method` содержит `"<модель>: explanation unavailable"`, а `top_features` пуст.

**Выбор модели объяснения:** если в запросе указана одна модель — объясняется она (при недоступности каскад catboost → random_forest → logistic_regression → svm), иначе по умолчанию CatBoost.

## Docker

### Сборка

**Полный образ** (все 8 моделей, ~5.8 GB, сборка ~28 мин):

```bash
docker build -t xssdetector:full .
```

**Lite-образ** (только классические модели, ~2 GB, сборка ~1 мин):

```bash
docker build \
  --build-arg INSTALL_TENSORFLOW=false \
  --build-arg INSTALL_TRANSFORMER=false \
  -t xssdetector:lite .
```

### Запуск

`HEALTHCHECK` уже объявлен в образе и обращается к `/health`, поэтому отдельный `--health-cmd` не нужен:

```bash
docker run -p 8001:8001 xssdetector:full
```

В составе стенда сервис поднимается из корня репозитория через `docker compose up --build`.

### Разделение зависимостей

| Файл | Содержит | Для чего |
|------|----------|----------|
| `requirements.txt` | FastAPI, uvicorn, pydantic, numpy, pandas, scikit-learn, catboost, shap, PyYAML, watchfiles | Базовый API |
| `requirements-tensorflow.txt` | tensorflow==2.21.0, tf_keras==2.21.0 | LSTM / BiLSTM / Char-CNN |
| `requirements-transformer.txt` | transformers==4.53.0 | DistilBERT |
| `requirements-train.txt` | datasets, accelerate, playwright, seaborn и др. | Только обучение, в образ не попадает |

### .dockerignore

Исключает: `ml/datasets/`, `ml/artifacts/runs/`, `results/`, `tests/`, `docs/`, `ml/docs/`, `*.md`, `__pycache__`, `*.pyc`, `.venv`, `.git`. Размер контекста: 3747 → 310 МБ.

## ML-пайплайн (CLI)

Все команды запускаются из `XSSDetector.ML/`:

```bash
python -m ml list-models                          # Доступные модели из manifest.json
python -m ml train --model catboost               # Обучение одной или «all»
python -m ml evaluate --model catboost            # LODO-оценка → results/
python -m ml stats --all [--format table|json]    # Метрики последних run-ов
python -m ml lodo-summary                         # Сравнение LODO по всем моделям
python -m ml crs-compare [--models ...]           # ML vs OWASP CRS
python -m ml shap-reference --source <path>       # Создание референсной выборки для глобального SHAP
```

### Как читать результаты

1. **`stats`** — метрики на случайной отложенной части *того же* датасета. Значения 0.98–0.999 ожидаемы и не говорят об обобщаемости.
2. **`lodo-summary`** — честная проверка обобщаемости: обучение без одного источника, проверка на нём.
3. **`crs-compare`** — CRS и ML на одном наборе (`--dataset <путь>`). Режим `--ml-source runs` использует метрики из run-ов (несопоставим с CRS, другие выборки).

### SHAP-объяснения

Глобальный SHAP в Docker-образе берёт данные из `ml/config/shap_reference_sample.csv` (датасеты в образ не попадают). Файл создаётся один раз на машине, где есть тестовый набор, и коммитится:

```bash
python -m ml shap-reference --source <путь к xss_dataset.csv>   # опционально --n 512 --out <путь>
```

Если файла нет, `/explain` работает как раньше, но `global_top_features` пуст, `global_sample_size = 0`.

## Результаты

Раздел собран из фактических прогонов: `python -m ml stats --all` (in-distribution), `python -m ml lodo-summary` (пункт 2.4), `results/global_shap_heldout.json` (пункт 2.3), `python -m ml crs-compare` (пункт 2.5) и `ml/training/adversarial/results/adversarial_results.json` (раздел 3). Артефакты обучения — 8 run-ов в `ml/artifacts/runs/`, по одному на модель.

### In-distribution holdout (`stats --all`)

Случайная отложенная часть *того же* датасета, на котором модель обучалась. Значения 0.98–0.999 ожидаемы и **не** являются мерой обобщаемости — см. LODO ниже.

| Модель | ROC-AUC | PR-AUC | TPR@1%FPR | FPR | Accuracy | F1 | n_test |
|--------|---------|--------|-----------|-----|----------|----|--------|
| CatBoost | 0.9996 | 0.9947 | 0.9949 | 0.0001 | 0.9994 | 0.9824 | 361 226 |
| Random Forest | 0.9985 | 0.9819 | 0.9855 | 0.0001 | 0.9981 | 0.9387 | 361 226 |
| Logistic Regression | 0.9874 | 0.9227 | 0.9455 | 0.0015 | 0.9961 | 0.8816 | 361 226 |
| SVM | 0.9952 | 0.9922 | 0.9574 | 0.0116 | 0.9803 | 0.9737 | 16 060 |
| LSTM | 0.9992 | 0.9991 | 0.9955 | 0.0036 | 0.9950 | 0.9934 | 16 060 |
| BiLSTM | 0.9975 | 0.9977 | 0.9556 | 0.0194 | 0.9856 | 0.9857 | 10 000 |
| Transformer | 0.9992 | 0.9991 | 0.9910 | 0.0138 | 0.9912 | 0.9912 | 10 000 |
| Char-CNN | 0.9982 | 0.9981 | 0.9422 | 0.0244 | 0.9806 | 0.9807 | 10 000 |

`n_test` различается: классические модели обучаются на полном `unified_dataset.csv`, нейросетевые — на подвыборках. Прямое сравнение по `n_test` некорректно.

### LODO (пункт 2.4, Leave-One-Dataset-Out)

Среднее по всем источникам, для которых у модели есть LODO-результат. Набор источников у моделей разный, поэтому средние **несопоставимы между собой** — это сводка по каждой модели.

| Модель | Источников | PR-AUC | ROC-AUC | TPR@1%FPR | FPR на benign |
|--------|-----------|--------|---------|-----------|---------------|
| CatBoost | 10 | 0.6734 | 0.9445 | 0.1938 | — |
| Random Forest | 5 | 0.9412 | 0.9521 | 0.7487 | 0.0394 |
| Logistic Regression | 5 | 0.8393 | 0.8404 | 0.5373 | 0.0706 |
| SVM | 5 | 0.8542 | 0.8570 | 0.7098 | 0.3380 |
| LSTM | 5 | 0.7811 | 0.9538 | 0.2378 | — |
| BiLSTM | 5 | 0.7947 | 0.9286 | 0.3192 | — |
| Transformer | 5 | 0.6173 | 0.9054 | 0.2916 | — |
| Char-CNN | 5 | 0.8069 | 0.7934 | 0.4665 | 0.3018 |

ROC-AUC по источникам (CatBoost обучен на 10 источниках, остальные — на 5 общих):

| Источник | CatBoost | RF | LR | SVM |
|----------|----------|-----|-----|-----|
| csic2010 | — | 0.954 | 0.737 | 0.687 |
| ecmlpkdd2007 | 0.959 | 0.939 | 0.803 | 0.777 |
| httpparams | 0.954 | 0.992 | 0.928 | 0.977 |
| kaggle | 0.954 | 1.000 | 1.000 | 0.999 |
| modsecurity | 0.911 | 0.875 | 0.734 | 0.844 |

Сопоставимое сравнение возможно только на **общих** для всех моделей источниках — их два (`httpparams`, `kaggle`):

| Модель | ROC-AUC (mean ± std) | PR-AUC (mean ± std) | TPR@1%FPR (mean) |
|--------|---------------------|--------------------|------------------|
| Random Forest | 0.9962 ± 0.0053 | 0.9946 ± 0.0077 | 0.9417 |
| LSTM | 0.9918 ± 0.0063 | 0.9912 ± 0.0123 | 0.4117 |
| SVM | 0.9879 ± 0.0152 | 0.9886 ± 0.0146 | 0.9467 |
| Logistic Regression | 0.9640 ± 0.0508 | 0.8955 ± 0.1477 | 0.5061 |
| CatBoost | 0.9542 ± 0.0001 | 0.9709 ± 0.0399 | 0.4211 |
| BiLSTM | 0.9019 ± 0.1280 | 0.9927 ± 0.0059 | 0.4409 |
| Transformer | 0.9015 ± 0.0988 | 0.6949 ± 0.4115 | 0.4746 |
| Char-CNN | 0.6009 ± 0.5563 | 0.6690 ± 0.4590 | 0.4821 |

> **Вывод пункта 2.4:** источников пересечения 2 (< 3), поэтому единый ранкинг моделей не делается. Видно, что LODO-качество заметно ниже in-distribution (0.94–0.996 против 0.98–0.999), а разброс между источниками велик — модели по-разному держат unseen-данные.

### Глобальный SHAP (пункт 2.3)

`results/global_shap_heldout.json`: стратифицированная выборка 128 примеров (по `source` и `label`), средние |SHAP|. Топ-5 признаков:

| Место | CatBoost (TreeSHAP) | RF (TreeSHAP) | LR (LinearSHAP) | SVM (KernelSHAP) |
|-------|--------------------|--------------|-----------------|-----------------|
| 1 | url_keywords_evil (0.277) | js_dom_alert (0.145) | js_dom_alert (3.851) | js_dom_alert (0.274) |
| 2 | text (0.250) | js_function_calls (0.134) | js_function_calls (1.484) | url_keywords_evil (0.055) |
| 3 | js_dom_alert (0.107) | url_keywords_evil (0.126) | url_keywords_evil (1.471) | js_function_calls (0.034) |
| 4 | js_max_length (0.017) | js_max_length (0.026) | html_tag_input (0.771) | html_tag_form (0.031) |
| 5 | url_tag_style (0.0001) | html_attr_class (0.026) | html_tag_form (0.678) | html_attr_action (0.028) |

**Диагностика смещения:** `biased = false` у всех четырёх моделей — явной концентрации на признаках длины/энтропии нет. Решающими оказываются смысловые XSS-признаки (`js_dom_alert`, `url_keywords_evil`, `js_function_calls`), а не эвристики размера строки.

LSTM и Transformer в это сравнение не включены: их Integrated Gradients дают атрибуции по токенам, несопоставимые с инженерными признаками.

### Пункт 2.5 (сравнение с OWASP CRS на независимом наборе)

Выполнено на независимом тестовом наборе `mendeley_data.csv` (2999 примеров: 1908 XSS, 1091 Normal), который не участвовал в обучении моделей. Это позволяет оценить истинную обобщающую способность ML-моделей против сигнатурного WAF в условиях Out-of-Distribution (OOD). Файлы: `CRS_baseline/crs_evaluation.csv`, `crs_vs_ml_comparison.csv`, `crs_vs_ml_roc_pr.png`.

| Модель | ROC-AUC | PR-AUC | TPR@1%FPR | FPR | Accuracy |
|--------|---------|--------|-----------|-----|----------|
| **CRS PL1** | 0.7791 | 0.8394 | 0.5613 | 0.0000 | 0.4948 |
| **CRS PL2** | 0.7791 | 0.8394 | 0.5613 | 0.0027 | 0.4938 |
| **CRS PL3** | 0.8588 | 0.8976 | 0.7227 | 0.0027 | 0.7199 |
| **CRS PL4** | 0.8133 | 0.8962 | 0.7227 | 0.0082 | 0.8206 |
| catboost | 0.9815 | 0.9895 | 0.7757 | 0.0788 | 0.9340 |
| random_forest | 0.9669 | 0.9856 | 0.8962 | 0.0000 | 0.7359 |
| logistic_regression | 0.9011 | 0.9583 | 0.8543 | 0.0000 | 0.7326 |
| svm | 0.9602 | 0.9831 | 0.9130 | 0.0009 | 0.8183 |
| lstm | 0.9719 | 0.9857 | 0.7191 | 0.0293 | 0.8910 |
| bilstm | 0.9514 | 0.9724 | 0.4644 | 0.1182 | 0.8606 |
| transformer | 0.8962 | 0.9419 | 0.4811 | 0.3850 | 0.7903 |
| char_cnn | 0.9636 | 0.9819 | 0.7820 | 0.1036 | 0.9123 |

> **Лучшая ML-модель:** CatBoost (PR-AUC=0.9895, ROC-AUC=0.9815).
> **Лучший уровень CRS:** PL3 по PR-AUC (0.8976).
>
> **Ключевые выводы:**
> 1. **Превосходство ML по качеству:** Все 8 ML-моделей (даже самая слабая — Transformer с PR-AUC 0.9419) значительно обходят любой уровень паранойи CRS по ROC-AUC и PR-AUC на независимых данных. Это доказывает, что ML-модели способны улавливать семантические паттерны XSS лучше, чем жесткие регулярные выражения.
> 2. **TPR@1%FPR:** Здесь лидируют Random Forest, SVM и Logistic Regression (0.89–0.91), что делает их отличным выбором для SOC, где критичен низкий уровень ложных срабатываний (FPR ≈ 0.000).
> 3. **Проблема FPR у нейросетей:** Нейросетевые модели (особенно Transformer с FPR 0.3850) склонны к переобучению на специфику исходного датасета и хуже генерализуются на новые легитимные данные. Классические модели (особенно RF и LR) демонстрируют нулевой FPR.
>
> Ограничение: несмотря на то, что CRS проигрывает по абсолютным метрикам, он не требует GPU и обучения. Однако результаты подтверждают мотивацию Раздела 3: ML-модели можно дообучать на состязательных атаках, а CRS (по данным AdvModSec, arXiv:2308.04964) на таких данных падает почти до случайного уровня.

Команда для повтора: `python -m ml crs-compare --dataset ml/datasets/test/mendeley_data.csv --ml-source predict`.

### Состязательное обучение (раздел 3)

`ml/training/adversarial/results/adversarial_results.json`. Цикл co-training: генератор мутаций атакует детектор → оракул проверяет исполнимость → обходящие пейлоады добавляются в обучение → CatBoost дообучается.

| Раунд | ROC-AUC (clean) | PR-AUC | TPR@1%FPR | Recall XSS | FPR | Evasion rate | Адоптировано |
|-------|-----------------|--------|-----------|-----------|-----|--------------|--------------|
| 0 (baseline) | 0.9992 | 0.9872 | 0.9938 | 0.9938 | 0.0564 | 50.0% | 0 |
| 1 | 0.9985 | 0.9734 | 0.9875 | 0.9000 | 0.0006 | 30.0% | 3 |
| 2 | 0.9988 | 0.9736 | 0.9875 | 0.8938 | 0.0006 | 60.0% | 6 |
| 3 | 0.9989 | 0.9735 | 0.9875 | 0.8938 | 0.0005 | 40.0% | 4 |

**Что видно:** дообучение на обходящих мутантах резко снижает FPR на чистых данных (0.0564 → 0.0006, примерно в 90 раз) при почти неизменном ROC-AUC; ценой является падение recall на чистом наборе (0.9938 → 0.8938).

**Ограничения прогона (важно):**
- Evasion rate считается по **10 seed-пейлоадам**, поэтому шаг измерения — 10 п.п., а различия 30% / 40% / 60% статистически незначимы.
- Каждый раунд атакует тот же набор из 10 сидов, но модель после раунда меняется, поэтому немонотонность (30% → 60%) объясняется стохастичностью мутатора, а не регрессией модели.
- `MAX_ROUNDS = 3`, `EVASION_THRESHOLD = 10%`: критерий устойчивости за 3 раунда не достигнут.
- Оракул в этом прогоне — эвристический (`validate_payload_heuristic`), без headless-браузера Playwright.

---

## Как добавить модель

1. Папка `ml/models/<name>/` с файлами:
   - `config.py` — метаданные (group, artifact paths)
   - `adapter.py` — `predict_proba(text, features)`
   - `train.py` — обучение → артефакты в `ml/artifacts/runs/`
   - `evaluate_lodo.py` — LODO-оценка
2. Запись в `ml/config/models.yaml`.
3. Запись в `ml/registry/manifest.json` (пути относительно `ml/`).
4. Если модель классическая (табличные признаки), добавить в `CLASSICAL_MODELS` в `ml/evaluation/scoring.py`.
5. Тест в `ml/tests/`.

## Тесты

```bash
python -m unittest discover -s ml/tests -t .
```

## Структура ML-пакета

```
ml/
├── cli.py                      # CLI-клиент (list-models, train, evaluate, stats…)
├── config/                     # models.yaml, shap_reference_sample.csv
├── features/                   # Извлечение признаков (XSShield, 80+ фичей)
├── models/                     # Адаптеры моделей (train/predict/evaluate)
│   ├── catboost/               config.py, adapter.py, train.py, evaluate_lodo.py
│   ├── random_forest/          …
│   ├── logistic_regression/    …
│   ├── svm/                    …
│   ├── lstm/                   …
│   ├── bilstm/                 …
│   ├── transformer/            …
│   └── char_cnn/               …
├── registry/                   # manifest.json, loader.py (available_models)
├── serving/                    # predictor.py (ансамбль, ленивая загрузка)
├── explainers/                 # explainer.py (SHAP + Integrated Gradients)
├── datasets/                   # raw, processed, test
├── artifacts/                  # trained models, runs
├── evaluation/                 # LODO, CRS, SHAP-отчёты
├── training/                   # Состязательное обучение
└── tests/                      # Модульные тесты