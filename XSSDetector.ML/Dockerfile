# ---------------------------------------------------------------------------
# Сервис инференса XSS-детектора.
#
# Сборка разделена на стадии, чтобы пересборка кода не переустанавливала
# зависимости, а сам образ содержал только то, что нужно для работы API:
#   builder — ставит зависимости в отдельный venv (кэш pip не попадает в образ)
#   runtime — python + libgomp1 + venv + main.py + ml/ (код и веса моделей)
#
# Build-arg-и (по умолчанию включены, чтобы поведение не менялось):
#   INSTALL_TENSORFLOW=false  — lite-сборка без TF и весов LSTM/BiLSTM/Char-CNN
#   INSTALL_TRANSFORMER=false — lite-сборка без CPU-torch/transformers и DistilBERT
#
# Пример lite-сборки:
#   docker build --build-arg INSTALL_TENSORFLOW=false \
#                --build-arg INSTALL_TRANSFORMER=false -t xssdetector:lite .
# ---------------------------------------------------------------------------

ARG PYTHON_VERSION=3.11

# ------------------------------ builder ------------------------------------
FROM python:${PYTHON_VERSION}-slim AS builder

ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_INPUT=1

RUN python -m venv "$VIRTUAL_ENV"

WORKDIR /build

# Отдельный слой только для файлов зависимостей: правки кода его не сбрасывают
COPY requirements.txt requirements-tensorflow.txt requirements-transformer.txt ./

# 1) Базовый рантайм API. Кэш pip монтируется, поэтому в слои образа он не
#    попадает, но повторная установка тех же пакетов идёт из кэша.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip setuptools wheel \
 && pip install -r requirements.txt

# 2) TensorFlow — только для LSTM / BiLSTM / Char-CNN
ARG INSTALL_TENSORFLOW=true
RUN --mount=type=cache,target=/root/.cache/pip \
    if [ "$INSTALL_TENSORFLOW" = "true" ]; then \
        pip install -r requirements-tensorflow.txt; \
    fi

# 3) CPU-сборка torch (без CUDA, без torchvision/torchaudio) + transformers.
#    CPU-wheel примерно в 10 раз меньше CUDA-сборки.
ARG TORCH_VERSION=2.9.1
ARG INSTALL_TRANSFORMER=true
RUN --mount=type=cache,target=/root/.cache/pip \
    if [ "$INSTALL_TRANSFORMER" = "true" ]; then \
        pip install --index-url https://download.pytorch.org/whl/cpu "torch==${TORCH_VERSION}" \
     && pip install -r requirements-transformer.txt; \
    fi

# 4) Чистка venv: заголовочные файлы TF нужны только для сборки кастомных
#    C++-операций (tf.load_op_library), в инференсе не используются (~250 МБ).
#    tensorflow/lite не трогаем: на него ссылается импорт tensorflow.
RUN set -eux; \
    rm -rf "$VIRTUAL_ENV"/lib/python*/site-packages/tensorflow/include; \
    find "$VIRTUAL_ENV" -type d -name "__pycache__" -prune -exec rm -rf {} + || true

# ------------------------------ runtime ------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    TF_CPP_MIN_LOG_LEVEL=2 \
    XSS_ARTIFACTS_DIR=/XSSDetector/ml/artifacts \
    XSS_DATASETS_DIR=/XSSDetector/ml/datasets \
    XSS_RESULTS_DIR=/XSSDetector/results

# libgomp1 — единственная системная библиотека, которая нужна catboost/numba.
# Компиляторы и mysql-заголовки больше не требуются: все зависимости — wheel.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /XSSDetector

COPY --from=builder /opt/venv /opt/venv

# Только код сервиса и веса моделей (датасеты и артефакты отсекает .dockerignore)
COPY main.py ./
COPY ml ./ml

# Для lite-сборки убираем веса моделей, зависимости которых не установлены
ARG INSTALL_TENSORFLOW=true
ARG INSTALL_TRANSFORMER=true
RUN set -eux; \
    if [ "$INSTALL_TENSORFLOW" != "true" ]; then \
        rm -rf ml/models/lstm/weights ml/models/bilstm/weights ml/models/char_cnn/weights; \
    fi; \
    if [ "$INSTALL_TRANSFORMER" != "true" ]; then \
        rm -rf ml/models/transformer/weights; \
    fi; \
    find ml -type d -name "__pycache__" -prune -exec rm -rf {} + || true

RUN useradd --create-home --uid 1000 appuser \
 && chown -R appuser:appuser /XSSDetector

USER appuser

EXPOSE 8001

# /health не загружает модели, поэтому проверка быстрая даже при прогреве
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=5)"]

# Без --reload: dev-режим с автоперезагрузкой вынесен в docker-compose.override.yml
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
