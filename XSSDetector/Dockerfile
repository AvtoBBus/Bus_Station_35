FROM python:3.11-slim

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y \
    pkg-config \
    default-libmysqlclient-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

    
WORKDIR /xssdetector

COPY ./requirements.txt .
RUN pip install --no-cache-dir -r ./requirements.txt

# Копируем приложение
COPY . /xssdetector

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]