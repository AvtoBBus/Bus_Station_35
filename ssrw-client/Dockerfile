# ==========================================
# ЭТАП 1: Сборка (Builder)
# ==========================================
FROM node:22-alpine AS builder

WORKDIR /app

# Сначала копируем только файлы зависимостей (для кэширования слоев)
COPY package*.json ./

# Устанавливаем зависимости
RUN npm ci

# Копируем весь остальной код
COPY . .

ENV PATH="/app/node_modules/.bin:$PATH"

# Собираем проект (создается папка dist)
RUN npm run build


# ==========================================
# ЭТАП 2: Раздача готовой статики (Runner)
# ==========================================
FROM nginx:alpine

# Удаляем дефолтную страницу Nginx
RUN rm -rf /usr/share/nginx/html/*

# Копируем ТОЛЬКО папку dist из первого этапа (builder)
COPY --from=builder /app/dist /usr/share/nginx/html

# Открываем порт 80 (внутри контейнера)
EXPOSE 80

# Запускаем Nginx
CMD ["nginx", "-g", "daemon off;"]