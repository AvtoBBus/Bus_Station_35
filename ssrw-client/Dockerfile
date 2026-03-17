FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json ./
COPY package-lock.json* ./

RUN npm ci || npm install

COPY . .

RUN npm run build

FROM node:22-alpine

RUN npm install -g serve

WORKDIR /app

EXPOSE 3000

CMD ["serve", "-s", "dist", "-l", "3000"]