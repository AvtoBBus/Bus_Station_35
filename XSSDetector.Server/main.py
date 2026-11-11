from fastapi import FastAPI, Request
from fastapi.concurrency import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware

from app.config import config
from app.config.logconfig import LOGGING_CONFIG

from app.routers import message as messages_router

from app.utils.logger import Colors, log_request_info, log_response_info
from app.models.message import Base
from app.utils.db import SessionLocal, engine
from app.utils.seed import seed_mock_messages

import logging
from logging.config import dictConfig
import asyncio
import time
import uuid
from dotenv import load_dotenv

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Код до запуска приложения
    print("🚀 Создаём таблицы...")
    attempts = 10
    for attempt in range(1, attempts + 1):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            print("✅ Таблицы готовы")
            break
        except Exception as exc:
            if attempt == attempts:
                print(f"❌ Не удалось создать таблицы: {exc}")
                raise
            print(f"⏳ MySQL ещё не готов (попытка {attempt}/{attempts}): {exc}")
            await asyncio.sleep(3)

    if config.settings.SEED_DATA:
        print("🌱 Проверяем мок-данные...")
        try:
            async with SessionLocal() as session:
                inserted = await seed_mock_messages(session)
            print(f"✅ Мок-данные готовы (добавлено: {inserted})")
        except Exception as exc:
            # Мок-данные не должны мешать запуску сервиса
            print(f"⚠️ Не удалось добавить мок-данные: {exc}")

    yield
    # Код при остановке
    print("👋 Останавливаем приложение")

app = FastAPI(
    swagger_ui_parameters={"syntaxHighlight": True},
    lifespan=lifespan
)

dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("myapp")

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    await log_request_info(request, request_id)

    start_time = time.time()

    try:
        response = await call_next(request)
    except Exception as exc:
        short_id = request_id[:8]
        print(f"\n{Colors.BOLD}{Colors.RED}╔═══════════════════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.RED}║ 💥 ERROR [{short_id}]{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.RED}╠═══════════════════════════════════════════════════════════════{Colors.RESET}")
        print(
            f"{Colors.BOLD}{Colors.WHITE}║ {Colors.RED}Exception: {str(exc)}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.RED}╚═══════════════════════════════════════════════════════════════{Colors.RESET}\n")
        raise

    processing_time = time.time() - start_time
    await log_response_info(response, request_id, processing_time)

    return response

app.include_router(messages_router.router,
                   prefix=config.settings.API_STR,
                   tags=["Сообщения"],
                   )
