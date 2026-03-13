from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.config import config
from app.config.logconfig import LOGGING_CONFIG

from app.routers import message as messages_router

from app.utils.logger import Colors, log_request_info, log_response_info

import logging
from logging.config import dictConfig
import time
import uuid
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    swagger_ui_parameters={"syntaxHighlight": True}
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


@app.middleware("https")
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

# app.include_router(food_router.router,
#                    prefix=config.settings.API_STR,
#                    tags=["Продукты"],
#                    dependencies=[Depends(RateLimiter(times=rl_times, seconds=rl_seconds))]
#                    )
