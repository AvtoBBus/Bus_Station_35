import os

# Каталог для файловых логов (можно переопределить через APP_LOG_DIR)
LOG_DIR = os.getenv("APP_LOG_DIR", "logs")


def _can_write_logs(path: str) -> bool:
    """Проверяем, что в каталог логов можно писать.

    В контейнере рабочая директория может принадлежать root, а приложение
    запускается от непривилегированного пользователя — тогда файловые
    хендлеры создать нельзя и падал бы весь запуск приложения.
    """
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".write_probe")
        with open(probe, "w"):
            pass
        os.remove(probe)
        return True
    except OSError:
        return False


FILE_LOGS = _can_write_logs(LOG_DIR)

_handlers = {
    "console": {
        "class": "logging.StreamHandler",
        "formatter": "default",
        "level": "INFO"
    },
}

if FILE_LOGS:
    _handlers["file"] = {
        "class": "logging.handlers.RotatingFileHandler",
        "formatter": "detailed",
        "filename": os.path.join(LOG_DIR, "app.log"),
        "maxBytes": 10485760,  # 10MB
        "backupCount": 5,
        "level": "INFO"
    }
    _handlers["error_file"] = {
        "class": "logging.handlers.RotatingFileHandler",
        "formatter": "detailed",
        "filename": os.path.join(LOG_DIR, "error.log"),
        "maxBytes": 10485760,
        "backupCount": 5,
        "level": "ERROR"
    }

_myapp_handlers = ["console"] + (["file", "error_file"] if FILE_LOGS else [])
_uvicorn_handlers = ["console"] + (["file"] if FILE_LOGS else [])

# Конфигурация логирования
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s"
        }
    },
    "handlers": _handlers,
    "loggers": {
        "myapp": {
            "handlers": _myapp_handlers,
            "level": "INFO",
            "propagate": False
        },
        "uvicorn": {
            "handlers": _uvicorn_handlers,
            "level": "INFO",
            "propagate": False
        }
    }
}

