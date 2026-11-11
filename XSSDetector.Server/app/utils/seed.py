"""Базовые мок-данные для демонстрации работы сервиса."""

import logging
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.message import Message

logger = logging.getLogger("myapp")

# (UserName, Text, сколько минут назад написано)
MOCK_MESSAGES: list[tuple[str, str, int]] = [
    ("admin", "Добро пожаловать в XSS Detector! Здесь можно оставить сообщение.", 120),
    ("security", "Все входящие сообщения проверяются моделью машинного обучения.", 90),
    ("tester", "Попробуйте отправить <script>alert(1)</script> — такое сообщение будет отклонено.", 60),
    ("analyst", "Подозрительные запросы не сохраняются в базе, а возвращают ошибку 400.", 30),
    ("guest", "Это тестовые данные, они добавляются один раз при первом запуске.", 5),
]


async def seed_mock_messages(session: AsyncSession) -> int:
    """Добавляет мок-сообщения, если таблица messages пуста.

    Возвращает количество вставленных записей (0, если данные уже есть).
    """
    existing = await session.scalar(select(func.count()).select_from(Message))
    if existing:
        logger.info("Мок-данные не нужны: в таблице messages уже %s записей", existing)
        return 0

    now = datetime.now()
    session.add_all(
        [
            Message(UserName=user_name, Text=text, Date=now - timedelta(minutes=minutes_ago))
            for user_name, text, minutes_ago in MOCK_MESSAGES
        ]
    )
    await session.commit()
    logger.info("Добавлено мок-сообщений: %s", len(MOCK_MESSAGES))
    return len(MOCK_MESSAGES)
