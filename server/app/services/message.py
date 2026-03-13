from fastapi import HTTPException

from app.schemas.message import MessagePostDTO
from app.models.message import Message

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from datetime import datetime
import requests


class MessageService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_messages(self):
        async with self.db as session:
            result = await session.execute(select(Message))
            data = result.scalars().all()
            return data

    async def create_message(self, new_message: MessagePostDTO):

        response = requests.request("POST",
                                    "http://127.0.0.1:8080/predict?text=" + new_message.Text)

        prediction_result = response.json()

        if not prediction_result["is_xss"]:
            async with self.db as session:
                inserted = Message(
                    UserName=new_message.UserName,
                    Text=new_message.Text,
                    Date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )

                session.add(inserted)
                await session.commit()
                await session.refresh(inserted)

                return None
        else:
            raise HTTPException(
                status_code=400,
                detail="Обнаружен подозрительный код"
            )
