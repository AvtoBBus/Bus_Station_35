from fastapi import APIRouter, Depends, HTTPException, status, Response

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.message import MessageGetDTO, MessagePostDTO
from app.services.message import MessageService
from app.utils.db import get_db

from typing import List

router = APIRouter()


@router.get("/messages", response_model=List[MessageGetDTO])
async def get_messages(
    db: AsyncSession = Depends(get_db)
):

    service = MessageService(db)
    messages = await service.get_messages()

    return [
        MessageGetDTO(
            ID=message.ID,
            UserName=message.UserName,
            Text=message.Text,
            Date=message.Date
        ) for message in messages
    ]


@router.post("/create")
async def create_message(
    new_message: MessagePostDTO,
    response: Response,
    db: AsyncSession = Depends(get_db)
):

    service = MessageService(db)

    await service.create_message(new_message)

    response.status_code = 204

    return None
