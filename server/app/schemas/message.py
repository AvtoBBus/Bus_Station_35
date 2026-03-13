from pydantic import BaseModel
from datetime import datetime


class MessageBase(BaseModel):
    UserName: str
    Text: str


class MessageGetDTO(MessageBase):
    Date: datetime


class MessagePostDTO(MessageBase):
    ...
