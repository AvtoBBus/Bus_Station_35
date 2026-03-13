from sqlalchemy import Integer, String, DateTime
from sqlalchemy.orm import mapped_column, Mapped, DeclarativeBase

from datetime import datetime


class Base(DeclarativeBase):
    ...


class Message(Base):
    __tablename__ = "messages"

    ID: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True)
    UserName: Mapped[str] = mapped_column(String(25), nullable=False)
    Date: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    Text: Mapped[str] = mapped_column(String(1000), nullable=False)
