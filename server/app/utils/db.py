from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from app.config import config

engine = create_async_engine(config.settings.DATABASE_URL)
SessionLocal = async_sessionmaker(autocommit=False, autoflush=False, bind=engine, class_=AsyncSession)

# Dependency
async def get_db():
    async with SessionLocal() as session:
        yield session
