from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from attest.config import settings

engine = create_async_engine(
    settings.database_url,
    pool_size=5,
    max_overflow=5,
    pool_pre_ping=True,
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False)