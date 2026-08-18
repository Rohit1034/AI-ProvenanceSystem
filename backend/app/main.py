import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.core.config import get_settings
from backend.app.core.logging import setup_logging
from backend.app.api.routes import router as api_router

logger = logging.getLogger("provenance.main")


async def _keep_alive_loop(url: str, interval: int):
    """Periodically ping a URL to keep free-tier instances from idling."""
    await asyncio.sleep(10)
    import httpx
    async with httpx.AsyncClient(timeout=10) as client:
        while True:
            try:
                r = await client.get(url)
                logger.info("Keep-alive ping sent to %s (status: %d)", url, r.status_code)
            except Exception as e:
                logger.debug("Keep-alive ping error: %s", e)
            await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    setup_logging(settings.LOG_LEVEL, settings.LOG_FORMAT)

    from backend.app.core.database import engine, Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    keep_alive_task = None
    if settings.KEEP_ALIVE_URL:
        keep_alive_task = asyncio.create_task(
            _keep_alive_loop(settings.KEEP_ALIVE_URL, settings.KEEP_ALIVE_INTERVAL_SECONDS)
        )

    yield

    if keep_alive_task:
        keep_alive_task.cancel()

    from backend.app.core.database import engine
    await engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    origins = settings.CORS_ORIGINS if settings.CORS_ORIGINS else ["*"]
    is_wildcard = "*" in origins

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins if not is_wildcard else ["*"],
        allow_origin_regex=r"https://.*\.vercel\.app|https://.*\.onrender\.com|http://localhost:.*" if is_wildcard else None,
        allow_credentials=not is_wildcard,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

    @app.get("/", include_in_schema=False)
    async def root():
        return JSONResponse({
            "service": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "status": "online",
            "docs": "/docs",
            "health": "/healthz",
            "api": f"{settings.API_V1_PREFIX}/analyze",
        })

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return JSONResponse({"status": "healthy", "service": settings.PROJECT_NAME})

    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    return app


app = create_app()
