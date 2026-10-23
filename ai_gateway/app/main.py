"""Domain routes: the management and execution routers."""

from fastapi import APIRouter

from ai_gateway.app.routes import execution, management, ocr

api_router = APIRouter()
api_router.include_router(management.router)
api_router.include_router(execution.router)
api_router.include_router(ocr.router)
