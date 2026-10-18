"""Domain routes: the management and execution routers."""

from fastapi import APIRouter

from ai_gateway.app.routes import execution, management

api_router = APIRouter()
api_router.include_router(management.router)
api_router.include_router(execution.router)
