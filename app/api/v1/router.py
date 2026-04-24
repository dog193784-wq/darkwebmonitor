"""API v1 router composition."""

from fastapi import APIRouter

from app.api.v1.endpoints.passwords import router as password_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(password_router)
