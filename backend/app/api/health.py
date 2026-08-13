"""Health-check endpoint."""

from fastapi import APIRouter, status

router = APIRouter(tags=["health"])


@router.get("/health", status_code=status.HTTP_200_OK)
def health_check() -> dict[str, str]:
    """Report that the backend process is ready to receive requests."""
    return {"status": "ok"}
