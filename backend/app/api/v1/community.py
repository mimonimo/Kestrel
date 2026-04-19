"""Community endpoints — placeholder. Wired in a later iteration.

Routes are declared so the frontend can discover them via OpenAPI, but they
currently return 501 Not Implemented.
"""
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/community", tags=["community"])


@router.get("/posts")
async def list_posts() -> dict:
    raise HTTPException(status_code=501, detail="community feature not implemented yet")


@router.get("/comments")
async def list_comments() -> dict:
    raise HTTPException(status_code=501, detail="community feature not implemented yet")
