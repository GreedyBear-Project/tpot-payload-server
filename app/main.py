"""FastAPI application entry point for the T-Pot Payload Server."""

from fastapi import FastAPI

from app.routes import router

app = FastAPI(
    title="T-Pot Payload Server",
    description=("Stateless API to query and retrieve honeypot payload files from T-Pot data directories."),
)

app.include_router(router)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}
