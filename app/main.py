from fastapi import FastAPI

app = FastAPI(title="T-Pot Payload Server")


@app.get("/")
def read_root() -> dict[str, str]:
    """Return a hello message from T-Pot Payload Server."""
    return {"message": "Hello from T-Pot Payload Server"}
