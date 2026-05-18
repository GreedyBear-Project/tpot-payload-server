from fastapi import FastAPI

app = FastAPI(title="T-Pot Payload Server")

@app.get("/")
def read_root():
    return {"message": "Hello from T-Pot Payload Server"}
