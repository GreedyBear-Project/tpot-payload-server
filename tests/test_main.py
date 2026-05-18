from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_read_root() -> None:
    """Test the GET / endpoint returns greeting message."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello from T-Pot Payload Server"}
