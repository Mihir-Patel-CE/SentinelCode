from fastapi.testclient import TestClient


def test_register_user_success(client: TestClient):
    payload = {
        "email": "developer@example.com",
        "username": "devuser",
        "password": "SecurePassword123!"
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "developer@example.com"
    assert data["username"] == "devuser"
    assert "id" in data


def test_register_duplicate_email(client: TestClient):
    payload = {
        "email": "duplicate@example.com",
        "username": "user1",
        "password": "SecurePassword123!"
    }
    res1 = client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    payload2 = {
        "email": "duplicate@example.com",
        "username": "user2",
        "password": "SecurePassword123!"
    }
    res2 = client.post("/api/v1/auth/register", json=payload2)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"]


def test_login_and_me_profile(client: TestClient):
    # 1. Register
    reg_payload = {
        "email": "authuser@example.com",
        "username": "authuser",
        "password": "SecurePassword123!"
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    # 2. Login
    login_payload = {
        "username_or_email": "authuser",
        "password": "SecurePassword123!"
    }
    res = client.post("/api/v1/auth/login", json=login_payload)
    assert res.status_code == 200
    token_data = res.json()
    assert "access_token" in token_data
    token = token_data["access_token"]

    # 3. Access /me with token
    headers = {"Authorization": f"Bearer {token}"}
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["username"] == "authuser"
    assert me_data["email"] == "authuser@example.com"


def test_login_invalid_password(client: TestClient):
    reg_payload = {
        "email": "badpw@example.com",
        "username": "badpw",
        "password": "CorrectPassword123!"
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    login_payload = {
        "username_or_email": "badpw",
        "password": "WrongPassword!"
    }
    res = client.post("/api/v1/auth/login", json=login_payload)
    assert res.status_code == 401


def test_demo_login_creates_and_returns_valid_token(client: TestClient):
    res = client.post("/api/v1/auth/demo-login")
    assert res.status_code == 200
    token_data = res.json()
    assert "access_token" in token_data
    token = token_data["access_token"]

    # Verify token works for /me
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["username"] == "demodev"
    assert me_data["email"] == "demouser@sentinelcode.dev"


def test_demo_login_idempotent(client: TestClient):
    res1 = client.post("/api/v1/auth/demo-login")
    assert res1.status_code == 200
    res2 = client.post("/api/v1/auth/demo-login")
    assert res2.status_code == 200


def test_standard_login_with_demo_credentials(client: TestClient):
    # Ensure demo user exists
    client.post("/api/v1/auth/demo-login")

    # Now standard login with demo credentials must work
    res = client.post("/api/v1/auth/login", json={
        "username_or_email": "demodev",
        "password": "DemoPassword123!"
    })
    assert res.status_code == 200
    assert "access_token" in res.json()
