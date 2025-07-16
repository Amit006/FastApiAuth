## API Endpoints

### 1. Login - Obtain JWT Token

**Endpoint:** `POST /login`

**Request:**
```bash
curl -X POST "http://localhost:8000/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=johndoe&password=secret"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "bearer",
  "device_id": "a1b2c3d4e5"
}
```

---

### 2. User Profile - Protected Endpoint

**Endpoint:** `GET /profile`

**Request:**
```bash
curl "http://localhost:8000/profile" \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

**Response:**
```json
{
  "username": "johndoe",
  "device": {
    "id": "a1b2c3d4e5",
    "type": "mobile",
    "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)"
  },
  "message": "Authenticated from mobile device"
}
```