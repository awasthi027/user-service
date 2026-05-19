# user-service

Spring Boot microservice that handles user registration, login (JWT Bearer tokens), and refresh-token rotation.  
Designed for deployment on **Railway** with a managed **PostgreSQL** database.

---

## Architecture

```
POST /api/users/register   → save user to PostgreSQL (BCrypt password)
POST /api/users/login      → validate credentials → issue access + refresh JWT
POST /api/users/refresh    → validate refresh token → rotate & issue new pair
GET  /api/users/{id}       → fetch user by ID
GET  /api/users            → list all users
GET  /api/users/health     → health check
```

**JWT claims (access token)** — compatible with API Gateway validation:

| Claim | Value |
|-------|-------|
| `sub` | userId |
| `iss` | `user-service` (configurable) |
| `aud` | `api-gateway` (configurable) |
| `jti` | unique token ID |
| `iat` | issued-at |
| `exp` | issued-at + 15 min |
| `email` | user's email |
| `role` | user's role |

---

## Environment Variables

| Variable | Description | Default (local dev) |
|----------|-------------|---------------------|
| `PGHOST` | PostgreSQL host | `localhost` |
| `PGPORT` | PostgreSQL port | `5432` |
| `PGDATABASE` | Database name | `userservice` |
| `PGUSER` | DB username | `postgres` |
| `PGPASSWORD` | DB password | `postgres` |
| `JWT_SECRET` | Base64-encoded HS256 key (≥ 32 bytes) | built-in dev key |
| `PORT` | HTTP port | `8080` |

> **Railway** injects `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` automatically  
> when you link a PostgreSQL service. Set `JWT_SECRET` as a Railway environment variable.

---

## Run Locally

### Prerequisites
- Java 17+  
- Maven 3.9+  
- PostgreSQL running locally (or Docker)

### Start a local PostgreSQL (Docker)
```bash
docker run -d \
  --name pg-userservice \
  -e POSTGRES_DB=userservice \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:16
```

### Run the application
```bash
export JWT_SECRET=bXlzdXBlcnNlY3JldGtleWZvcnVzZXJzZXJ2aWNlMTIzNDU2
mvn spring-boot:run
```

---

## Run Tests

```bash
mvn test
```

Tests use an **H2 in-memory database** — no PostgreSQL required.

| Test Class | Coverage |
|------------|----------|
| `JwtServiceTest` | token generation, claims, tamper detection, expiry (10 tests) |
| `UserServiceTest` | register, login, refresh, rotation, revocation (14 tests) |
| `UserControllerTest` | all HTTP endpoints, validation errors, auth flows (15 tests) |

---

## Example API Calls

### Register
```bash
curl -X POST http://localhost:8080/api/users/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com","password":"secure123"}'
```

### Login
```bash
curl -X POST http://localhost:8080/api/users/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"secure123"}'
```
Response:
```json
{
  "status": 200,
  "message": "Login successful",
  "data": {
    "tokenType": "Bearer",
    "accessToken": "<JWT>",
    "refreshToken": "<JWT>",
    "expiresIn": 900,
    "userId": "...",
    "email": "alice@example.com",
    "role": "user"
  }
}
```

### Use access token with API Gateway
```bash
curl -H "Authorization: Bearer <accessToken>" https://api-gateway/some/resource
```

### Refresh Token
```bash
curl -X POST http://localhost:8080/api/users/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refreshToken>"}'
```

---

## Railway Deployment

This repo includes a production `Dockerfile` and `railway.toml` so Railway can build and run reliably.

1. Push this repo to GitHub and connect it to a Railway service.
2. In Railway, set these service variables:
   - `JWT_SECRET` (generate with `openssl rand -base64 32`)
   - `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` (from your Neon project)
3. Trigger a deploy (Railway usually deploys automatically after repo connect, otherwise click **Deploy Latest Commit**).
4. Verify after deploy:
   - `GET /api/users/health` returns `200`
   - Logs show Flyway migrations ran successfully

### Neon (external PostgreSQL)

If DB is hosted outside Railway (Neon/Supabase), Railway will not auto-inject `PG*` variables. Add them manually in the service Variables tab.
