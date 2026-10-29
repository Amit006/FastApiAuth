# Design Spec: OmniMarket — Secure Auth Gateway & Micro-Frontend Monorepo

**Date:** 2026-10-30
**Status:** Approved

---

## 1. Scope

Build a production-grade authentication system and Next.js micro-frontend monorepo for the OmniMarket platform, consisting of:

- **FastAPI Auth Gateway** — token issuance, rotation, reuse detection, Redis-backed registry
- **`@omnimarket/auth`** — custom build-time auth package (no external auth libraries)
- **Turborepo Monorepo** — three Next.js apps (`storefront`, `dashboard`, `creators`) plus shared packages

---

## 2. Repository Structure

### Backend (existing repo: `FastApi/`)
```
FastApi/
├── .env
├── requirements.txt
└── app/
    ├── main.py                  ← FastAPI app, CORS, router registration
    ├── core/
    │   └── config.py            ← pydantic-settings, loads .env
    ├── routers/
    │   └── auth.py              ← all auth endpoints
    ├── models/
    │   └── auth.py              ← Pydantic request/response schemas
    └── services/
        ├── token.py             ← JWT encode/decode, token creation
        └── redis_store.py       ← RedisTokenStore: save, get, mark_used, revoke_all
```

### Frontend (new monorepo: `omnimarket/`)
```
omnimarket/
├── apps/
│   ├── storefront/              ← Next.js App Router (port 3000)
│   ├── dashboard/               ← Next.js App Router (port 3001)
│   └── creators/                ← Next.js App Router (port 3002)
├── packages/
│   ├── auth/                    ← @omnimarket/auth
│   ├── ui/                      ← @omnimarket/ui
│   ├── tsconfig/                ← @omnimarket/tsconfig
│   └── eslint-config/           ← @omnimarket/eslint-config
├── turbo.json
└── package.json
```

---

## 3. FastAPI Auth Gateway

### Endpoints

| Method | Path | Success | Error |
|--------|------|---------|-------|
| `POST` | `/api/v1/auth/login` | `200 { accessToken }` | `401` wrong credentials, `422` validation |
| `POST` | `/api/v1/auth/refresh` | `200 { accessToken }` | `401` expired/missing, `403` reuse detected |
| `POST` | `/api/v1/auth/logout` | `204` | `401` no active session |
| `GET`  | `/api/v1/auth/session` | `200 { user, accessToken }` | `401` unauthenticated |

### Token Design

- **Access token** — HS256, 15-minute expiry
  - Payload: `{ sub, type: "access", exp }`
- **Refresh token** — HS256, 24-hour rolling window
  - Payload: `{ sub, type: "refresh", exp, absolute_exp }`
- **`absolute_exp`** — Unix timestamp set once at login (login time + 7 days). Copied unchanged on every rotation. Once breached, all refresh attempts return `401`.
- **Cookie** — `refresh_token`, `HttpOnly=True`, `Secure=True`, `SameSite=Lax`, `Path=/api/v1/auth`

### Redis Token Registry

```
key:   "rt:{token_string}"
value: { "user_id": str, "is_used": bool }
TTL:   absolute_exp - now  (auto-expires, no manual cleanup needed)
```

### Reuse Detection

When `/api/v1/auth/refresh` receives a token with `is_used=True`:
1. Call `revoke_all_user_sessions(user_id)` — deletes all `rt:*` keys for that user
2. Delete the `refresh_token` cookie on the response
3. Return `403 Forbidden`: `"Security breach detected. All sessions revoked."`

### Environment Variables (`.env`)

```env
SECRET_KEY=
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_HOURS=24
ABSOLUTE_SESSION_EXPIRE_DAYS=7
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001,http://localhost:3002
```

### CORS

```python
CORSMiddleware(
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,   # required for HttpOnly cookie forwarding
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
```

---

## 4. `@omnimarket/auth` Package

### Package Structure

```
packages/auth/
├── src/
│   ├── index.ts                    ← public exports
│   ├── types.ts                    ← Session, AuthState, ApiClientConfig
│   ├── context/
│   │   ├── AuthProvider.tsx        ← React context, token state, bootstrap
│   │   └── useAuth.ts              ← { session, isLoading, logout }
│   ├── client/
│   │   └── createApiClient.ts      ← fetch wrapper with auto-refresh + replay
│   ├── server/
│   │   ├── getSession.ts           ← server-side: reads cookie, verifies JWT
│   │   └── withAuth.ts             ← HOC for Next.js Server Components
│   └── middleware/
│       └── createAuthMiddleware.ts ← Next.js middleware factory (RBAC)
└── package.json
```

### Types

```typescript
interface Session {
  userId: string
  username: string
  accessToken: string     // volatile — React state only, never persisted
  absoluteExp: number     // UTC timestamp for "session expiring" warnings
}

interface AuthState {
  session: Session | null
  isLoading: boolean
}
```

### Bootstrap Flow (Approach C — Hybrid)

1. Request hits Next.js — `middleware.ts` runs, reads `refresh_token` cookie
2. Protected route + no cookie → `307` redirect to `/login`
3. Page renders — root `layout.tsx` mounts `<AuthProvider>`
4. `AuthProvider` calls `GET /api/auth/session` (Next.js Route Handler, same-origin)
5. Route Handler reads cookie server-side → calls FastAPI `GET /api/v1/auth/session`
6. Response: `{ session }` → `AuthProvider` stores `accessToken` in React state only
7. All client API calls use `createApiClient`, which reads token from context

### `createApiClient` Silent Refresh Logic

```
Request → inject Authorization: Bearer <accessToken>
       ↓
  Response 401?
       ↓ yes
  Call GET /api/auth/session (Route Handler → FastAPI /refresh)
       ↓ success                    ↓ fail (401 or 403)
  Update AuthProvider state         logout() → redirect /login
  Replay original request → 200
```

### `createAuthMiddleware` Config

```typescript
createAuthMiddleware({
  publicPaths: ['/login', '/register'],  // bypass cookie check
})
```

- Cookie present + valid → `next()` (continue)
- Cookie missing → `307` to `/login`
- Cookie malformed → `307` to `/login`

---

## 5. Next.js Apps

### `apps/storefront` — Public, SEO-first (port 3000)

No auth middleware. `AuthProvider` mounted optionally for cart/wishlist state.

| Route | Strategy | Rationale |
|-------|----------|-----------|
| `/`, `/about`, `/privacy` | SSG | Static content, build-time only |
| `/products/category/[id]` | ISR `revalidate: 60` | Stock updates without full rebuild |
| `/search?q=...` | SSR | Query params require on-demand evaluation |

Optimizations: `next/image` (WebP/AVIF), `next/font` (self-hosted, eliminates CLS), `next/script` (defer third-party).

### `apps/dashboard` — Protected, streaming-first (port 3001)

```
middleware.ts  ←  createAuthMiddleware({ publicPaths: ['/login'] })
```

| Route | Strategy | Key Concept |
|-------|----------|-------------|
| `/dashboard` | Streaming + Suspense | Shell instant, `<OrderHistory />` + `<PaymentMethods />` stream |
| `/dashboard/track/[id]` | CSR (SWR) | Live delivery map, polls FastAPI |
| `/api/auth/session/route.ts` | Route Handler | Cookie → FastAPI → returns `{ session }` |
| `/api/webhooks/payments/route.ts` | Route Handler | Async payment hook ingestion |

### `apps/creators` — Protected, App Router bleeding-edge (port 3002)

```
middleware.ts  ←  createAuthMiddleware({ publicPaths: [] })
```

| Route | Strategy | Key Concept |
|-------|----------|-------------|
| `/creators` | PPR | Static shell + dynamic revenue widget at edge |
| `/creators/upload` | Server Action (`"use server"`) | Media upload + metadata |
| `/creators/analytics` | Parallel Routes (`@revenue`, `@traffic`, `@sales`) | Non-blocking async slots |
| `/creators/sales/[id]` | Intercepting Route `(..)modal` | Modal overlay + shareable direct URL |

### Shared Route Handler Pattern

Each protected app (`dashboard`, `creators`) contains:
```
app/api/auth/session/route.ts
  GET → forward refresh_token cookie to FastAPI GET /api/v1/auth/session
      → 200 { session }  or  401 {}
```

---

## 6. Turborepo Pipeline

```json
{
  "tasks": {
    "build":      { "dependsOn": ["^build"], "outputs": [".next/**"] },
    "dev":        { "cache": false, "persistent": true },
    "lint":       { "dependsOn": ["^lint"] },
    "typecheck":  { "dependsOn": ["^typecheck"] }
  }
}
```

---

## 7. End-to-End Auth Data Flow

```
LOGIN
  Browser → POST /api/v1/auth/login
  FastAPI → 200 { accessToken } + Set-Cookie: refresh_token (HttpOnly)
  AuthProvider stores accessToken in React state

AUTHENTICATED REQUEST
  createApiClient → GET /api/v1/... (Authorization: Bearer <token>)
  FastAPI → 200 { data }

SILENT REFRESH (access token expired)
  createApiClient catches 401
  → GET /api/auth/session (Route Handler, same-origin)
    → FastAPI POST /api/v1/auth/refresh
    → marks old token is_used=True, issues new cookie + new accessToken
  AuthProvider updates state → original request replayed → 200

REUSE DETECTED (stolen token replayed)
  FastAPI sees is_used=True → 403
  → revoke_all_user_sessions(user_id) wipes all Redis keys
  → delete refresh_token cookie
  createApiClient catches 403 → logout() → 307 /login

ABSOLUTE SESSION EXPIRY (7 days)
  FastAPI sees now > absolute_exp → 401
  createApiClient catches 401 on /refresh → logout() → 307 /login

LOGOUT
  Browser → POST /api/v1/auth/logout
  FastAPI → 204 + delete cookie + revoke Redis key
  AuthProvider clears state → redirect /login
```

---

## 8. Security Properties

| Threat | Mitigation |
|--------|-----------|
| XSS token theft | Access token in React state only — no localStorage, no readable cookie |
| Refresh token theft via JS | HttpOnly cookie — inaccessible to JavaScript |
| CSRF on `/refresh` | `SameSite=Lax` blocks cross-site POST |
| Token replay / session hijack | Reuse detection → `403` + full session wipe |
| Infinite rolling sessions | `absolute_exp` hard ceiling, never extended |
| Dangling tokens after logout | Redis revocation + TTL auto-expiry |

---

## 9. Build Phases

| Phase | Scope |
|-------|-------|
| **1** | FastAPI backend: refactor into `app/` structure, Redis store, all 4 endpoints |
| **2** | Turborepo monorepo: scaffold, shared packages (`auth`, `ui`, `tsconfig`, `eslint-config`) |
| **3** | `apps/storefront`: SSG/ISR/SSR pages, `next/image`, `next/font` |
| **4** | `apps/dashboard`: middleware, streaming, SWR, Route Handlers |
| **5** | `apps/creators`: PPR, Server Actions, Parallel/Intercepting routes |
