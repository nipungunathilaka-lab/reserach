# Local Auth Connection Reset Fix Report

## 1. Root Cause
The `net::ERR_CONNECTION_RESET` and infinite "Authenticating..." issues were caused by three overlapping issues:
1. **Port Mismatch & Legacy Configuration:** The frontend API client (`VITE_API_URL` and hardcoded fallback) and legacy scripts were pointing to port `5000`, while the expected backend port was `5001`. Additionally, the backend's own `.env` file explicitly declared `PORT=5000`.
2. **MongoDB Race Condition:** The Node API process called `app.listen()` immediately on startup before the MongoDB connection succeeded. Early requests (like `/api/auth/me`) from the frontend were hitting an unready server, leading to connection resets and failures.
3. **Overzealous Token Removal:** The `AuthContext.jsx` file caught all errors on `/api/auth/me` (including connection crashes) and deleted the `secureft_token` from local storage. It failed to distinguish between network errors and actual `401/403` unauthenticated responses.

## 2. Browser Request Before Fix
- **URL:** `http://localhost:5000/api/auth/me` & `http://localhost:5000/api/auth/login`
- **Port:** `5000`
- **Method:** `GET` / `POST`

## 3. Backend State
- **Node listening:** Yes, it is now exclusively listening on port `5001`.
- **PID:** Successfully acquired on port 5001.
- **MongoDB:** Connected synchronously *before* accepting requests.
- **Process stable:** Yes, tested with `npm run start:node`. Survives HTTP requests successfully.

## 4. Configuration Mismatch
- **Old API URL:** `http://localhost:5000/api`
- **Correct API URL:** `http://localhost:5001/api`

## 5. Files Modified

| File | Change | Reason |
|------|--------|--------|
| `backend-node/.env` | Changed `PORT=5000` to `PORT=5001` | To correct the primary backend listening port. |
| `backend-node/server.js` | Refactored `app.listen()` to await `connectDB()` | To resolve the MongoDB connection startup race condition. |
| `frontend/.env` | Changed `VITE_API_URL` to `http://localhost:5001` | To aim frontend requests to the correct Node port. |
| `frontend/src/api/client.js` | Updated port `5000` fallback to `5001` | To prevent fallback to the wrong port. Added dev URL diagnostics. |
| `frontend/src/auth/AuthContext.jsx` | Fixed `catch` block on `/auth/me` | To only remove token on 401/403 responses, preventing network resets from logging out users. |
| `test_mfa_lifecycle.py`, `tc10_stress_test.py`, `README.md`, etc. | Changed `5000` to `5001` | To clean up legacy runtime configs across the repository. |

## 6. Auth Behavior
- **Login:** Works gracefully without `ERR_CONNECTION_RESET`. Returns standard response.
- **Auth/me:** Only unsets user when the backend replies `401` or `403`. 
- **MFA:** MFA flows remain stable.
- **Token persistence:** Uses `secureft_token` consistently in both login writer and interceptor reader.

## 7. CORS
- **Origin:** `['http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:5174', 'http://127.0.0.1:5174', 'http://localhost:5175', 'http://127.0.0.1:5175']`
- **Preflight:** Valid, credentialed wildcard-free origin match.
- **Result:** Successfully authorizes requests from Vite dev server.

## 8. Tests

| Test | Result |
|------|--------|
| `AUTH-LOCAL-01` (No Token) | PASS. No infinite "Authenticating..." state. |
| `AUTH-LOCAL-02` (POST login) | PASS. Calls `5001`. No `ERR_CONNECTION_RESET`. |
| `AUTH-LOCAL-03` (Valid credentials) | PASS. Success response returned. |
| `AUTH-LOCAL-04` (Invalid credentials) | PASS. Returns 4xx JSON, not Network Error. |
| `AUTH-LOCAL-05` (Valid session /auth/me) | PASS. Returns 200 JSON with user data. |
| `AUTH-LOCAL-06` (Missing token /auth/me) | PASS. Controlled 401 response, connection remains open. |
| `AUTH-LOCAL-07` (Refresh browser) | PASS. Session initializes seamlessly. |

## 9. Final Runtime Verification
- **Frontend** = PASS
- **Node** = PASS
- **MongoDB** = PASS
- **Login** = PASS
- **Auth/me** = PASS
- **Dashboard** = PASS
- **Key-status** = PASS
