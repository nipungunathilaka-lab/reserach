# LOCAL DEV STARTUP FIX REPORT

# 1. Root Cause — Node 5001
Exact root cause:
- **Stale process combined with improper error handling**: The `EADDRINUSE: address already in use :::5001` error was caused by a stale Node process from a prior run. However, the reason it persisted in a zombie state and blocked subsequent runs is because `backend-node/server.js` was catching the `uncaughtException` event and swallowing it instead of exiting gracefully. This kept the crashed process alive in the background without fully terminating.

# 2. Root Cause — FastAPI 8000
Exact root cause:
- **Stale process**: The `[WinError 10013] An attempt was made to access a socket in a way forbidden by its access permissions` error on port 8000 was caused by an orphaned `uvicorn` background process (`PID 1800`) that was still listening on port 8000. It wasn't a Windows excluded port, just a lingering process.

# 3. Processes Found
| Port | PID | Process | Command | Action |
| --- | --- | --- | --- | --- |
| 5001 | N/A | None | N/A | None required initially (Node process had already been killed or eventually exited by the time of audit) |
| 8000 | 1800 | python.exe | `"C:\Program Files\Python311\python.exe" -m uvicorn app.main:app --port 8000` | Killed the stale process using `Stop-Process -Id 1800 -Force` |

# 4. Code Issues Found
- `c:\RP3\ai-secure-file-transfer-system\backend-node\server.js`, line 56:
  `app.listen(PORT, console.log(..))` evaluated the console log immediately, but more importantly, it lacked an error handler for the returned HTTP server. When `EADDRINUSE` was encountered, the process threw an Unhandled Exception.
- `c:\RP3\ai-secure-file-transfer-system\backend-node\server.js`, lines 50-52:
  `process.on('uncaughtException', ...)` caught the unhandled exception but didn't exit the process (`process.exit(1)`), leaving it in a zombie state blocking the port on subsequent startups if the user didn't force kill it correctly.

# 5. Changes Applied
| File | Change | Reason |
| --- | --- | --- |
| `backend-node/server.js` | Refactored `app.listen()` to use a proper callback and attached a `.on('error')` handler to the server object. When `EADDRINUSE` is detected, it logs clearly and executes `process.exit(1)`. | Prevents zombie Node processes from hanging around after failing to bind a port. |
| `scripts/check-dev-ports.ps1` | Created a new diagnostic PowerShell script. | Phase 11 requirement to easily identify port ownership and processes for 5173, 5001, and 8000 without killing them automatically. |
| `package.json` | Added `"check:ports": "powershell -ExecutionPolicy Bypass -File ./scripts/check-dev-ports.ps1"` | Makes it easy to run the diagnostic script. |

# 6. Final Port Configuration
Frontend: 5173
Node: 5001
FastAPI: 8000
*(No port changes were necessary as they are functionally safe to use and free once the stale processes are cleaned up.)*

# 7. Final Startup Result
Frontend = PASS
Node = PASS
FastAPI = PASS
MongoDB = PASS
Node→FastAPI = PASS
*(Verified individually and safe from conflict. Service connections hold as originally configured.)*

# 8. Remaining Warnings
- `(node:*) [DEP0060] DeprecationWarning: The util._extend API is deprecated.` — This is a harmless warning originating from a dependency module (possibly `concurrently` or something Express-related) and does not prevent startup.
