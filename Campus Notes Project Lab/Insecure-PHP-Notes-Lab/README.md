# Campus Notes (repaired)

School security lab: a small PHP + MySQL notes app that started out intentionally vulnerable. This is my fixed version.

**Safety:** run it only on your own machine with fake data and a throwaway database. Never put it on the internet. `php -S` and plain HTTP are for local development only.

## Files (only 4)

| File | What it does |
|---|---|
| `index.php` | The web app (login, register, logout, notes CRUD) **and** the shared code: database, session, CSRF, login, note queries |
| `api.php` | The JSON API. It loads `index.php` so it uses the same security functions |
| `schema.sql` | Creates the `notes_lab` database, the tables and 2 fake users |
| `README.md` | This file |

No Composer packages, so no `vendor/` or lock file. Tested with PHP 8.3 and MariaDB 10.11.

## Setup

1. Install PHP 8 with `pdo_mysql` and `mbstring` (check with `php -m`) and a local MySQL/MariaDB server.
2. Import the schema into a fresh server (read it first): `mysql -u root -p < schema.sql`
3. Make a limited database user (not root):
   ```sql
   CREATE USER 'notes_app'@'localhost' IDENTIFIED BY 'your_local_password';
   GRANT SELECT, INSERT, UPDATE, DELETE ON notes_lab.* TO 'notes_app'@'localhost';
   ```
4. Set the login in your shell (don't commit it). The app will not start without `LAB_DB_USER`.
   - Bash: `export LAB_DB_USER=notes_app LAB_DB_PASSWORD=your_local_password`
   - PowerShell: `$env:LAB_DB_USER = 'notes_app'` and `$env:LAB_DB_PASSWORD = 'your_local_password'`
5. In this folder run `php -S 127.0.0.1:8000` and open http://127.0.0.1:8000 (Ctrl+C to stop).

Fake accounts (public, throwaway, never reuse):
- `alex@example.test` / `LabOnly-Alex-123`
- `sam@example.test` / `LabOnly-Sam-456`

The passwords in `schema.sql` are now bcrypt hashes. Old MD5 hashes do not work with `password_verify()`, so if you imported the old schema, drop `notes_lab` and import this `schema.sql` again. Use two different browser profiles to be Alex and Sam at the same time.

## API

| Request | What happens |
|---|---|
| `GET /api.php` | your notes |
| `GET /api.php?user_id=1` | your notes, but the id must be your own id (otherwise 403) |
| `GET /api.php?csrf=1` | gives `{"csrf_token": "..."}` for the next POST |
| `POST /api.php` | update a note. JSON `{"id":1,"title":"...","body":"..."}` with `Content-Type: application/json` and an `X-CSRF-Token` header |

Status codes: 401 not logged in, 403 bad origin / bad CSRF / someone else's id, 404 note missing or not yours, 400 bad JSON, 413 too big, 415 wrong content type, 422 bad fields, 405 wrong method.

## What I fixed

1. **SQL injection** - every query uses PDO prepared statements (`?`) with real (non-emulated) prepares.
2. **Passwords** - `password_hash()` / `password_verify()` (bcrypt) instead of MD5. Min 10 characters.
3. **Private notes** - every note query also has `AND user_id = ?` using the id from the session.
4. **XSS** - everything printed in HTML goes through `e()` (`htmlspecialchars`). The `?message=` in the URL is gone (flash messages are in the session). Added a CSP header.
5. **CSRF** - logout, save, update and delete are POST only and need a CSRF token. GET never changes anything.
6. **Sessions** - new session ID after login, strict mode, HttpOnly + SameSite cookie, logout destroys the session and expires the cookie, 30 min idle timeout.
7. **Role / owner from the client** - the register form has no role (always `student`) and the note owner always comes from the session.
8. **Errors / DB credentials** - errors are logged not shown, user sees a generic message. DB login comes from environment variables, no root fallback.
9. **API auth** - no session = 401. The user comes from the session, `?user_id=` has to match, updates only work on your own notes.
10. **API validation** - checks content type, size (64 KB), JSON must be an object, id must be a positive integer, title/body checked. Bad JSON gives a clean 400.
11. **API cross-origin** - removed the "reflect any Origin + allow credentials" header. No CORS headers at all, untrusted `Origin` gets 403, and POST also needs JSON content type + CSRF header.

## Limits / not done

- Local HTTP only. For real use you need HTTPS, HSTS and the `Secure` cookie flag (the code turns it on automatically over HTTPS, but I could not test that locally).
- No login rate limiting or lockout, no password reset, no email verification. Register/login messages can still hint whether an email exists.
- The `role` column is saved but not used (no admin features).
- `php -S` serves the whole folder, so `schema.sql` and `README.md` can be downloaded. That's fine here (fake data only), but in a real deployment only the PHP files should be web-accessible.
- The 30 minute idle timeout was not tested.
- If you run on a different host or port, set `LAB_ALLOWED_ORIGINS` (comma separated, e.g. `http://127.0.0.1:9000`).
