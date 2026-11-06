<?php
declare(strict_types=1);

/*
 * Campus Notes - index.php
 *
 * This file has two parts:
 *   1. shared code (settings, database, session, login, csrf, notes functions)
 *   2. the web page (login / register / note CRUD)
 * api.php loads this file too, so the web app and the API use the SAME security code.
 * (The lab zip is only 4 files, so the shared code lives here instead of a src/ folder.)
 */

// =====================================================================
// 1. SETTINGS + ERRORS  (issue 8)
// =====================================================================

// never show PHP/database errors to the browser, just log them
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

// DB login comes from environment variables only. Nothing is hardcoded and
// there is NO fallback to root (the starter used root with an empty password).
function config(): array
{
    return [
        'db_host' => getenv('LAB_DB_HOST') ?: '127.0.0.1',
        'db_name' => getenv('LAB_DB_NAME') ?: 'notes_lab',
        'db_user' => getenv('LAB_DB_USER') ?: '',
        'db_pass' => getenv('LAB_DB_PASSWORD') ?: '',
        // origins allowed to call the API (issue 11)
        'allowed_origins' => array_filter(array_map(
            'trim',
            explode(',', getenv('LAB_ALLOWED_ORIGINS') ?: 'http://127.0.0.1:8000,http://localhost:8000')
        )),
        'idle_seconds' => 1800,   // 30 min
        'min_password' => 10,
    ];
}

// Generic error page. Only the exception class/code/line is logged, not the message,
// because a PDO connection error message can contain the host and username.
function fail(Throwable $e, bool $json): void
{
    error_log(sprintf('[campus-notes] %s (code %s) at %s:%d',
        get_class($e), (string) $e->getCode(), basename($e->getFile()), $e->getLine()));
    if (!headers_sent()) {
        http_response_code(500);
        header($json ? 'Content-Type: application/json; charset=utf-8' : 'Content-Type: text/plain; charset=utf-8');
    }
    echo $json ? json_encode(['error' => 'Internal server error']) : 'Something went wrong. Please try again later.';
    exit;
}

// =====================================================================
// 2. SMALL HELPERS
// =====================================================================

// escape everything that goes into HTML (issue 4)
function e($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $path): void
{
    header('Location: ' . $path, true, 303);
    exit;
}

// one-time message kept in the session (the starter used ?message= in the URL, which was XSS)
function flash(?string $message = null): ?string
{
    if ($message !== null) {
        $_SESSION['flash'] = $message;
        return null;
    }
    $msg = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return $msg;
}

function json_out(int $status, array $data): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

// only accept plain strings from POST (so title[]=x does not slip through)
function post_str(string $key): ?string
{
    $v = $_POST[$key] ?? null;
    return is_string($v) ? $v : null;
}

// "5" or 5 -> 5, anything else -> null
function pos_int($v): ?int
{
    if (is_int($v)) {
        return $v > 0 ? $v : null;
    }
    if (is_string($v) && preg_match('/^[1-9][0-9]{0,9}$/', $v) === 1) {
        return (int) $v;
    }
    return null;
}

// checks title + body, returns [title, body, error]. Limits match the schema (title is VARCHAR(120)).
function check_note($title, $body): array
{
    if (!is_string($title) || !is_string($body)) {
        return [null, null, 'Title and body must be text.'];
    }
    $title = trim($title);
    $body = trim($body);
    if ($title === '' || $body === '') {
        return [null, null, 'Title and body are required.'];
    }
    if (!mb_check_encoding($title . $body, 'UTF-8')) {
        return [null, null, 'Invalid text encoding.'];
    }
    if (mb_strlen($title, 'UTF-8') > 120) {
        return [null, null, 'Title must be 120 characters or fewer.'];
    }
    if (mb_strlen($body, 'UTF-8') > 10000) {
        return [null, null, 'Body must be 10,000 characters or fewer.'];
    }
    return [$title, $body, null];
}

// =====================================================================
// 3. DATABASE  (issues 1 and 8)
// =====================================================================

function db(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $c = config();
    if ($c['db_user'] === '') {
        throw new RuntimeException('LAB_DB_USER is not set');   // fail closed, no root fallback
    }
    $dsn = 'mysql:host=' . $c['db_host'] . ';dbname=' . $c['db_name'] . ';charset=utf8mb4';
    $pdo = new PDO($dsn, $c['db_user'], $c['db_pass'], [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,   // real prepared statements
        PDO::MYSQL_ATTR_FOUND_ROWS   => true,    // rowCount = rows matched, so "no change" is not "not found"
    ]);
    return $pdo;
}

// =====================================================================
// 4. SESSION + HEADERS  (issue 6)
// =====================================================================

// random value for the inline <style> tag so the CSP can allow our CSS and nothing else
function csp_nonce(): string
{
    static $nonce = null;
    if ($nonce === null) {
        $nonce = bin2hex(random_bytes(16));
    }
    return $nonce;
}

function send_headers(bool $json): void
{
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    if ($json) {
        header('Content-Type: application/json; charset=utf-8');
        header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
    } else {
        header("Content-Security-Policy: default-src 'none'; style-src 'nonce-" . csp_nonce()
            . "'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    }
}

function start_session(): void
{
    $c = config();
    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

    ini_set('session.use_strict_mode', '1');    // ignore session IDs the browser made up
    ini_set('session.use_only_cookies', '1');   // never take the ID from the URL
    ini_set('session.use_trans_sid', '0');
    session_name('CAMPUSNOTESSID');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => $https,    // on when served over HTTPS (cannot test this on local HTTP)
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();

    // idle timeout
    $now = time();
    if (isset($_SESSION['last_seen']) && ($now - (int) $_SESSION['last_seen']) > $c['idle_seconds']) {
        end_session();
        session_start();
    }
    $_SESSION['last_seen'] = $now;
}

// fully log out: clear data, expire the cookie, delete the server-side session
function end_session(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $p['path'],
            'domain'   => $p['domain'],
            'secure'   => $p['secure'],
            'httponly' => $p['httponly'],
            'samesite' => $p['samesite'] ?: 'Lax',
        ]);
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
}

// call this first in every entry point (index.php and api.php)
function setup(bool $json): void
{
    set_exception_handler(static function (Throwable $e) use ($json) {
        fail($e, $json);
    });
    set_error_handler(static function (int $no, string $str, string $file, int $line): bool {
        if (!(error_reporting() & $no)) {
            return false;
        }
        throw new ErrorException($str, 0, $no, $file, $line);
    });
    send_headers($json);
    start_session();
}

// =====================================================================
// 5. CSRF  (issues 5 and 11)
// =====================================================================

function csrf_token(): string
{
    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function csrf_ok(?string $sent): bool
{
    return is_string($sent)
        && isset($_SESSION['csrf'])
        && is_string($_SESSION['csrf'])
        && hash_equals($_SESSION['csrf'], $sent);
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

// =====================================================================
// 6. USERS: register / login / who am I  (issues 2, 6, 7)
// =====================================================================

// register. Returns an error message or null if it worked.
// The role is NOT read from the form, every new account is 'student' (issue 7).
function register_user(string $email, string $password): ?string
{
    $c = config();
    $email = trim(mb_strtolower($email));
    if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        return 'Enter a valid email address.';
    }
    if (strlen($password) < $c['min_password']) {
        return 'Password must be at least ' . $c['min_password'] . ' characters.';
    }
    if (strlen($password) > 72) {   // bcrypt only uses the first 72 bytes
        return 'Password must be 72 bytes or fewer.';
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);   // salted bcrypt, not MD5
    try {
        $stmt = db()->prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'student')");
        $stmt->execute([$email, $hash]);
    } catch (PDOException $ex) {
        if ($ex->getCode() === '23000') {   // duplicate email
            return 'Registration failed. Try a different email or sign in.';
        }
        throw $ex;
    }
    return null;
}

// login. true if ok. New session ID after login so session fixation does not work.
function login_user(string $email, string $password): bool
{
    // hash of a random string, so an unknown email takes about as long as a wrong password
    $dummy = '$2y$10$pgCkANymAZVMsHIfF/0hl.oioKQs5bcso1qHzGxCnO8RTQWlq6biO';

    $email = trim(mb_strtolower($email));
    $stmt = db()->prepare('SELECT id, password_hash FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    $ok = password_verify($password, $user['password_hash'] ?? $dummy);
    if (!$user || !$ok) {
        return false;
    }

    if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
        $upd = db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $upd->execute([password_hash($password, PASSWORD_DEFAULT), $user['id']]);
    }

    session_regenerate_id(true);
    $_SESSION['user_id'] = (int) $user['id'];
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
    $_SESSION['last_seen'] = time();
    return true;
}

// the logged in user, or null. Always looked up from the session, never from the request.
function current_user(): ?array
{
    $id = $_SESSION['user_id'] ?? null;
    if (!is_int($id)) {
        return null;
    }
    $stmt = db()->prepare('SELECT id, email, role FROM users WHERE id = ?');
    $stmt->execute([$id]);
    $user = $stmt->fetch();
    if (!$user) {   // account was deleted
        end_session();
        return null;
    }
    return $user;
}

// =====================================================================
// 7. NOTES  (issues 1, 3, 9)
// Every query uses ? placeholders AND has "user_id = ?" in the WHERE,
// where the user id always comes from the session.
// =====================================================================

function notes_for_user(int $userId): array
{
    $stmt = db()->prepare('SELECT id, user_id, title, body FROM notes WHERE user_id = ? ORDER BY id DESC');
    $stmt->execute([$userId]);
    return $stmt->fetchAll();
}

function note_for_user(int $noteId, int $userId): ?array
{
    $stmt = db()->prepare('SELECT id, user_id, title, body FROM notes WHERE id = ? AND user_id = ?');
    $stmt->execute([$noteId, $userId]);
    return $stmt->fetch() ?: null;
}

function note_create(int $userId, string $title, string $body): void
{
    $stmt = db()->prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
    $stmt->execute([$userId, $title, $body]);
}

// true if the note belongs to this user (even if nothing changed)
function note_update(int $noteId, int $userId, string $title, string $body): bool
{
    $stmt = db()->prepare('UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?');
    $stmt->execute([$title, $body, $noteId, $userId]);
    return $stmt->rowCount() > 0;
}

function note_delete(int $noteId, int $userId): bool
{
    $stmt = db()->prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
    $stmt->execute([$noteId, $userId]);
    return $stmt->rowCount() > 0;
}

// =====================================================================
// 8. THE WEB PAGE
// =====================================================================

function run_web(): void
{
    setup(false);
    $user = current_user();
    $method = $_SERVER['REQUEST_METHOD'];

    if ($method === 'POST') {
        // every state-changing action is POST + CSRF token (issue 5)
        if (!csrf_ok(post_str('csrf_token'))) {
            http_response_code(403);
            echo 'Invalid or missing security token. Go back, reload the page and try again.';
            exit;
        }
        $action = post_str('action') ?? '';

        // not logged in: only register and login are allowed
        if ($user === null) {
            if ($action === 'register') {
                $error = register_user(post_str('email') ?? '', post_str('password') ?? '');
                flash($error ?? 'Account created. You can sign in now.');
                redirect('/');
            }
            if ($action === 'login') {
                if (login_user(post_str('email') ?? '', post_str('password') ?? '')) {
                    redirect('/');
                }
                flash('Invalid email or password.');   // same message for wrong email or wrong password
                redirect('/');
            }
            http_response_code(401);
            echo 'Please sign in first.';
            exit;
        }

        // logged in. The owner is ALWAYS $uid from the session, user_id/role in the form are ignored.
        $uid = (int) $user['id'];

        if ($action === 'logout') {
            end_session();
            session_start();   // brand new anonymous session just for the flash message
            flash('You have been logged out.');
            redirect('/');
        }

        if ($action === 'save') {
            [$title, $body, $err] = check_note($_POST['title'] ?? null, $_POST['body'] ?? null);
            if ($err !== null) {
                flash($err);
                redirect('/');
            }
            note_create($uid, $title, $body);
            flash('Note saved.');
            redirect('/');
        }

        if ($action === 'update') {
            $id = pos_int($_POST['id'] ?? null);
            [$title, $body, $err] = check_note($_POST['title'] ?? null, $_POST['body'] ?? null);
            if ($id === null || $err !== null) {
                flash($err ?? 'Invalid note.');
                redirect('/');
            }
            // someone else's note looks the same as a note that does not exist
            flash(note_update($id, $uid, $title, $body) ? 'Note updated.' : 'Note not found.');
            redirect('/');
        }

        if ($action === 'delete') {
            $id = pos_int($_POST['id'] ?? null);
            flash($id !== null && note_delete($id, $uid) ? 'Note deleted.' : 'Note not found.');
            redirect('/');
        }

        http_response_code(400);
        echo 'Unknown action.';
        exit;
    }

    if ($method !== 'GET' && $method !== 'HEAD') {
        header('Allow: GET, HEAD, POST');
        http_response_code(405);
        echo 'Method not allowed.';
        exit;
    }

    // GET only reads, it never changes anything
    $message = flash();
    $notes = [];
    $editing = null;
    if ($user !== null) {
        $notes = notes_for_user((int) $user['id']);
        $editId = pos_int($_GET['edit'] ?? null);
        if ($editId !== null) {
            $editing = note_for_user($editId, (int) $user['id']);   // null if it is not theirs
        }
    }
    show_page($user, $message, $notes, $editing);
}

// the HTML. Every value goes through e().
function show_page(?array $user, ?string $message, array $notes, ?array $editing): void
{
    ?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Campus Notes</title>
<style nonce="<?= e(csp_nonce()) ?>">
body{font:16px sans-serif;max-width:750px;margin:2rem auto}
label{display:block;margin:.5rem 0}
article{border:1px solid #aaa;padding:1rem;margin:1rem 0}
article p{white-space:pre-wrap}
form.inline{display:inline}
</style>
</head>
<body>
<h1>Campus Notes</h1>
<?php if ($message): ?><p role="status"><?= e($message) ?></p><?php endif; ?>

<?php if ($user === null): ?>
<h2>Register or sign in</h2>
<form method="post" action="/">
  <?= csrf_field() ?>
  <label>Email <input name="email" type="email" maxlength="254" required autocomplete="username"></label>
  <label>Password <input name="password" type="password" minlength="10" maxlength="72" required autocomplete="current-password"></label>
  <button name="action" value="register">Register</button>
  <button name="action" value="login">Sign in</button>
</form>
<?php else: ?>
<form method="post" action="/" class="inline">
  <?= csrf_field() ?>
  <span>Signed in as <?= e($user['email']) ?> (<?= e($user['role']) ?>)</span>
  <button name="action" value="logout">Log out</button>
</form>

<?php if ($editing): ?>
<h2>Edit note</h2>
<form method="post" action="/">
  <?= csrf_field() ?>
  <input type="hidden" name="id" value="<?= e($editing['id']) ?>">
  <label>Title <input name="title" value="<?= e($editing['title']) ?>" maxlength="120" required></label>
  <label>Body <textarea name="body" maxlength="10000" required><?= e($editing['body']) ?></textarea></label>
  <button name="action" value="update">Update</button>
  <a href="/">Cancel</a>
</form>
<?php endif; ?>

<h2>Create a note</h2>
<form method="post" action="/">
  <?= csrf_field() ?>
  <label>Title <input name="title" maxlength="120" required></label>
  <label>Body <textarea name="body" maxlength="10000" required></textarea></label>
  <button name="action" value="save">Save</button>
</form>

<h2>Your notes</h2>
<?php foreach ($notes as $note): ?>
<article>
  <h3><?= e($note['title']) ?></h3>
  <p><?= e($note['body']) ?></p>
  <a href="/?edit=<?= e($note['id']) ?>">Edit</a>
  <form method="post" action="/" class="inline">
    <?= csrf_field() ?>
    <input type="hidden" name="id" value="<?= e($note['id']) ?>">
    <button name="action" value="delete">Delete</button>
  </form>
</article>
<?php endforeach; ?>
<?php if (!$notes): ?><p>No notes yet.</p><?php endif; ?>
<?php endif; ?>
</body>
</html>
<?php
}

// run the page, unless api.php is the one loading this file
if (!defined('CAMPUS_NOTES_API')) {
    run_web();
}
