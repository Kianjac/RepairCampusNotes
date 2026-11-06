<?php
declare(strict_types=1);

/*
 * Campus Notes - api.php (JSON API)
 *
 *   GET  /api.php             -> my notes
 *   GET  /api.php?user_id=N   -> my notes (N must be my own id, otherwise 403)
 *   GET  /api.php?csrf=1      -> {"csrf_token": "..."} to use on the next POST
 *   POST /api.php             -> update one of my notes, JSON: {"id":1,"title":"..","body":".."}
 *                                needs Content-Type: application/json and X-CSRF-Token header
 *
 * It loads index.php for the shared functions. The constant below tells index.php
 * not to show the web page.
 */
define('CAMPUS_NOTES_API', true);
require __DIR__ . '/index.php';

$config = config();
setup(true);

// ---- cross-origin protection (issue 11) ----
// The starter sent "Access-Control-Allow-Origin: <whatever origin asked>" together with
// "Allow-Credentials: true", so any website could use a logged-in user's cookie.
// Now: no CORS headers at all (same-origin only) and untrusted origins are rejected.
$origin = $_SERVER['HTTP_ORIGIN'] ?? null;
if ($origin !== null && !in_array($origin, $config['allowed_origins'], true)) {
    json_out(403, ['error' => 'Origin not allowed']);
}
if (($_SERVER['HTTP_SEC_FETCH_SITE'] ?? 'same-origin') === 'cross-site') {
    json_out(403, ['error' => 'Cross-site requests are not allowed']);
}

$method = $_SERVER['REQUEST_METHOD'];
if ($method === 'OPTIONS') {
    http_response_code(204);   // preflight is never approved (no CORS headers), so browsers block it
    exit;
}
if ($method !== 'GET' && $method !== 'POST') {
    header('Allow: GET, POST');
    json_out(405, ['error' => 'Method not supported']);
}

// ---- authentication (issue 9): who you are comes from the session only ----
$user = current_user();
if ($user === null) {
    json_out(401, ['error' => 'Authentication required']);
}
$uid = (int) $user['id'];

// ---- GET ----
if ($method === 'GET') {
    if (isset($_GET['csrf'])) {
        json_out(200, ['csrf_token' => csrf_token()]);
    }
    // user_id is optional, and if it is there it has to be mine (issue 3 / 9)
    if (array_key_exists('user_id', $_GET)) {
        $asked = pos_int($_GET['user_id']);
        if ($asked === null) {
            json_out(400, ['error' => 'user_id must be a positive integer']);
        }
        if ($asked !== $uid) {
            json_out(403, ['error' => 'Forbidden']);
        }
    }
    json_out(200, notes_for_user($uid));
}

// ---- POST: update a note ----
// JSON content type: a plain HTML form on another site cannot send this without a
// CORS preflight, and we never approve one. The CSRF token below is the second layer.
$type = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
if ($type !== 'application/json') {
    json_out(415, ['error' => 'Content-Type must be application/json']);
}
if (!csrf_ok($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null)) {
    json_out(403, ['error' => 'Missing or invalid CSRF token']);
}

// read at most 64 KB
$max = 65536;
$raw = file_get_contents('php://input', false, null, 0, $max + 1);
if ($raw === false || $raw === '') {
    json_out(400, ['error' => 'Request body is required']);
}
if (strlen($raw) > $max) {
    json_out(413, ['error' => 'Request body too large']);
}

// malformed JSON -> clean 400, not a PHP error (issue 10)
try {
    $data = json_decode($raw, false, 8, JSON_THROW_ON_ERROR);
} catch (JsonException $ex) {
    json_out(400, ['error' => 'Malformed JSON']);
}
if (!($data instanceof stdClass)) {   // has to be a JSON object, not a list / number / string
    json_out(400, ['error' => 'JSON body must be an object']);
}

$id = pos_int($data->id ?? null);
if ($id === null) {
    json_out(422, ['error' => 'id must be a positive integer']);
}
[$title, $body, $err] = check_note($data->title ?? null, $data->body ?? null);
if ($err !== null) {
    json_out(422, ['error' => $err]);
}
// a "user_id" or "role" in the JSON is never read (issue 7)

if (!note_update($id, $uid, $title, $body)) {
    json_out(404, ['error' => 'Note not found']);   // same answer for "missing" and "not yours"
}
json_out(200, ['updated' => 1]);
