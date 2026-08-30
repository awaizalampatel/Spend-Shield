<?php
/**
 * Shared bootstrap for every /api/v1 endpoint: JSON output, error handling,
 * and authentication.
 *
 * Auth model: a bearer token issued by login.php, stored server-side in
 * `sessions`, checked on every request. Tokens are random 32-byte values, so
 * there is nothing in them to forge, and revoking one is a DELETE.
 *
 * There is NO dev bypass. A security product whose API answers unauthenticated
 * requests "because it's only localhost" is the product arguing against itself,
 * and a bypass added for convenience is exactly the thing that ships by accident.
 */
declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';

const SESSION_TTL_HOURS = 12;

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

// The Vite dev server runs on another port, so it needs an explicit origin.
// Only known development origins are allowed, never a wildcard with credentials.
$allowedOrigins = ['http://localhost:5173', 'http://127.0.0.1:5173'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
}
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

function fail(int $code, string $message, array $extra = []): never
{
    http_response_code($code);
    echo json_encode(['error' => $message] + $extra, JSON_UNESCAPED_UNICODE);
    exit;
}

function ok(array $payload): never
{
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
    exit;
}

/** Read a JSON body, or the form body, whichever the caller sent. */
function body(): array
{
    $raw = file_get_contents('php://input') ?: '';
    if ($raw !== '') {
        $j = json_decode($raw, true);
        if (is_array($j)) {
            return $j;
        }
    }
    return $_POST;
}

function ensureSessions(PDO $pdo): void
{
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS sessions (
            token       CHAR(64) NOT NULL PRIMARY KEY,
            user_id     INT NOT NULL,
            created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at  DATETIME NOT NULL,
            last_seen_at TIMESTAMP NULL,
            KEY idx_sessions_user (user_id)
         ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    );
}

/** The bearer token on this request, if any. */
function bearer(): ?string
{
    $h = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if ($h === '' && function_exists('apache_request_headers')) {
        foreach (apache_request_headers() as $k => $v) {
            if (strcasecmp($k, 'Authorization') === 0) { $h = $v; break; }
        }
    }
    if (preg_match('/^Bearer\s+([A-Za-z0-9]{32,64})$/', trim((string) $h), $m)) {
        return $m[1];
    }
    return null;
}

/**
 * Resolve the caller. Returns the user row joined to their tenant, or 401s.
 * Every endpoint calls this before touching data — there is no path to a row
 * that does not pass through here.
 */
function currentUser(PDO $pdo): array
{
    ensureSessions($pdo);
    $token = bearer();
    if ($token === null) {
        fail(401, 'Sign in to continue.');
    }
    $q = $pdo->prepare(
        "SELECT u.id, u.tenant_id, u.email, u.name, u.role, u.scope_json,
                t.slug AS tenant_slug, t.name AS tenant_name, s.expires_at
           FROM sessions s
           JOIN users u   ON u.id = s.user_id AND u.deleted_at IS NULL
           JOIN tenants t ON t.id = u.tenant_id
          WHERE s.token = ? AND s.expires_at > NOW()"
    );
    $q->execute([$token]);
    $u = $q->fetch();
    if (!$u) {
        fail(401, 'Your session has expired. Sign in again.');
    }
    $pdo->prepare("UPDATE sessions SET last_seen_at = NOW() WHERE token = ?")->execute([$token]);
    $pdo->prepare("UPDATE users SET last_active_at = NOW() WHERE id = ?")->execute([$u['id']]);
    return $u;
}

/**
 * Role gate. Executives deliberately cannot reach raw findings, and viewers
 * cannot change anything — see the role table in the interface book.
 */
function require_role(array $user, array $roles): void
{
    if (!in_array($user['role'], $roles, true)) {
        fail(403, 'Your role does not have access to this.', ['role' => $user['role']]);
    }
}

/** Format helper shared by every endpoint that returns money. */
function money(float $x): array
{
    return ['value' => round($x, 2), 'display' => inr($x)];
}

function inr(float $x): string
{
    if ($x >= 10000000) { return '₹' . number_format($x / 10000000, 2) . ' Cr'; }
    if ($x >= 100000)   { return '₹' . number_format($x / 100000, 2) . ' L'; }
    return '₹' . number_format($x, 0);
}

set_exception_handler(static function (Throwable $e): void {
    error_log('[api] ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());

    // A database that is not running is an OPERATIONAL state, not a bug, and it
    // deserves its own answer. 503 is the honest code, and naming the dependency
    // turns a mystery into something the reader can act on. It leaks nothing an
    // attacker could not learn by watching the service fail anyway.
    if ($e instanceof PDOException || str_contains($e->getMessage(), 'SQLSTATE')) {
        fail(503, 'The database is not reachable. If you are running this locally, '
                . 'start MySQL from the XAMPP control panel and try again.');
    }

    // Everything else stays generic on purpose — a stack trace in an API response
    // is a free map of the backend for anyone probing it.
    fail(500, 'Something went wrong on our side. The error has been logged.');
});
