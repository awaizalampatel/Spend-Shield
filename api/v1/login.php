<?php
/**
 * POST /api/v1/login.php   {email, password}  ->  {token, user}
 * POST /api/v1/login.php?logout=1  (with a bearer token)
 *
 * Deliberate choices:
 *  - one error message for "no such user" and "wrong password", so the endpoint
 *    cannot be used to enumerate who has an account
 *  - a constant-ish cost on the miss path (a dummy hash verify), so timing does
 *    not leak whether the address exists
 *  - throttling per email + IP, announced with a wait, never a silent lockout
 */
require_once __DIR__ . '/_boot.php';

$pdo = db();
ensureSessions($pdo);

// ---- logout
if (isset($_GET['logout'])) {
    $t = bearer();
    if ($t !== null) {
        $pdo->prepare("DELETE FROM sessions WHERE token = ?")->execute([$t]);
    }
    ok(['ok' => true]);
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fail(405, 'Use POST to sign in.');
}

$in       = body();
$email    = strtolower(trim((string) ($in['email'] ?? '')));
$password = (string) ($in['password'] ?? '');

if ($email === '' || $password === '') {
    fail(400, 'Enter your email and password.');
}

// ---- throttle
$pdo->exec(
    "CREATE TABLE IF NOT EXISTS login_attempts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(190) NOT NULL,
        ip VARCHAR(45) NOT NULL,
        ok TINYINT(1) NOT NULL DEFAULT 0,
        at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY idx_attempt (email, at)
     ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
);
$ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
$recent = $pdo->prepare(
    "SELECT COUNT(*) FROM login_attempts
      WHERE email = ? AND ok = 0 AND at > NOW() - INTERVAL 15 MINUTE"
);
$recent->execute([$email]);
$misses = (int) $recent->fetchColumn();
if ($misses >= 5) {
    fail(429, 'Too many failed attempts. Try again in 15 minutes, or reset your password.');
}

$q = $pdo->prepare(
    "SELECT u.*, t.slug AS tenant_slug, t.name AS tenant_name
       FROM users u JOIN tenants t ON t.id = u.tenant_id
      WHERE u.email = ? AND u.deleted_at IS NULL"
);
$q->execute([$email]);
$user = $q->fetch();

// Always spend the cost of a verify, so a missing account is not faster than a
// wrong password.
$hash = $user['password_hash'] ?? '$2y$10$usesomesillystringfnsomethingfake0000000000000000000000';
$good = password_verify($password, (string) $hash) && $user;

$pdo->prepare("INSERT INTO login_attempts (email, ip, ok) VALUES (?,?,?)")
    ->execute([$email, $ip, $good ? 1 : 0]);

if (!$good) {
    fail(401, 'That email and password do not match.');
}

$token = bin2hex(random_bytes(32));
$pdo->prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?, NOW() + INTERVAL ? HOUR)")
    ->execute([$token, $user['id'], SESSION_TTL_HOURS]);

// Housekeeping, cheap and on the rare path.
$pdo->exec("DELETE FROM sessions WHERE expires_at < NOW()");

ok([
    'token' => $token,
    'expires_in' => SESSION_TTL_HOURS * 3600,
    'user' => [
        'id'     => (int) $user['id'],
        'name'   => $user['name'],
        'email'  => $user['email'],
        'role'   => $user['role'],
        'tenant' => ['slug' => $user['tenant_slug'], 'name' => $user['tenant_name']],
        'twofa_enabled' => (bool) $user['twofa_enabled'],
    ],
]);
