<?php
/**
 * Database connection. Credentials come from api/config/secrets.php when it
 * exists (gitignored), otherwise from the XAMPP defaults below.
 */

if (is_file(__DIR__ . '/secrets.php')) {
    require_once __DIR__ . '/secrets.php';
}

defined('DB_HOST') || define('DB_HOST', '127.0.0.1');
defined('DB_PORT') || define('DB_PORT', '3306');
defined('DB_NAME') || define('DB_NAME', 'spendshield');
defined('DB_USER') || define('DB_USER', 'root');
defined('DB_PASS') || define('DB_PASS', '');

/**
 * @param bool $withDb false connects to the server without selecting a database
 *                     (needed by the installer, which has to CREATE it first).
 */
function db(bool $withDb = true): PDO
{
    static $conns = [];
    $k = $withDb ? 'main' : 'server';
    if (isset($conns[$k])) {
        return $conns[$k];
    }
    $dsn = 'mysql:host=' . DB_HOST . ';port=' . DB_PORT
         . ($withDb ? ';dbname=' . DB_NAME : '') . ';charset=utf8mb4';
    $conns[$k] = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
    return $conns[$k];
}
