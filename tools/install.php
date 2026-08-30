<?php
/**
 * Creates the database and applies api/schema.sql.
 *   php tools/install.php [--fresh]
 * --fresh drops the database first. Everything else is idempotent.
 */
require_once __DIR__ . '/../api/config/db.php';

$fresh = in_array('--fresh', $argv, true);
$pdo = db(false);

if ($fresh) {
    $pdo->exec('DROP DATABASE IF EXISTS `' . DB_NAME . '`');
    echo "dropped database " . DB_NAME . "\n";
}

$pdo->exec('CREATE DATABASE IF NOT EXISTS `' . DB_NAME . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
echo "database " . DB_NAME . " ready\n";

$sql = file_get_contents(__DIR__ . '/../api/schema.sql');
if ($sql === false) {
    fwrite(STDERR, "cannot read api/schema.sql\n");
    exit(1);
}

$pdo->exec('USE `' . DB_NAME . '`');
$pdo->exec($sql);

$tables = $pdo->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
echo count($tables) . " tables: " . implode(', ', $tables) . "\n";
