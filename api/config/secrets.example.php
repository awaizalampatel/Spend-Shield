<?php
/**
 * Copy this file to secrets.php and fill in real values.
 * secrets.php is gitignored and must never be committed.
 */

// --- database
define('DB_HOST', '127.0.0.1');
define('DB_PORT', '3306');
define('DB_NAME', 'spendshield');
define('DB_USER', 'root');
define('DB_PASS', '');

// --- OpenRouter — the answer/judge models for the agent layer (Phase 5).
// https://openrouter.ai/keys
define('OPENROUTER_API_KEY', '');

// --- Jina embeddings — powers agent dedup and the assessment reuse ladder.
// https://jina.ai/embeddings  (free tier is enough for a demo)
define('JINA_API_KEY', '');
