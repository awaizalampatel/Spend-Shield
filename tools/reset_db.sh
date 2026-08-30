#!/usr/bin/env bash
# Rebuild the database from scratch with real feed data. ~5 minutes, mostly NVD's
# rate limit. Run from the project root.
set -e
PHP="${PHP:-php}"

"$PHP" tools/install.php --fresh
"$PHP" api/ingest/sync_feeds.php --kev
"$PHP" api/ingest/sync_feeds.php --epss
"$PHP" api/ingest/seed_estate.php --reset
"$PHP" api/ingest/sync_feeds.php --nvd --limit=45
echo "done"
