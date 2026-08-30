<?php
/**
 * Real threat-intelligence sync. Three public sources, no keys required:
 *
 *   --kev    CISA Known Exploited Vulnerabilities catalog  (is it being exploited?)
 *   --epss   FIRST EPSS                                    (probability of exploitation, 30d)
 *   --nvd    NVD CVE API                                   (CVSS base score + vector)
 *
 * Usage:
 *   php api/ingest/sync_feeds.php --kev --epss
 *   php api/ingest/sync_feeds.php --nvd --limit=40
 *   php api/ingest/sync_feeds.php --all
 *
 * KEV brings the catalog in. EPSS and NVD enrich rows already present, cheapest
 * first: EPSS takes 100 CVEs per request, NVD takes one and is rate limited, so
 * NVD runs last and only for rows that still lack a score.
 */
require_once __DIR__ . '/../config/db.php';

const KEV_URL  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
const NVD_URL  = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const UA       = 'SpendShield/1.0 (SIH26105 risk quantification; +http://localhost/spendshield)';

/** One HTTP GET. Returns decoded JSON or null. */
function http_json(string $url, int $timeout = 60): ?array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_USERAGENT      => UA,
        CURLOPT_HTTPHEADER     => ['Accept: application/json'],
    ]);
    $body = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    if ($body === false || $code !== 200) {
        fwrite(STDERR, "  HTTP $code $err — $url\n");
        return null;
    }
    $j = json_decode($body, true);
    return is_array($j) ? $j : null;
}

function log_run(PDO $pdo, string $feed, string $status, int $records, int $changed, int $ms, ?string $msg = null): void
{
    $pdo->prepare("INSERT INTO feed_runs (feed, status, records, changed, duration_ms, message)
                   VALUES (?,?,?,?,?,?)")
        ->execute([$feed, $status, $records, $changed, $ms, $msg]);
}

// ------------------------------------------------------------------ KEV
function sync_kev(PDO $pdo): void
{
    echo "KEV: downloading CISA catalog…\n";
    $t0 = microtime(true);
    $data = http_json(KEV_URL, 90);
    if (!$data || empty($data['vulnerabilities'])) {
        log_run($pdo, 'kev', 'failed', 0, 0, (int) ((microtime(true) - $t0) * 1000), 'download failed');
        echo "KEV: FAILED\n";
        return;
    }
    $rows = $data['vulnerabilities'];
    echo "KEV: catalog " . ($data['catalogVersion'] ?? '?') . " — " . count($rows) . " entries\n";

    $ins = $pdo->prepare(
        "INSERT INTO vulnerabilities
            (cve_id, source, title, description, cvss_version, kev_listed, kev_date_added,
             kev_ransomware, last_synced_at)
         VALUES (?, 'nvd', ?, ?, NULL, 1, ?, ?, NOW())
         ON DUPLICATE KEY UPDATE
            title           = VALUES(title),
            description     = VALUES(description),
            kev_listed      = 1,
            kev_date_added  = VALUES(kev_date_added),
            kev_ransomware  = VALUES(kev_ransomware),
            last_synced_at  = NOW()"
    );

    $n = 0;
    $pdo->beginTransaction();
    foreach ($rows as $v) {
        $cve = trim((string) ($v['cveID'] ?? ''));
        if ($cve === '') continue;
        $title = trim(((string) ($v['vendorProject'] ?? '')) . ' ' . ((string) ($v['product'] ?? ''))
               . ' — ' . ((string) ($v['vulnerabilityName'] ?? $cve)));
        $ins->execute([
            $cve,
            mb_substr($title, 0, 255),
            (string) ($v['shortDescription'] ?? ''),
            (string) ($v['dateAdded'] ?? null) ?: null,
            (strtolower((string) ($v['knownRansomwareCampaignUse'] ?? '')) === 'known') ? 1 : 0,
        ]);
        $n++;
    }
    $pdo->commit();
    $ms = (int) ((microtime(true) - $t0) * 1000);
    log_run($pdo, 'kev', 'ok', count($rows), $n, $ms);
    echo "KEV: $n rows upserted in {$ms}ms\n";
}

// ----------------------------------------------------------------- EPSS
function sync_epss(PDO $pdo, bool $onlyMissing = false): void
{
    $t0 = microtime(true);
    $sql = "SELECT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL";
    if ($onlyMissing) {
        $sql .= " AND epss_score IS NULL";
    }
    $cves = $pdo->query($sql)->fetchAll(PDO::FETCH_COLUMN);
    if (!$cves) {
        echo "EPSS: nothing to fetch\n";
        return;
    }
    echo "EPSS: " . count($cves) . " CVEs, 100 per request…\n";

    $upd = $pdo->prepare("UPDATE vulnerabilities
                          SET epss_score = ?, epss_percentile = ?, epss_asof = ?
                          WHERE cve_id = ?");
    $done = 0; $hits = 0; $batches = 0;
    foreach (array_chunk($cves, 100) as $chunk) {
        $url = EPSS_URL . '?limit=100&cve=' . urlencode(implode(',', $chunk));
        $res = http_json($url, 45);
        $batches++;
        if ($res && !empty($res['data'])) {
            $pdo->beginTransaction();
            foreach ($res['data'] as $r) {
                $upd->execute([$r['epss'], $r['percentile'], $r['date'], $r['cve']]);
                $hits++;
            }
            $pdo->commit();
        }
        $done += count($chunk);
        if ($batches % 5 === 0) {
            echo "  … $done/" . count($cves) . "\n";
        }
        usleep(250000); // be polite to a free public API
    }
    $ms = (int) ((microtime(true) - $t0) * 1000);
    log_run($pdo, 'epss', 'ok', $done, $hits, $ms);
    echo "EPSS: $hits scores written in {$ms}ms\n";
}

// ------------------------------------------------------------------ NVD
function sync_nvd(PDO $pdo, int $limit): void
{
    $t0 = microtime(true);
    // Only rows we actually use: anything with a finding, plus anything still
    // missing a CVSS score. NVD allows one CVE per call and rate limits hard,
    // so this deliberately never walks the whole catalog.
    $cves = $pdo->query(
        "SELECT v.cve_id
           FROM vulnerabilities v
           LEFT JOIN findings f ON f.vulnerability_id = v.id
          WHERE v.cve_id IS NOT NULL AND v.cvss_score IS NULL
          GROUP BY v.id
          ORDER BY (COUNT(f.id) > 0) DESC, v.kev_date_added DESC
          LIMIT " . (int) $limit
    )->fetchAll(PDO::FETCH_COLUMN);

    if (!$cves) {
        echo "NVD: every tracked CVE already has a CVSS score\n";
        return;
    }
    echo "NVD: " . count($cves) . " CVEs, ~6s apart (public rate limit)…\n";

    $upd = $pdo->prepare(
        "UPDATE vulnerabilities
            SET cvss_version = ?, cvss_score = ?, cvss_severity = ?, cvss_vector = ?,
                cwe = COALESCE(?, cwe), published_at = COALESCE(?, published_at),
                description = CASE WHEN description IS NULL OR description = '' THEN ? ELSE description END,
                last_synced_at = NOW()
          WHERE cve_id = ?"
    );

    $ok = 0;
    foreach ($cves as $i => $cve) {
        $res = http_json(NVD_URL . '?cveId=' . urlencode($cve), 40);
        $c = $res['vulnerabilities'][0]['cve'] ?? null;
        if ($c) {
            // Prefer v3.1, then v4.0, then v3.0, then v2 — whatever NVD actually has.
            $m = $c['metrics']['cvssMetricV31'][0]['cvssData']
                ?? $c['metrics']['cvssMetricV40'][0]['cvssData']
                ?? $c['metrics']['cvssMetricV30'][0]['cvssData']
                ?? $c['metrics']['cvssMetricV2'][0]['cvssData']
                ?? null;
            $sev = $m['baseSeverity']
                ?? $c['metrics']['cvssMetricV2'][0]['baseSeverity']
                ?? null;
            $desc = '';
            foreach (($c['descriptions'] ?? []) as $d) {
                if (($d['lang'] ?? '') === 'en') { $desc = $d['value']; break; }
            }
            $cwe = $c['weaknesses'][0]['description'][0]['value'] ?? null;
            if ($m) {
                $upd->execute([
                    (string) ($m['version'] ?? '3.1'),
                    $m['baseScore'] ?? null,
                    $sev,
                    $m['vectorString'] ?? null,
                    (is_string($cwe) && str_starts_with($cwe, 'CWE-')) ? $cwe : null,
                    isset($c['published']) ? str_replace('T', ' ', substr($c['published'], 0, 19)) : null,
                    $desc,
                    $cve,
                ]);
                $ok++;
            }
        }
        if ($i < count($cves) - 1) {
            sleep(6); // 5 requests / 30s without an API key
        }
    }
    $ms = (int) ((microtime(true) - $t0) * 1000);
    log_run($pdo, 'nvd', 'ok', count($cves), $ok, $ms);
    echo "NVD: $ok scores written in " . round($ms / 1000) . "s\n";
}

// ----------------------------------------------------------------- main
$pdo  = db();
$args = $argv;
$all  = in_array('--all', $args, true);
$limit = 40;
foreach ($args as $a) {
    if (str_starts_with($a, '--limit=')) {
        $limit = max(1, (int) substr($a, 8));
    }
}

if ($all || in_array('--kev', $args, true))  { sync_kev($pdo); }
if ($all || in_array('--epss', $args, true)) { sync_epss($pdo, in_array('--missing', $args, true)); }
if ($all || in_array('--nvd', $args, true))  { sync_nvd($pdo, $limit); }

if (!$all && count(array_intersect($args, ['--kev', '--epss', '--nvd'])) === 0) {
    echo "usage: php api/ingest/sync_feeds.php [--kev] [--epss] [--nvd] [--all] [--limit=N] [--missing]\n";
}
