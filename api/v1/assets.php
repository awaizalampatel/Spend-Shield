<?php
/**
 * GET /api/v1/assets.php              the estate, priced
 * GET /api/v1/assets.php?id=12        one asset, with its controls and findings
 *
 * "Unscanned" is reported as exposure UNKNOWN, never as zero. A gap in coverage
 * that renders as a low number is the most dangerous thing a risk tool can do.
 */
require_once __DIR__ . '/_boot.php';

$pdo  = db();
$user = currentUser($pdo);
require_role($user, ['owner', 'analyst', 'viewer']);
$tid  = (int) $user['tenant_id'];
$id   = (int) ($_GET['id'] ?? 0);

// ------------------------------------------------------------------ one asset
if ($id > 0) {
    $q = $pdo->prepare("SELECT * FROM assets WHERE id = ? AND tenant_id = ?");
    $q->execute([$id, $tid]);
    $a = $q->fetch();
    if (!$a) {
        fail(404, 'That asset does not exist, or belongs to another organization.');
    }

    $c = $pdo->prepare(
        "SELECT c.control_key, c.name, c.vendor, c.claimed_effectiveness,
                c.observed_effectiveness, c.observation_count, c.miss_count, ac.status
           FROM asset_controls ac JOIN controls c ON c.id = ac.control_id
          WHERE ac.asset_id = ?"
    );
    $c->execute([$id]);

    $f = $pdo->prepare(
        "SELECT f.id, f.status, COALESCE(v.cve_id, v.local_key) ref, v.title,
                v.cvss_score, v.cvss_severity, v.kev_listed, ROUND(v.epss_score,4) epss,
                rs.ale_likely, f.first_seen_at
           FROM findings f
           JOIN vulnerabilities v ON v.id = f.vulnerability_id
      LEFT JOIN risk_scores rs    ON rs.finding_id = f.id AND rs.is_current = 1
          WHERE f.asset_id = ? AND f.status = 'open'
       ORDER BY rs.ale_likely DESC"
    );
    $f->execute([$id]);

    $h = $pdo->prepare(
        "SELECT DATE(computed_at) d, SUM(ale_likely) total
           FROM risk_scores WHERE finding_id IN (SELECT id FROM findings WHERE asset_id = ?)
       GROUP BY DATE(computed_at) ORDER BY d ASC LIMIT 90"
    );
    $h->execute([$id]);

    $total = (float) $pdo->query(
        "SELECT COALESCE(SUM(rs.ale_likely),0) FROM risk_scores rs
           JOIN findings f ON f.id = rs.finding_id
          WHERE rs.is_current = 1 AND f.asset_id = " . (int) $id
    )->fetchColumn();

    ok([
        'asset' => [
            'id' => (int) $a['id'], 'hostname' => $a['hostname'], 'ip' => $a['ip'],
            'class' => $a['asset_class'], 'os' => $a['os'],
            'business_unit' => $a['business_unit'], 'owner' => $a['owner_team'],
            'environment' => $a['environment'], 'criticality' => (float) $a['criticality'],
            'crown_jewel' => (bool) $a['is_crown_jewel'],
            'internet_facing' => (bool) $a['internet_facing'],
            'pii_records' => (int) $a['pii_records'],
            'revenue_per_hour' => $a['revenue_per_hour'] !== null ? (float) $a['revenue_per_hour'] : null,
            'source' => $a['source'], 'last_scan' => $a['last_scan_at'],
            'exposure' => money($total),
            'scan_stale' => $a['last_scan_at'] === null
                || strtotime((string) $a['last_scan_at']) < time() - 7 * 86400,
        ],
        'controls' => array_map(static fn($r) => [
            'key' => $r['control_key'], 'name' => $r['name'], 'vendor' => $r['vendor'],
            'status' => $r['status'],
            'claimed'  => (float) $r['claimed_effectiveness'],
            'observed' => $r['observed_effectiveness'] !== null ? (float) $r['observed_effectiveness'] : null,
            'observations' => (int) $r['observation_count'],
            'misses' => (int) $r['miss_count'],
        ], $c->fetchAll()),
        'findings' => array_map(static fn($r) => [
            'id' => (int) $r['id'], 'ref' => $r['ref'], 'title' => $r['title'],
            'cvss' => $r['cvss_score'] !== null ? (float) $r['cvss_score'] : null,
            'severity' => strtolower((string) $r['cvss_severity']),
            'kev' => (bool) $r['kev_listed'],
            'epss' => $r['epss'] !== null ? (float) $r['epss'] : null,
            'loss' => $r['ale_likely'] !== null ? money((float) $r['ale_likely']) : null,
            'age_days' => (int) floor((time() - strtotime((string) $r['first_seen_at'])) / 86400),
        ], $f->fetchAll()),
        'history' => array_map(static fn($r) => [
            'date' => $r['d'], 'value' => round((float) $r['total'], 2),
        ], $h->fetchAll()),
    ]);
}

// ------------------------------------------------------------------- the list
$rows = $pdo->query(
    "SELECT a.id, a.hostname, a.ip, a.asset_class, a.os, a.business_unit, a.owner_team,
            a.environment, a.criticality, a.is_crown_jewel, a.internet_facing,
            a.pii_records, a.last_scan_at,
            COUNT(DISTINCT f.id) AS open_findings,
            COALESCE(SUM(rs.ale_likely),0) AS exposure,
            SUM(v.cvss_score >= 9.0) AS critical, SUM(v.cvss_score >= 7.0 AND v.cvss_score < 9.0) AS high
       FROM assets a
  LEFT JOIN findings f        ON f.asset_id = a.id AND f.status = 'open'
  LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
  LEFT JOIN risk_scores rs    ON rs.finding_id = f.id AND rs.is_current = 1
      WHERE a.tenant_id = $tid AND a.decommissioned_at IS NULL
   GROUP BY a.id
   ORDER BY exposure DESC"
)->fetchAll();

$kpi = $pdo->query(
    "SELECT COUNT(*) total,
            SUM(is_crown_jewel) crown,
            SUM(internet_facing) internet,
            SUM(last_scan_at IS NULL OR last_scan_at < NOW() - INTERVAL 30 DAY) stale
       FROM assets WHERE tenant_id = $tid AND decommissioned_at IS NULL"
)->fetch();

$crownExposure = (float) $pdo->query(
    "SELECT COALESCE(SUM(rs.ale_likely),0) FROM risk_scores rs
       JOIN findings f ON f.id = rs.finding_id
       JOIN assets a   ON a.id = f.asset_id
      WHERE rs.tenant_id = $tid AND rs.is_current = 1 AND a.is_crown_jewel = 1"
)->fetchColumn();

ok([
    'summary' => [
        'assets'          => (int) $kpi['total'],
        'crown_jewels'    => (int) $kpi['crown'],
        'crown_exposure'  => money($crownExposure),
        'internet_facing' => (int) $kpi['internet'],
        'unscanned_30d'   => (int) $kpi['stale'],
        'unscanned_note'  => 'Exposure on these assets is unknown, not zero.',
    ],
    'assets' => array_map(static fn($r) => [
        'id' => (int) $r['id'], 'hostname' => $r['hostname'], 'ip' => $r['ip'],
        'class' => $r['asset_class'], 'os' => $r['os'],
        'business_unit' => $r['business_unit'], 'owner' => $r['owner_team'],
        'environment' => $r['environment'],
        'criticality' => (float) $r['criticality'],
        'crown_jewel' => (bool) $r['is_crown_jewel'],
        'internet_facing' => (bool) $r['internet_facing'],
        'pii_records' => (int) $r['pii_records'],
        'open_findings' => (int) $r['open_findings'],
        'critical' => (int) $r['critical'],
        'high' => (int) $r['high'],
        'exposure' => money((float) $r['exposure']),
        'last_scan' => $r['last_scan_at'],
        'scan_stale' => $r['last_scan_at'] === null
            || strtotime((string) $r['last_scan_at']) < time() - 7 * 86400,
    ], $rows),
]);
