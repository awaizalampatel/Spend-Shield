<?php
/**
 * GET /api/v1/finding.php?id=123
 *
 * One finding, and — the important part — the arithmetic behind its money
 * figure: every factor, its value, where it came from, and what it did to the
 * result. If this endpoint cannot produce that table, the UI must not display
 * the number as money.
 */
require_once __DIR__ . '/_boot.php';
require_once __DIR__ . '/../risk/Portfolio.php';

$pdo  = db();
$user = currentUser($pdo);
require_role($user, ['owner', 'analyst', 'viewer']);
$tid  = (int) $user['tenant_id'];
$id   = (int) ($_GET['id'] ?? 0);
if ($id <= 0) {
    fail(400, 'Which finding?');
}

$q = $pdo->prepare(
    "SELECT f.*, a.hostname, a.ip, a.asset_class, a.os, a.business_unit, a.owner_team,
            a.criticality, a.is_crown_jewel, a.internet_facing, a.environment,
            a.revenue_per_hour, a.pii_records, a.last_scan_at,
            v.id AS vuln_id, v.cve_id, v.local_key, v.source, v.title, v.description, v.cwe,
            v.cvss_score, v.cvss_version, v.cvss_severity, v.cvss_vector,
            v.epss_score, v.epss_percentile, v.epss_asof,
            v.kev_listed, v.kev_date_added, v.kev_ransomware, v.published_at, v.last_synced_at,
            v.impact_c, v.impact_i, v.impact_a
       FROM findings f
       JOIN assets a          ON a.id = f.asset_id
       JOIN vulnerabilities v ON v.id = f.vulnerability_id
      WHERE f.id = ? AND f.tenant_id = ?"
);
$q->execute([$id, $tid]);
$f = $q->fetch();
if (!$f) {
    fail(404, 'That finding does not exist, or belongs to another organization.');
}

$rs = $pdo->prepare("SELECT * FROM risk_scores WHERE finding_id = ? AND is_current = 1 LIMIT 1");
$rs->execute([$id]);
$score = $rs->fetch();

// Re-derive the provenance sentences from the same engine that produced the
// stored score, so the explanation can never drift from the number.
$controls = [];
$cq = $pdo->prepare(
    "SELECT c.control_key, c.name, c.vendor, c.claimed_effectiveness, c.observed_effectiveness
       FROM asset_controls ac JOIN controls c ON c.id = ac.control_id
      WHERE ac.asset_id = ? AND ac.status <> 'absent'"
);
$cq->execute([(int) $f['asset_id']]);
$controlRows = $cq->fetchAll();
foreach ($controlRows as $c) {
    $observed = $c['observed_effectiveness'] !== null;
    $controls[$c['control_key']] = [
        'effectiveness' => (float) ($observed ? $c['observed_effectiveness'] : $c['claimed_effectiveness']),
        'observed'      => $observed,
    ];
}
$live = RiskEngine::score($f, $f, $controls);

$factors = [
    ['factor' => 'Severity',           'value' => (float) $live['severity_factor'],
     'source' => $live['why']['severity']],
    ['factor' => 'Threat probability', 'value' => (float) $live['threat_probability'],
     'source' => $live['why']['threat']],
    ['factor' => 'Asset criticality',  'value' => (float) $live['asset_criticality'],
     'source' => $live['why']['criticality']],
    ['factor' => 'Exposure',           'value' => (float) $live['exposure_factor'],
     'source' => $live['why']['exposure']],
    ['factor' => 'Control gap',        'value' => (float) $live['control_gap'],
     'source' => $live['why']['controls']],
];

// What the cheapest fix would be, and what it buys.
$fix = $pdo->prepare(
    "SELECT r.id, r.name, r.cost_inr, r.effort_days, r.status
       FROM remediation_findings rf JOIN remediations r ON r.id = rf.remediation_id
      WHERE rf.finding_id = ? AND r.status <> 'done'
   ORDER BY r.cost_inr ASC LIMIT 3"
);
$fix->execute([$id]);
$fixes = $fix->fetchAll();

$cheapest = null;
if ($fixes) {
    // Value the cheapest option against the live estate, the same way the
    // optimizer would — no cached figure, no estimate.
    $p = Portfolio::load($pdo, (string) $user['tenant_slug']);
    $before = $p->exposure();
    $after  = $p->exposure(['remove_findings' => [$id]]);
    $cheapest = [
        'id'      => (int) $fixes[0]['id'],
        'name'    => $fixes[0]['name'],
        'cost'    => money((float) $fixes[0]['cost_inr']),
        'effort_days' => (int) $fixes[0]['effort_days'],
        'removes' => money(max(0.0, $before - $after)),
    ];
}

// Sibling findings on the same asset, so the reader can see what else is wrong.
$sib = $pdo->prepare(
    "SELECT f.id, COALESCE(v.cve_id, v.local_key) ref, v.title, v.cvss_score, rs.ale_likely
       FROM findings f
       JOIN vulnerabilities v ON v.id = f.vulnerability_id
  LEFT JOIN risk_scores rs    ON rs.finding_id = f.id AND rs.is_current = 1
      WHERE f.asset_id = ? AND f.id <> ? AND f.status = 'open'
   ORDER BY rs.ale_likely DESC LIMIT 8"
);
$sib->execute([(int) $f['asset_id'], $id]);

$evidence = [];
if ($f['cve_id']) {
    if ($f['cvss_score'] !== null) {
        $evidence[] = ['source' => 'NVD', 'detail' => 'CVSS ' . $f['cvss_version'] . ' base '
            . $f['cvss_score'] . ' · ' . $f['cvss_vector'], 'retrieved' => $f['last_synced_at']];
    }
    if ($f['epss_score'] !== null) {
        $evidence[] = ['source' => 'FIRST EPSS', 'detail' => 'Exploitation probability '
            . rtrim(rtrim(number_format((float) $f['epss_score'], 5, '.', ''), '0'), '.')
            . ' over 30 days · percentile ' . round((float) $f['epss_percentile'] * 100, 1) . '%',
            'retrieved' => $f['epss_asof']];
    }
    if ($f['kev_listed']) {
        $evidence[] = ['source' => 'CISA KEV', 'detail' => 'Listed as actively exploited since '
            . $f['kev_date_added'] . ($f['kev_ransomware'] ? ' · linked to ransomware campaigns' : ''),
            'retrieved' => $f['last_synced_at']];
    }
}
$evidence[] = ['source' => ucfirst((string) $f['detector']), 'detail' => (string) $f['evidence'],
               'retrieved' => $f['last_seen_at']];

ok([
    'finding' => [
        'id'     => (int) $f['id'],
        'ref'    => $f['cve_id'] ?: $f['local_key'],
        'title'  => $f['title'],
        'description' => $f['description'],
        'kind'   => $f['source'] === 'config' ? 'configuration' : 'vulnerability',
        'cwe'    => $f['cwe'],
        'status' => $f['status'],
        'port'   => $f['port'] !== null ? (int) $f['port'] : null,
        'service'=> $f['service'],
        'first_seen' => $f['first_seen_at'],
        'last_seen'  => $f['last_seen_at'],
        'detector'   => $f['detector'],
        'impacts' => [
            'confidentiality' => (bool) $f['impact_c'],
            'integrity'       => (bool) $f['impact_i'],
            'availability'    => (bool) $f['impact_a'],
        ],
    ],
    'asset' => [
        'id' => (int) $f['asset_id'], 'hostname' => $f['hostname'], 'ip' => $f['ip'],
        'class' => $f['asset_class'], 'os' => $f['os'],
        'business_unit' => $f['business_unit'], 'owner' => $f['owner_team'],
        'criticality' => (float) $f['criticality'],
        'crown_jewel' => (bool) $f['is_crown_jewel'],
        'internet_facing' => (bool) $f['internet_facing'],
        'environment' => $f['environment'],
        'pii_records' => (int) $f['pii_records'],
        'last_scan'   => $f['last_scan_at'],
    ],
    'score' => $score ? [
        'raw_risk'   => (float) $score['raw_risk'],
        'confidence' => (float) $score['confidence'],
        'loss'       => money((float) $score['ale_likely']),
        'band'       => ['min' => money((float) $score['ale_min']), 'max' => money((float) $score['ale_max'])],
        'sle'        => money((float) $score['sle']),
        'agent'      => $score['agent_key'],
        'reuse'      => $score['reuse_type'],
        'cost_usd'   => (float) $score['cost_usd'],
        'computed_at'=> $score['computed_at'],
        'loss_model_version' => (int) $score['loss_model_version'],
    ] : null,
    // The table that has to defend the number.
    'factors' => $factors,
    'formula' => 'severity × threat probability × asset criticality × exposure × control gap',
    'controls' => array_map(static fn($c) => [
        'key'      => $c['control_key'],
        'name'     => $c['name'],
        'vendor'   => $c['vendor'],
        'claimed'  => (float) $c['claimed_effectiveness'],
        'observed' => $c['observed_effectiveness'] !== null ? (float) $c['observed_effectiveness'] : null,
        'applied'  => str_contains($live['why']['controls'], (string) $c['control_key']),
    ], $controlRows),
    'evidence' => $evidence,
    'fixes'    => array_map(static fn($r) => [
        'id' => (int) $r['id'], 'name' => $r['name'],
        'cost' => money((float) $r['cost_inr']),
        'effort_days' => (int) $r['effort_days'], 'status' => $r['status'],
    ], $fixes),
    'cheapest_fix' => $cheapest,
    'siblings' => array_map(static fn($r) => [
        'id' => (int) $r['id'], 'ref' => $r['ref'], 'title' => $r['title'],
        'cvss' => $r['cvss_score'] !== null ? (float) $r['cvss_score'] : null,
        'loss' => $r['ale_likely'] !== null ? money((float) $r['ale_likely']) : null,
    ], $sib->fetchAll()),
]);
