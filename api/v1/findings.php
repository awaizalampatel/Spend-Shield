<?php
/**
 * GET /api/v1/findings.php
 *   ?severity=critical,high & exposure=internet & asset=plant-jump-01
 *   &status=open & sort=loss|cvss|epss|age & limit=50 & offset=0 & q=text
 *
 * The risk register. Default sort is annualized loss, not CVSS — that default
 * is the product's whole thesis expressed as a table order.
 *
 * Executives deliberately cannot reach this: raw findings are an analyst's tool,
 * and the money views are theirs. See the role table in the interface book.
 */
require_once __DIR__ . '/_boot.php';

$pdo  = db();
$user = currentUser($pdo);
require_role($user, ['owner', 'analyst', 'viewer']);
$tid = (int) $user['tenant_id'];

$where  = ['f.tenant_id = :tid', 'a.decommissioned_at IS NULL'];
$params = [':tid' => $tid];

// ---- status
$status = (string) ($_GET['status'] ?? 'open');
if ($status !== 'all') {
    $allowed = ['open', 'accepted', 'remediated', 'closed'];
    if (!in_array($status, $allowed, true)) {
        fail(400, 'Unknown status filter.', ['allowed' => $allowed]);
    }
    $where[] = 'f.status = :status';
    $params[':status'] = $status;
}

// ---- severity, by CVSS band
if (!empty($_GET['severity'])) {
    $bands = array_filter(array_map('trim', explode(',', (string) $_GET['severity'])));
    $ranges = ['critical' => [9.0, 10.1], 'high' => [7.0, 9.0], 'medium' => [4.0, 7.0], 'low' => [0.0, 4.0]];
    $clauses = [];
    foreach ($bands as $i => $b) {
        if (!isset($ranges[$b])) {
            fail(400, 'Unknown severity band: ' . $b, ['allowed' => array_keys($ranges)]);
        }
        $clauses[] = "(v.cvss_score >= :s{$i}lo AND v.cvss_score < :s{$i}hi)";
        $params[":s{$i}lo"] = $ranges[$b][0];
        $params[":s{$i}hi"] = $ranges[$b][1];
    }
    if ($clauses) {
        $where[] = '(' . implode(' OR ', $clauses) . ')';
    }
}

// ---- exposure / asset / KEV
if (($_GET['exposure'] ?? '') === 'internet') { $where[] = 'a.internet_facing = 1'; }
if (($_GET['crown'] ?? '') === '1')           { $where[] = 'a.is_crown_jewel = 1'; }
if (($_GET['kev'] ?? '') === '1')             { $where[] = 'v.kev_listed = 1'; }
if (!empty($_GET['asset'])) {
    $where[] = 'a.hostname = :asset';
    $params[':asset'] = (string) $_GET['asset'];
}
if (!empty($_GET['agent'])) {
    $where[] = 'rs.agent_key = :agent';
    $params[':agent'] = (string) $_GET['agent'];
}
if (!empty($_GET['q'])) {
    $where[] = '(v.title LIKE :q OR v.cve_id LIKE :q OR a.hostname LIKE :q)';
    $params[':q'] = '%' . str_replace(['%', '_'], ['\%', '\_'], (string) $_GET['q']) . '%';
}

// ---- sort. Whitelisted: never interpolate user input into ORDER BY.
$sorts = [
    'loss' => 'rs.ale_likely DESC',
    'cvss' => 'v.cvss_score DESC',
    'epss' => 'v.epss_score DESC',
    'age'  => 'f.first_seen_at ASC',
];
$sortKey = (string) ($_GET['sort'] ?? 'loss');
$order   = $sorts[$sortKey] ?? $sorts['loss'];

$limit  = max(1, min(200, (int) ($_GET['limit'] ?? 50)));
$offset = max(0, (int) ($_GET['offset'] ?? 0));
$w = implode(' AND ', $where);

$countSql = "SELECT COUNT(*) n, COALESCE(SUM(rs.ale_likely),0) total
               FROM findings f
               JOIN assets a          ON a.id = f.asset_id
               JOIN vulnerabilities v ON v.id = f.vulnerability_id
          LEFT JOIN risk_scores rs    ON rs.finding_id = f.id AND rs.is_current = 1
              WHERE $w";
$c = $pdo->prepare($countSql);
$c->execute($params);
$summary = $c->fetch();

$sql = "SELECT f.id, f.status, f.port, f.service, f.first_seen_at, f.last_seen_at,
               a.hostname, a.asset_class, a.is_crown_jewel, a.internet_facing, a.owner_team,
               COALESCE(v.cve_id, v.local_key) AS ref, v.title, v.source,
               v.cvss_score, v.cvss_severity, v.kev_listed, v.kev_ransomware,
               ROUND(v.epss_score,4) AS epss,
               rs.ale_likely, rs.ale_min, rs.ale_max, rs.control_gap, rs.raw_risk,
               rs.threat_probability, rs.confidence, rs.agent_key
          FROM findings f
          JOIN assets a          ON a.id = f.asset_id
          JOIN vulnerabilities v ON v.id = f.vulnerability_id
     LEFT JOIN risk_scores rs    ON rs.finding_id = f.id AND rs.is_current = 1
         WHERE $w
      ORDER BY $order
         LIMIT $limit OFFSET $offset";
$q = $pdo->prepare($sql);
$q->execute($params);

$rows = [];
foreach ($q as $r) {
    $rows[] = [
        'id'        => (int) $r['id'],
        'status'    => $r['status'],
        'ref'       => $r['ref'],
        'title'     => $r['title'],
        'kind'      => $r['source'] === 'config' ? 'configuration' : 'vulnerability',
        'asset'     => [
            'hostname'        => $r['hostname'],
            'class'           => $r['asset_class'],
            'crown_jewel'     => (bool) $r['is_crown_jewel'],
            'internet_facing' => (bool) $r['internet_facing'],
            'owner'           => $r['owner_team'],
        ],
        'port'      => $r['port'] !== null ? (int) $r['port'] : null,
        'service'   => $r['service'],
        'cvss'      => $r['cvss_score'] !== null ? (float) $r['cvss_score'] : null,
        'severity'  => strtolower((string) $r['cvss_severity']),
        'kev'       => (bool) $r['kev_listed'],
        'ransomware'=> (bool) $r['kev_ransomware'],
        'epss'      => $r['epss'] !== null ? (float) $r['epss'] : null,
        'control_gap' => $r['control_gap'] !== null ? (float) $r['control_gap'] : null,
        'raw_risk'  => $r['raw_risk'] !== null ? (float) $r['raw_risk'] : null,
        'confidence'=> $r['confidence'] !== null ? (float) $r['confidence'] : null,
        'agent'     => $r['agent_key'],
        'loss'      => $r['ale_likely'] !== null ? money((float) $r['ale_likely']) : null,
        'band'      => $r['ale_min'] !== null
            ? ['min' => money((float) $r['ale_min']), 'max' => money((float) $r['ale_max'])]
            : null,
        'first_seen'=> $r['first_seen_at'],
        'age_days'  => (int) floor((time() - strtotime((string) $r['first_seen_at'])) / 86400),
    ];
}

ok([
    'findings' => $rows,
    'summary'  => [
        'matched'  => (int) $summary['n'],
        'exposure' => money((float) $summary['total']),
        'returned' => count($rows),
        'offset'   => $offset,
        'limit'    => $limit,
        'sort'     => $sortKey,
    ],
]);
