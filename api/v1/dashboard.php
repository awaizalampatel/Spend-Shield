<?php
/**
 * GET /api/v1/dashboard.php
 *
 * Everything the executive dashboard needs, in one request: the four KPI tiles,
 * the exposure trend with its annotations, the severity composition, scan
 * coverage, and the top findings by money.
 *
 * One request rather than six, because the page is read as a single picture and
 * six requests means six different moments in time on one screen.
 */
require_once __DIR__ . '/_boot.php';

$pdo  = db();
$user = currentUser($pdo);
$tid  = (int) $user['tenant_id'];

// ---- KPI 1 & 2: exposure now, and its band
$now = $pdo->query(
    "SELECT COALESCE(SUM(ale_likely),0) total, COALESCE(SUM(ale_min),0) lo,
            COALESCE(SUM(ale_max),0) hi, COUNT(*) scored
       FROM risk_scores WHERE tenant_id = $tid AND is_current = 1"
)->fetch();

// 30 days ago: the most recent score for each finding that existed back then.
$then = $pdo->query(
    "SELECT COALESCE(SUM(ale_likely),0) FROM risk_scores rs
      WHERE rs.tenant_id = $tid
        AND rs.id IN (
            SELECT MAX(id) FROM risk_scores
             WHERE tenant_id = $tid AND computed_at <= NOW() - INTERVAL 30 DAY
             GROUP BY finding_id)"
)->fetchColumn();

$total = (float) $now['total'];
$prev  = (float) $then;

// ---- severity composition, from the live CVSS scores
$sev = $pdo->query(
    "SELECT CASE
              WHEN v.cvss_score >= 9.0 THEN 'critical'
              WHEN v.cvss_score >= 7.0 THEN 'high'
              WHEN v.cvss_score >= 4.0 THEN 'medium'
              ELSE 'low' END AS band,
            COUNT(*) n, COALESCE(SUM(rs.ale_likely),0) exposure
       FROM findings f
       JOIN vulnerabilities v ON v.id = f.vulnerability_id
  LEFT JOIN risk_scores rs    ON rs.finding_id = f.id AND rs.is_current = 1
      WHERE f.tenant_id = $tid AND f.status = 'open'
   GROUP BY band"
)->fetchAll();

$composition = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
$sevExposure = ['critical' => 0.0, 'high' => 0.0, 'medium' => 0.0, 'low' => 0.0];
foreach ($sev as $r) {
    $composition[$r['band']] = (int) $r['n'];
    $sevExposure[$r['band']] = (float) $r['exposure'];
}

// ---- KPI: exposure with no funded remediation
$unbudgeted = (float) $pdo->query(
    "SELECT COALESCE(SUM(rs.ale_likely),0)
       FROM risk_scores rs
       JOIN findings f ON f.id = rs.finding_id
      WHERE rs.tenant_id = $tid AND rs.is_current = 1
        AND NOT EXISTS (
            SELECT 1 FROM remediation_findings rf
              JOIN remediations r ON r.id = rf.remediation_id
             WHERE rf.finding_id = f.id AND r.status IN ('approved','in_progress'))"
)->fetchColumn();

// ---- scan coverage
$cov = $pdo->query(
    "SELECT COUNT(*) total,
            SUM(last_scan_at > NOW() - INTERVAL 7 DAY) recent,
            SUM(is_crown_jewel) crown
       FROM assets WHERE tenant_id = $tid AND decommissioned_at IS NULL"
)->fetch();

// ---- trend: daily exposure from the score history
$trend = $pdo->query(
    "SELECT DATE(computed_at) d, SUM(ale_likely) total
       FROM risk_scores rs
      WHERE rs.tenant_id = $tid
        AND rs.id IN (SELECT MAX(id) FROM risk_scores
                       WHERE tenant_id = $tid GROUP BY finding_id, DATE(computed_at))
   GROUP BY DATE(computed_at)
   ORDER BY d ASC LIMIT 90"
)->fetchAll();

// ---- annotations: what moved the line
$annotations = $pdo->query(
    "SELECT DATE(created_at) d, action, note, money_effect
       FROM audit_log
      WHERE tenant_id = $tid AND money_effect IS NOT NULL AND ABS(money_effect) > 0
   ORDER BY created_at DESC LIMIT 12"
)->fetchAll();

// ---- top findings by money
$top = $pdo->query(
    "SELECT f.id, a.hostname, a.is_crown_jewel,
            COALESCE(v.cve_id, v.local_key) AS ref, v.title, v.cvss_score, v.cvss_severity,
            v.kev_listed, v.kev_ransomware, ROUND(v.epss_score,4) AS epss,
            rs.ale_likely, rs.ale_min, rs.ale_max, rs.agent_key, rs.confidence
       FROM risk_scores rs
       JOIN findings f        ON f.id = rs.finding_id
       JOIN assets a          ON a.id = f.asset_id
       JOIN vulnerabilities v ON v.id = f.vulnerability_id
      WHERE rs.tenant_id = $tid AND rs.is_current = 1
   ORDER BY rs.ale_likely DESC LIMIT 8"
)->fetchAll();

// ---- the standing optimizer recommendation, if there is one
$run = $pdo->query(
    "SELECT id, budget_inr, allocated_inr, exposure_before, exposure_removed, created_at
       FROM optimizer_runs WHERE tenant_id = $tid ORDER BY created_at DESC LIMIT 1"
)->fetch();

$freshness = $pdo->query(
    "SELECT feed, MAX(ran_at) last_run, MAX(status) status FROM feed_runs GROUP BY feed"
)->fetchAll();

ok([
    'tenant' => ['slug' => $user['tenant_slug'], 'name' => $user['tenant_name']],
    'exposure' => [
        'total'  => money($total),
        'band'   => ['min' => money((float) $now['lo']), 'max' => money((float) $now['hi'])],
        'change_30d' => $prev > 0 ? round(($total - $prev) / $prev * 100, 1) : null,
        'previous'   => $prev > 0 ? money($prev) : null,
        'scored_findings' => (int) $now['scored'],
    ],
    'unbudgeted' => money($unbudgeted),
    'composition' => [
        'counts'   => $composition,
        'exposure' => array_map(static fn($v) => money((float) $v), $sevExposure),
        'total'    => array_sum($composition),
    ],
    'coverage' => [
        'assets'        => (int) $cov['total'],
        'scanned_7d'    => (int) $cov['recent'],
        'crown_jewels'  => (int) $cov['crown'],
        'percent'       => $cov['total'] > 0 ? round($cov['recent'] / $cov['total'] * 100) : 0,
    ],
    'trend' => array_map(static fn($r) => [
        'date'  => $r['d'],
        'value' => round((float) $r['total'], 2),
    ], $trend),
    'annotations' => array_map(static fn($r) => [
        'date'   => $r['d'],
        'label'  => $r['action'],
        'note'   => $r['note'],
        'effect' => money((float) $r['money_effect']),
    ], $annotations),
    'top_findings' => array_map(static fn($r) => [
        'id'        => (int) $r['id'],
        'asset'     => $r['hostname'],
        'crown'     => (bool) $r['is_crown_jewel'],
        'ref'       => $r['ref'],
        'title'     => $r['title'],
        'cvss'      => $r['cvss_score'] !== null ? (float) $r['cvss_score'] : null,
        'severity'  => strtolower((string) $r['cvss_severity']),
        'kev'       => (bool) $r['kev_listed'],
        'ransomware'=> (bool) $r['kev_ransomware'],
        'epss'      => $r['epss'] !== null ? (float) $r['epss'] : null,
        'agent'     => $r['agent_key'],
        'confidence'=> (float) $r['confidence'],
        'loss'      => money((float) $r['ale_likely']),
        'band'      => ['min' => money((float) $r['ale_min']), 'max' => money((float) $r['ale_max'])],
    ], $top),
    'recommendation' => $run ? [
        'run_id'    => (int) $run['id'],
        'budget'    => money((float) $run['budget_inr']),
        'allocated' => money((float) $run['allocated_inr']),
        'removed'   => money((float) $run['exposure_removed']),
        'percent'   => $run['exposure_before'] > 0
            ? round((float) $run['exposure_removed'] / (float) $run['exposure_before'] * 100, 1) : 0,
        'created_at'=> $run['created_at'],
    ] : null,
    'feeds' => array_map(static fn($r) => [
        'feed'     => $r['feed'],
        'last_run' => $r['last_run'],
        'status'   => $r['status'],
    ], $freshness),
]);
