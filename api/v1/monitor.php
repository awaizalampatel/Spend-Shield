<?php
/**
 * GET /api/v1/monitor.php
 *
 * What changed, and what it cost. Every entry names the money it moved — an
 * alert with no financial consequence is not an alert, it is noise.
 *
 * Feed health reports CONSEQUENCE, not status: "214 cloud assets not refreshed
 * for 2 days" rather than a red dot. A status without a consequence gets ignored.
 */
require_once __DIR__ . '/_boot.php';

$pdo  = db();
$user = currentUser($pdo);
$tid  = (int) $user['tenant_id'];

$feeds = $pdo->query(
    "SELECT f.feed, f.status, f.records, f.changed, f.ran_at, f.message
       FROM feed_runs f
       JOIN (SELECT feed, MAX(ran_at) m FROM feed_runs GROUP BY feed) x
         ON x.feed = f.feed AND x.m = f.ran_at"
)->fetchAll();

$expected = ['kev' => 24, 'epss' => 24, 'nvd' => 168];   // hours between runs
$feedOut  = [];
foreach ($feeds as $f) {
    $ageH = (time() - strtotime((string) $f['ran_at'])) / 3600;
    $stale = $ageH > ($expected[$f['feed']] ?? 24);
    $feedOut[] = [
        'feed'      => $f['feed'],
        'status'    => $stale ? 'stale' : $f['status'],
        'last_run'  => $f['ran_at'],
        'age_hours' => round($ageH, 1),
        'records'   => (int) $f['records'],
        'changed'   => (int) $f['changed'],
        'consequence' => $stale
            ? ucfirst($f['feed']) . ' data has not refreshed for ' . round($ageH)
              . ' hours — scores built on it are shown as stale, not current.'
            : null,
    ];
}

// Activity: the audit log, which already records what each change moved.
$since = (string) ($_GET['since'] ?? '7 DAY');
$window = in_array($since, ['24 HOUR', '7 DAY', '30 DAY'], true) ? $since : '7 DAY';

$activity = $pdo->query(
    "SELECT created_at, actor, action, entity_type, entity_ref,
            before_value, after_value, money_effect, note
       FROM audit_log
      WHERE tenant_id = $tid AND created_at > NOW() - INTERVAL $window
   ORDER BY created_at DESC LIMIT 60"
)->fetchAll();

// New arrivals worth waking someone for.
$newFindings = $pdo->query(
    "SELECT COUNT(*) n, COALESCE(SUM(rs.ale_likely),0) exposure
       FROM findings f
  LEFT JOIN risk_scores rs ON rs.finding_id = f.id AND rs.is_current = 1
      WHERE f.tenant_id = $tid AND f.status = 'open'
        AND f.first_seen_at > NOW() - INTERVAL 1 DAY"
)->fetch();

$ransomware = $pdo->query(
    "SELECT COUNT(*) FROM findings f
       JOIN vulnerabilities v ON v.id = f.vulnerability_id
       JOIN assets a ON a.id = f.asset_id
      WHERE f.tenant_id = $tid AND f.status = 'open'
        AND v.kev_ransomware = 1 AND a.is_crown_jewel = 1"
)->fetchColumn();

$moved = (float) $pdo->query(
    "SELECT COALESCE(SUM(money_effect),0) FROM audit_log
      WHERE tenant_id = $tid AND created_at > NOW() - INTERVAL 1 DAY"
)->fetchColumn();

$alerts = [];
if ((int) $ransomware > 0) {
    $alerts[] = [
        'level'   => 'critical',
        'title'   => $ransomware . ' ransomware-linked vulnerabilities on crown-jewel systems',
        'detail'  => 'CISA links these CVEs to active ransomware campaigns, and they sit on systems '
                   . 'the business cannot run without.',
    ];
}
if ((int) $newFindings['n'] > 0) {
    $alerts[] = [
        'level'  => 'info',
        'title'  => $newFindings['n'] . ' new findings in the last 24 hours',
        'detail' => 'Carrying ' . inr((float) $newFindings['exposure']) . ' of exposure.',
    ];
}

ok([
    'feeds' => $feedOut,
    'headline' => [
        'exposure_moved_24h' => money($moved),
        'new_findings_24h'   => (int) $newFindings['n'],
        'alerts'             => count($alerts),
    ],
    'alerts' => $alerts,
    'activity' => array_map(static fn($r) => [
        'at'     => $r['created_at'],
        'actor'  => $r['actor'],
        'action' => $r['action'],
        'entity' => trim(((string) $r['entity_type']) . ' ' . ((string) $r['entity_ref'])),
        'change' => $r['before_value'] !== null
            ? ($r['before_value'] . ' → ' . $r['after_value'])
            : null,
        'effect' => $r['money_effect'] !== null ? money((float) $r['money_effect']) : null,
        'note'   => $r['note'],
    ], $activity),
]);
