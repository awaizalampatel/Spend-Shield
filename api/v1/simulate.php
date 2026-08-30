<?php
/**
 * POST /api/v1/simulate.php
 *   {
 *     "controls":   {"mfa": 0.90, "segmentation": 0.80},   // raise a control everywhere
 *     "deploy":     {"mfa": ["all"]},                      // or roll it out to assets
 *     "fix":        [12, 44],                              // findings that would be fixed
 *     "assumptions":{"revenue_per_hour": 1500000}          // test a belief, not an action
 *   }
 *
 * Nothing is written. The what-if simulator computes against the real finding
 * set through the same Portfolio the dashboard uses, so the two can never
 * disagree — a client-side approximation would eventually contradict the number
 * on the previous screen.
 *
 * Actions and assumptions are answered separately in the response, because
 * "risk fell because we would deploy MFA" and "risk fell because we decided
 * downtime costs less" are not the same claim.
 */
require_once __DIR__ . '/_boot.php';
require_once __DIR__ . '/../risk/Portfolio.php';

$pdo  = db();
$user = currentUser($pdo);
require_role($user, ['owner', 'executive', 'analyst']);

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fail(405, 'Use POST to run a scenario.');
}

$in = body();
$p  = Portfolio::load($pdo, (string) $user['tenant_slug']);
$baseline = $p->exposure();

// ---- assumptions change the loss model, not the estate
$assumed = [];
foreach (['revenue_per_hour', 'median_recovery_hours', 'cost_per_record',
          'ransom_recovery_cost', 'reputational_cost'] as $k) {
    if (isset($in['assumptions'][$k]) && is_numeric($in['assumptions'][$k])) {
        $v = (float) $in['assumptions'][$k];
        if ($v < 0) {
            fail(400, "An assumption cannot be negative: $k");
        }
        $assumed[$k] = $v;
        $p->model[$k] = $v;
    }
}

// ---- actions change the estate
$what = ['remove_findings' => [], 'control_effectiveness' => [], 'add_control_to' => []];

foreach ((array) ($in['fix'] ?? []) as $fid) {
    $fid = (int) $fid;
    if (isset($p->findings[$fid])) {
        $what['remove_findings'][] = $fid;
    }
}
foreach ((array) ($in['controls'] ?? []) as $key => $eff) {
    if (!is_numeric($eff)) { continue; }
    $eff = (float) $eff;
    if ($eff < 0 || $eff > 1) {
        fail(400, "Control effectiveness must be between 0 and 1: $key");
    }
    $what['control_effectiveness'][(string) $key] = $eff;
}
foreach ((array) ($in['deploy'] ?? []) as $key => $targets) {
    $ids = [];
    foreach ((array) $targets as $t) {
        if ($t === 'all') {
            $ids = array_keys($p->assets);
            break;
        }
        $ids[] = (int) $t;
    }
    $what['add_control_to'][(string) $key] = array_values(array_intersect($ids, array_keys($p->assets)));
}

// Baseline under the NEW assumptions but the OLD estate — this is how much of
// the movement is a changed belief rather than a changed system.
$assumptionOnly = $p->exposure();
$after = $p->evaluate($what);

$byAsset = [];
foreach ($after['per_asset'] as $aid => $v) {
    $was = 0.0;
    $byAsset[] = [
        'asset' => $p->assets[$aid]['hostname'],
        'exposure' => money((float) $v),
    ];
}
usort($byAsset, static fn($a, $b) => $b['exposure']['value'] <=> $a['exposure']['value']);

ok([
    'baseline'  => money($baseline),
    'result'    => money($after['total']),
    'removed'   => money(max(0.0, $baseline - $after['total'])),
    'percent'   => $baseline > 0 ? round(max(0.0, $baseline - $after['total']) / $baseline * 100, 1) : 0.0,
    'attribution' => [
        'from_assumptions' => money($baseline - $assumptionOnly),
        'from_actions'     => money($assumptionOnly - $after['total']),
        'note' => 'Movement from assumptions is a change of belief, not a reduction in risk.',
    ],
    'applied' => [
        'fixed_findings' => count($what['remove_findings']),
        'controls'       => $what['control_effectiveness'],
        'deployed_to'    => array_map('count', $what['add_control_to']),
        'assumptions'    => $assumed,
    ],
    'by_asset' => array_slice($byAsset, 0, 10),
    'saved'    => false,
]);
