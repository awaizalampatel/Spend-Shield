<?php
/**
 * GET  /api/v1/optimizer.php?budget=1800000[&curve=1]
 * POST /api/v1/optimizer.php   {budget, save:true}   -> also stores the run
 *
 * The answer to "so what do I do?". Returns the chosen plan, the options that
 * lost and why, and — with curve=1 — what another rupee would buy.
 *
 * Rejected options are part of the response on purpose. An optimizer that shows
 * only its picks is a black box; showing the near-misses is what makes the pick
 * believable.
 */
require_once __DIR__ . '/_boot.php';
require_once __DIR__ . '/../risk/Portfolio.php';
require_once __DIR__ . '/../risk/Optimizer.php';
require_once __DIR__ . '/../risk/Remediations.php';

$pdo  = db();
$user = currentUser($pdo);
require_role($user, ['owner', 'executive', 'analyst', 'viewer']);

$isPost = ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST';
$in     = $isPost ? body() : $_GET;

$budget = (float) ($in['budget'] ?? 1800000);
if ($budget < 0 || $budget > 10000000000) {
    fail(400, 'Enter a budget between ₹0 and ₹1,000 Cr.');
}

$p       = Portfolio::load($pdo, (string) $user['tenant_slug']);
$options = Remediations::catalog($pdo, $p->tenantId);
if (!$options) {
    ok(['baseline' => money($p->exposure()), 'selected' => [], 'rejected' => [],
        'message' => 'No remediation options have been added yet.']);
}

// The curve is several full solves, so it is opt-in rather than always-on.
if (!empty($in['curve'])) {
    $max = max(1, (int) round(array_sum(array_column($options, 'cost'))));
    $points = [];
    for ($i = 0; $i <= 10; $i++) {
        $points[] = round($max * $i / 10);
    }
    $curve = Optimizer::curve($p, $options, $points);
    ok([
        'baseline' => money($p->exposure()),
        'curve' => array_map(static fn($c) => [
            'budget'    => money((float) $c['budget']),
            'removed'   => money((float) $c['removed']),
            'allocated' => money((float) $c['allocated']),
            'fixes'     => (int) $c['count'],
        ], $curve),
    ]);
}

$r = Optimizer::solve($p, $options, $budget);

// Attach what each option actually covers, so the UI can say "14 findings".
$meta = [];
foreach ($options as $o) {
    $meta[$o['id']] = $o['meta'];
}
$decorate = static function (array $row) use ($meta): array {
    $m = $meta[$row['id']] ?? [];
    return [
        'id'          => $row['id'],
        'name'        => $row['name'],
        'description' => $m['description'] ?? '',
        'cost'        => money((float) $row['cost']),
        'removes'     => money((float) $row['value']),
        'ratio'       => $row['ratio'],
        'covers'      => $m['covers'] ?? 0,
        'effort_days' => $m['effort_days'] ?? null,
        'control'     => $m['control_key'] ?? null,
        'reason'      => $row['reason'] ?? null,
    ];
};

$runId = null;
if ($isPost && !empty($in['save'])) {
    require_role($user, ['owner', 'analyst']);
    $pdo->prepare(
        "INSERT INTO optimizer_runs
            (tenant_id, budget_inr, allocated_inr, exposure_before, exposure_removed, solved_ms, constraints_json, created_by)
         VALUES (?,?,?,?,?,?,?,?)"
    )->execute([$p->tenantId, $r['budget'], $r['allocated'], $r['baseline'], $r['removed'],
                $r['solved_ms'], json_encode(['options' => count($options)]), (int) $user['id']]);
    $runId = (int) $pdo->lastInsertId();

    $sel = $pdo->prepare(
        "INSERT INTO optimizer_selections (run_id, remediation_id, selected, cost_inr, exposure_removed, ratio, reason)
         VALUES (?,?,?,?,?,?,?)"
    );
    foreach ($r['selected'] as $s) {
        $sel->execute([$runId, $s['id'], 1, $s['cost'], $s['value'], $s['ratio'], null]);
    }
    foreach ($r['rejected'] as $s) {
        $sel->execute([$runId, $s['id'], 0, $s['cost'], $s['value'], $s['ratio'] ?? 0, $s['reason']]);
    }
    $pdo->prepare("INSERT INTO audit_log (tenant_id, actor, action, entity_type, entity_ref, money_effect, note)
                   VALUES (?,?,?,?,?,?,?)")
        ->execute([$p->tenantId, (string) $user['email'], 'Optimizer plan saved', 'optimizer_run',
                   (string) $runId, $r['removed'],
                   'Budget ' . inr($r['budget']) . ', ' . count($r['selected']) . ' fixes selected']);
}

ok([
    'run_id'    => $runId,
    'baseline'  => money((float) $r['baseline']),
    'budget'    => money((float) $r['budget']),
    'allocated' => money((float) $r['allocated']),
    'unspent'   => money((float) $r['unspent']),
    'removed'   => money((float) $r['removed']),
    'percent'   => $r['baseline'] > 0 ? round($r['removed'] / $r['baseline'] * 100, 1) : 0.0,
    'return_per_rupee' => $r['allocated'] > 0 ? round($r['removed'] / $r['allocated'], 2) : null,
    // Non-zero means the chosen fixes cover some of the same ground. The
    // headline above is the joint value; this is how much the parts overstated it.
    'overlap'   => money((float) $r['overlap']),
    'selected'  => array_map($decorate, $r['selected']),
    'rejected'  => array_map($decorate, $r['rejected']),
    'solved_ms' => $r['solved_ms'],
    'options_considered' => count($options),
]);
