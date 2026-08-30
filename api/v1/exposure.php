<?php
/**
 * GET /api/v1/exposure.php
 *
 * The CFO's page: the total with its band, what drives it, and every assumption
 * in force. Sensitivity is computed by actually re-running the model with each
 * driver switched off — not by apportioning the total, which would only tell
 * the reader what we already assumed.
 */
require_once __DIR__ . '/_boot.php';
require_once __DIR__ . '/../risk/Portfolio.php';

$pdo  = db();
$user = currentUser($pdo);
require_role($user, ['owner', 'executive', 'analyst', 'viewer']);
$tid  = (int) $user['tenant_id'];

$p     = Portfolio::load($pdo, (string) $user['tenant_slug']);
$model = $p->model;
$eval  = $p->evaluate();
$total = $eval['total'];

$band = $pdo->query(
    "SELECT COALESCE(SUM(ale_min),0) lo, COALESCE(SUM(ale_max),0) hi
       FROM risk_scores WHERE tenant_id = $tid AND is_current = 1"
)->fetch();

// ---- what drives the total, by impact channel. Re-evaluate with each channel
//      zeroed so the answer comes from the model, not from arithmetic on it.
$drivers = [];
foreach (['availability', 'confidentiality', 'integrity'] as $channel) {
    $muted = clone $p;
    $muted->findings = [];
    foreach ($p->findings as $fid => $f) {
        $copy = $f;
        $copy[$channel === 'availability' ? 'impact_a'
            : ($channel === 'confidentiality' ? 'impact_c' : 'impact_i')] = 0;
        $muted->findings[$fid] = $copy;
    }
    $without = $muted->exposure();
    $drivers[] = [
        'driver'  => $channel,
        'label'   => [
            'availability'    => 'Downtime and recovery',
            'confidentiality' => 'Data breach and penalty',
            'integrity'       => 'Contractual and reputational',
        ][$channel],
        'value'   => money(max(0.0, $total - $without)),
        'share'   => $total > 0 ? round(max(0.0, $total - $without) / $total * 100, 1) : 0.0,
    ];
}
usort($drivers, static fn($a, $b) => $b['value']['value'] <=> $a['value']['value']);

// ---- top assets, so the total is traceable to real systems
$byAsset = [];
foreach ($eval['per_asset'] as $aid => $v) {
    $byAsset[] = ['asset' => $p->assets[$aid]['hostname'], 'exposure' => money((float) $v)];
}
usort($byAsset, static fn($a, $b) => $b['exposure']['value'] <=> $a['exposure']['value']);

$versions = $pdo->prepare(
    "SELECT version, revenue_per_hour, created_at, note, is_active
       FROM loss_models WHERE tenant_id = ? ORDER BY version DESC"
);
$versions->execute([$tid]);

ok([
    'total' => money($total),
    'band'  => [
        'min' => money((float) $band['lo']),
        'max' => money((float) $band['hi']),
        'note' => 'The band widens as confidence falls. It is not a forecast range — '
                . 'it is how much the inputs themselves are trusted.',
    ],
    'drivers' => $drivers,
    'by_asset' => array_slice($byAsset, 0, 10),
    'assumptions' => [
        'revenue_per_hour'      => money((float) $model['revenue_per_hour']),
        'median_recovery_hours' => (float) $model['median_recovery_hours'],
        'pii_records'           => (int) $model['pii_records'],
        'cost_per_record'       => money((float) $model['cost_per_record']),
        'penalty_band'          => $model['penalty_band'],
        'penalty_cap'           => money((float) $model['penalty_cap']),
        'ransom_recovery_cost'  => money((float) $model['ransom_recovery_cost']),
        'reputational_cost'     => money((float) $model['reputational_cost']),
        'version'               => (int) $model['version'],
        'note'                  => $model['note'],
    ],
    'model_versions' => array_map(static fn($r) => [
        'version' => (int) $r['version'],
        'revenue_per_hour' => money((float) $r['revenue_per_hour']),
        'created_at' => $r['created_at'],
        'active' => (bool) $r['is_active'],
        'note' => $r['note'],
    ], $versions->fetchAll()),
]);
