<?php
/**
 * GET /api/v1/controls.php
 *
 * The page that keeps the model honest: what each control claims, what the
 * telemetry observed, and what it is worth in rupees today. "Exposure reduced"
 * is computed by removing the control and re-running the model — the argument
 * for renewing it at contract time, and a number nobody currently has.
 */
require_once __DIR__ . '/_boot.php';
require_once __DIR__ . '/../risk/Portfolio.php';

$pdo  = db();
$user = currentUser($pdo);
require_role($user, ['owner', 'analyst', 'viewer']);
$tid  = (int) $user['tenant_id'];

$p        = Portfolio::load($pdo, (string) $user['tenant_slug']);
$baseline = $p->exposure();

$rows = $pdo->prepare(
    "SELECT c.*, COUNT(ac.asset_id) AS deployed
       FROM controls c
  LEFT JOIN asset_controls ac ON ac.control_id = c.id AND ac.status <> 'absent'
      WHERE c.tenant_id = ?
   GROUP BY c.id
   ORDER BY c.control_key"
);
$rows->execute([$tid]);

$assetCount = count($p->assets);
$out = [];
$underperforming = [];

foreach ($rows as $c) {
    $key = (string) $c['control_key'];

    // Worth: exposure if this control vanished, minus exposure now.
    $stripped = clone $p;
    $stripped->controls = [];
    foreach ($p->controls as $aid => $set) {
        unset($set[$key]);
        $stripped->controls[$aid] = $set;
    }
    $without = $stripped->exposure();
    $worth   = max(0.0, $without - $baseline);

    $claimed  = (float) $c['claimed_effectiveness'];
    $observed = $c['observed_effectiveness'] !== null ? (float) $c['observed_effectiveness'] : null;
    $gap      = $observed !== null ? $claimed - $observed : null;

    $row = [
        'key'      => $key,
        'name'     => $c['name'],
        'vendor'   => $c['vendor'],
        'claimed'  => $claimed,
        'observed' => $observed,
        'gap'      => $gap !== null ? round($gap, 4) : null,
        'in_use'   => $observed !== null ? $observed : $claimed,
        'basis'    => $observed !== null ? 'observed' : 'claimed only',
        'coverage' => [
            'assets' => (int) $c['deployed'],
            'total'  => $assetCount,
            'percent'=> $assetCount > 0 ? round((int) $c['deployed'] / $assetCount * 100) : 0,
        ],
        'telemetry' => [
            'observations' => (int) $c['observation_count'],
            'misses'       => (int) $c['miss_count'],
        ],
        'exposure_reduced' => money($worth),
    ];

    // A control materially below its claim is the headline of this page.
    if ($gap !== null && $gap >= 0.15) {
        $underperforming[] = [
            'key' => $key, 'name' => $c['name'],
            'claimed' => $claimed, 'observed' => $observed,
            'assets' => (int) $c['deployed'],
            'message' => $c['name'] . ' claims ' . number_format($claimed, 2)
                       . ' but telemetry puts it at ' . number_format((float) $observed, 2)
                       . ' across ' . (int) $c['deployed'] . ' assets. The score uses the observed figure.',
        ];
    }
    $out[] = $row;
}

usort($out, static fn($a, $b) => $b['exposure_reduced']['value'] <=> $a['exposure_reduced']['value']);

ok([
    'baseline' => money($baseline),
    'controls' => $out,
    'underperforming' => $underperforming,
    'note' => 'Exposure reduced is what the estate would carry WITHOUT this control, '
            . 'minus what it carries today. Coverage counts assets the control actually '
            . 'reaches, not licences purchased.',
]);
