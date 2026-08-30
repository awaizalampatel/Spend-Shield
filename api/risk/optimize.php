<?php
/**
 * Run the optimizer and store the result.
 *
 *   php api/risk/optimize.php --budget=1800000 [--tenant=acme-in] [--curve] [--dry]
 *
 * --curve prints the diminishing-returns table instead of a single plan.
 * --dry   solves without writing an optimizer_runs row.
 */
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/Portfolio.php';
require_once __DIR__ . '/Optimizer.php';
require_once __DIR__ . '/Remediations.php';

$pdo    = db();
$tenant = 'acme-in';
$budget = 1800000.0;
$curve  = in_array('--curve', $argv, true);
$dry    = in_array('--dry', $argv, true);
foreach ($argv as $a) {
    if (str_starts_with($a, '--tenant=')) { $tenant = substr($a, 9); }
    if (str_starts_with($a, '--budget=')) { $budget = (float) substr($a, 9); }
}

$inr = static function (float $x): string {
    if ($x >= 10000000) { return '₹' . number_format($x / 10000000, 2) . ' Cr'; }
    if ($x >= 100000)   { return '₹' . number_format($x / 100000, 2) . ' L'; }
    return '₹' . number_format($x, 0);
};

$p = Portfolio::load($pdo, $tenant);
$options = Remediations::catalog($pdo, $p->tenantId);
if (!$options) {
    fwrite(STDERR, "no remediation options — run api/ingest/seed_remediations.php\n");
    exit(1);
}

if ($curve) {
    $budgets = [0, 100000, 250000, 500000, 1000000, 1800000, 3000000, 5000000, 8000000];
    echo "\nWhat another rupee buys\n", str_repeat('-', 58), "\n";
    printf("%12s %14s %14s %7s\n", 'BUDGET', 'REMOVED', 'SPENT', 'FIXES');
    foreach (Optimizer::curve($p, $options, $budgets) as $pt) {
        printf("%12s %14s %14s %7d\n",
            $inr($pt['budget']), $inr($pt['removed']), $inr($pt['allocated']), $pt['count']);
    }
    echo "\n";
    exit(0);
}

$r = Optimizer::solve($p, $options, $budget);

echo "\nBudget ", $inr($r['budget']), " · baseline exposure ", $inr($r['baseline']), "\n";
echo str_repeat('-', 96), "\n";
printf("%-58s %11s %13s %8s\n", 'SELECTED', 'COST', 'REMOVES', 'RETURN');
foreach ($r['selected'] as $s) {
    printf("%-58s %11s %13s %7sx\n",
        mb_substr($s['name'], 0, 58), $inr($s['cost']), $inr($s['value']), number_format($s['ratio'], 1));
}

echo "\n";
printf("%-58s %11s %13s %8s\n", 'NOT SELECTED', 'COST', 'WOULD REMOVE', '');
foreach (array_slice($r['rejected'], 0, 6) as $s) {
    printf("%-58s %11s %13s   %s\n",
        mb_substr($s['name'], 0, 58), $inr($s['cost']), $inr($s['value']), $s['reason']);
}

$pct = $r['baseline'] > 0 ? $r['removed'] / $r['baseline'] * 100 : 0;
echo "\n", str_repeat('-', 96), "\n";
echo "Allocated       ", $inr($r['allocated']), "   (unspent ", $inr($r['unspent']), ")\n";
echo "Exposure removed ", $inr($r['removed']), "   ", number_format($pct, 1), "% of ", $inr($r['baseline']), "\n";
echo "Return           ", $inr($r['allocated'] > 0 ? $r['removed'] / $r['allocated'] : 0),
     " of exposure removed per rupee spent\n";
if ($r['overlap'] > 0) {
    echo "Overlap          ", $inr($r['overlap']),
         " — the chosen fixes cover some of the same ground; the figure above is the joint value, not the sum\n";
}
echo "Solved in        ", $r['solved_ms'], "ms over ", count($options), " options\n";

if ($dry) {
    exit(0);
}

$pdo->prepare(
    "INSERT INTO optimizer_runs
        (tenant_id, budget_inr, allocated_inr, exposure_before, exposure_removed, solved_ms, constraints_json)
     VALUES (?,?,?,?,?,?,?)"
)->execute([$p->tenantId, $r['budget'], $r['allocated'], $r['baseline'], $r['removed'], $r['solved_ms'],
            json_encode(['options' => count($options)])]);
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

echo "Stored as optimizer run #", $runId, "\n";
