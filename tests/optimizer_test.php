<?php
/**
 * Self-check for the optimizer and the portfolio evaluator.
 * No database — the Portfolio is built by hand.
 *
 *   php tests/optimizer_test.php
 */
require_once __DIR__ . '/../api/risk/Portfolio.php';
require_once __DIR__ . '/../api/risk/Optimizer.php';

$pass = 0; $fail = 0;
function check(string $what, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) { $pass++; echo "  ok   $what\n"; }
    else     { $fail++; echo "  FAIL $what" . ($detail ? " — $detail" : '') . "\n"; }
}

// ------------------------------------------------------------- a tiny estate
function makePortfolio(): Portfolio
{
    $p = new Portfolio();
    $p->tenantId = 1;
    $p->model = [
        'version' => 1, 'revenue_per_hour' => 1000000.00, 'median_recovery_hours' => 10.00,
        'pii_records' => 100000, 'cost_per_record' => 6000.00, 'penalty_cap' => 250000000.00,
        'ransom_recovery_cost' => 5000000.00, 'reputational_cost' => 4000000.00,
    ];
    $p->assets = [
        1 => ['id' => 1, 'hostname' => 'edge-01', 'criticality' => 0.9, 'internet_facing' => 1,
              'revenue_per_hour' => null, 'pii_records' => 0],
        2 => ['id' => 2, 'hostname' => 'db-01', 'criticality' => 0.8, 'internet_facing' => 0,
              'revenue_per_hour' => null, 'pii_records' => 100000],
    ];
    $vuln = [
        'source' => 'nvd', 'title' => 'Remote code execution in the web server',
        'description' => 'remote code execution', 'cvss_score' => 9.8, 'cvss_version' => '3.1',
        'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'epss_score' => 0.9, 'epss_asof' => '2026-08-29', 'kev_listed' => 1, 'kev_ransomware' => 0,
        'impact_c' => 1, 'impact_i' => 1, 'impact_a' => 1,
    ];
    $p->findings = [
        10 => $vuln + ['id' => 10, 'asset_id' => 1],
        11 => $vuln + ['id' => 11, 'asset_id' => 1],
        12 => $vuln + ['id' => 12, 'asset_id' => 2],
    ];
    $p->controls = [];
    return $p;
}

$p = makePortfolio();
$baseline = $p->exposure();

echo "Portfolio\n";
check('a loaded estate has exposure', $baseline > 0);
check('removing a finding lowers exposure',
    $p->exposure(['remove_findings' => [10]]) < $baseline);
check('removing every finding takes exposure to zero',
    $p->exposure(['remove_findings' => [10, 11, 12]]) == 0.0);
check('deploying a control lowers exposure',
    $p->exposure(['add_control_to' => ['edr' => [1, 2]], 'control_effectiveness' => ['edr' => 0.8]]) < $baseline);
check('evaluating a hypothetical does not mutate the portfolio',
    $p->exposure() === $baseline, 'baseline moved after counterfactuals');

// REGRESSION: two findings on one asset must not cost twice one finding.
$one = $p->exposure(['remove_findings' => [11, 12]]);   // only finding 10 remains
$two = $p->exposure(['remove_findings' => [12]]);        // findings 10 and 11 remain
check('a second finding on the same asset adds less than the first',
    $two < $one * 2 && $two > $one, "one=$one two=$two");

// ------------------------------------------------------------------ knapsack
echo "\nOptimizer\n";

$options = [
    ['id' => 1, 'name' => 'cheap and effective', 'cost' => 50000.0,
     'effect' => ['remove_findings' => [10]]],
    ['id' => 2, 'name' => 'dear and effective', 'cost' => 900000.0,
     'effect' => ['remove_findings' => [12]]],
    ['id' => 3, 'name' => 'covers the same ground as option 1', 'cost' => 70000.0,
     'effect' => ['remove_findings' => [10]]],
    ['id' => 4, 'name' => 'fixes nothing that exists', 'cost' => 20000.0,
     'effect' => ['remove_findings' => [999]]],
];

$r = Optimizer::solve($p, $options, 200000.0);
check('nothing selected costs more than the budget', $r['allocated'] <= $r['budget']);
check('the cheap effective option is selected',
    in_array(1, array_column($r['selected'], 'id'), true));
check('an option that fixes nothing is rejected',
    in_array(4, array_column($r['rejected'], 'id'), true));
check('and it is rejected for the right reason',
    ($r['rejected'][array_search(4, array_column($r['rejected'], 'id'), true)]['reason'] ?? '')
    === 'removes no exposure the estate actually carries');
check('an unaffordable option says so',
    ($r['rejected'][array_search(2, array_column($r['rejected'], 'id'), true)]['reason'] ?? '')
    === 'costs more than the whole budget');

// REGRESSION: overlapping options must not be paid for twice.
$overlap = Optimizer::solve($p, [
    ['id' => 1, 'name' => 'a', 'cost' => 50000.0, 'effect' => ['remove_findings' => [10]]],
    ['id' => 3, 'name' => 'b', 'cost' => 70000.0, 'effect' => ['remove_findings' => [10]]],
], 500000.0);
$sumOfParts = array_sum(array_column($overlap['selected'], 'value'));
check('the reported removal is the joint value, never the sum of parts',
    $overlap['removed'] <= $sumOfParts + 0.01,
    "removed={$overlap['removed']} sum=$sumOfParts");
check('overlap between chosen fixes is reported, not hidden',
    count($overlap['selected']) < 2 || $overlap['overlap'] > 0);

check('a zero budget buys nothing',
    Optimizer::solve($p, $options, 0.0)['removed'] == 0.0);
$rich = Optimizer::solve($p, $options, 100000000.0);
check('an unlimited budget cannot remove more than the estate is worth',
    $rich['removed'] <= $baseline + 0.01, "removed={$rich['removed']} baseline=$baseline");
check('exposure removed is never negative', $rich['removed'] >= 0);

// ---------------------------------------------------------------- the curve
echo "\nCurve\n";
$curve = Optimizer::curve($p, $options, [0, 50000, 200000, 1000000, 5000000]);
$monotone = true;
for ($i = 1; $i < count($curve); $i++) {
    if ($curve[$i]['removed'] < $curve[$i - 1]['removed'] - 0.01) { $monotone = false; }
}
check('more budget never removes less exposure', $monotone);
check('the curve starts at zero', $curve[0]['removed'] == 0.0);
check('the curve flattens rather than growing forever',
    $curve[count($curve) - 1]['removed'] <= $baseline + 0.01);

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
