<?php
/**
 * Self-check for the risk engine. No framework, no database — pure functions in,
 * assertions out.  php tests/risk_engine_test.php
 *
 * Every case here is one the model got WRONG at some point during Phase 2.
 */
require_once __DIR__ . '/../api/risk/RiskEngine.php';
require_once __DIR__ . '/../api/risk/LossModel.php';
require_once __DIR__ . '/../api/risk/Aggregator.php';

$pass = 0;
$fail = 0;

function check(string $what, bool $ok, string $detail = ''): void
{
    global $pass, $fail;
    if ($ok) { $pass++; echo "  ok   $what\n"; }
    else     { $fail++; echo "  FAIL $what" . ($detail ? " — $detail" : '') . "\n"; }
}

// ---------------------------------------------------------------- fixtures
$bluekeep = [
    'cve_id' => 'CVE-2019-0708', 'source' => 'nvd',
    'title' => 'Microsoft Remote Desktop Services Remote Code Execution',
    'description' => 'remote code execution in remote desktop services',
    'cvss_score' => 9.8, 'cvss_version' => '3.1',
    'cvss_vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'epss_score' => 0.99999, 'epss_asof' => '2026-08-29',
    'kev_listed' => 1, 'kev_ransomware' => 1,
];
$quietBug = [
    'cve_id' => 'CVE-2016-0000', 'source' => 'nvd', 'title' => 'Local info disclosure',
    'description' => 'local information disclosure', 'cvss_score' => 4.0, 'cvss_version' => '3.1',
    'cvss_vector' => 'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N',
    'epss_score' => 0.0001, 'epss_asof' => '2026-08-29',
    'kev_listed' => 0, 'kev_ransomware' => 0,
];
$edgeAsset     = ['criticality' => 0.90, 'internet_facing' => 1, 'revenue_per_hour' => null, 'pii_records' => 0];
$internalAsset = ['criticality' => 0.50, 'internet_facing' => 0, 'revenue_per_hour' => null, 'pii_records' => 0];
$model = [
    'version' => 1, 'revenue_per_hour' => 1240000.00, 'median_recovery_hours' => 12.00,
    'pii_records' => 184000, 'cost_per_record' => 6100.00, 'penalty_cap' => 250000000.00,
    'ransom_recovery_cost' => 8500000.00, 'reputational_cost' => 4800000.00,
];

// ------------------------------------------------------------ RiskEngine
echo "RiskEngine\n";

$s = RiskEngine::score($bluekeep, $edgeAsset, []);
check('every factor is a probability in [0,1]',
    $s['severity_factor'] <= 1 && $s['threat_probability'] <= 1 && $s['exposure_factor'] <= 1
    && $s['control_gap'] <= 1 && $s['raw_risk'] >= 0 && $s['raw_risk'] <= 1);
check('raw risk is exactly the product of the five factors',
    abs($s['raw_risk'] - $s['severity_factor'] * $s['threat_probability'] * $s['asset_criticality']
        * $s['exposure_factor'] * $s['control_gap']) < 1e-6);
check('internet-facing asset is fully exposed', $s['exposure_factor'] == 1.00);
check('an unprotected asset has no control credit', $s['control_gap'] == 1.00);

$q = RiskEngine::score($quietBug, $internalAsset, []);
check('a local low-EPSS bug scores far below an exploited RCE',
    $q['raw_risk'] < $s['raw_risk'] / 20, "quiet={$q['raw_risk']} bluekeep={$s['raw_risk']}");
check('CVSS attack vector drives exposure on internal assets',
    $q['exposure_factor'] == 0.25, 'AV:L should give 0.25, got ' . $q['exposure_factor']);

// The KEV floor: CISA has SEEN this exploited, so a low EPSS must not talk the
// probability down to nothing.
$kevButQuiet = $quietBug;
$kevButQuiet['kev_listed'] = 1;
$k = RiskEngine::score($kevButQuiet, $internalAsset, []);
check('KEV listing floors the threat probability at 0.70', $k['threat_probability'] >= 0.70);
$ransom = $kevButQuiet;
$ransom['kev_ransomware'] = 1;
check('a ransomware-linked CVE floors higher still',
    RiskEngine::score($ransom, $internalAsset, [])['threat_probability'] >= 0.85);

// EPSS is a 30-day figure. Using it raw would understate a year of exposure.
$slow = $quietBug;
$slow['epss_score'] = 0.05;
$annual = RiskEngine::score($slow, $internalAsset, [])['threat_probability'];
check('EPSS is annualized, not used raw', $annual > 0.05 * 3,
    "30-day 0.05 should compound well above 0.15, got $annual");

// Controls
$controls = ['edr' => ['effectiveness' => 0.71, 'observed' => true]];
$withEdr = RiskEngine::score($bluekeep, $edgeAsset, $controls);
check('an applicable control reduces the gap', $withEdr['control_gap'] < 1.00);
// A web application firewall cannot stop an RDP exploit. A control that cannot
// touch a weakness must not be allowed to reduce its score — that is how a
// security programme talks itself into a number it has not earned.
$wafOnly = RiskEngine::score($bluekeep, $edgeAsset, ['waf' => ['effectiveness' => 0.9, 'observed' => false]]);
check('a WAF gets no credit against an RDP exploit',
    $wafOnly['control_gap'] == 1.00, 'gap ' . $wafOnly['control_gap'] . ' tags: ' . implode(',', $wafOnly['tags']));

// REGRESSION: three stacked controls once composed to a 99.5% reduction.
$stack = [
    'edr'    => ['effectiveness' => 0.71, 'observed' => true],
    'waf'    => ['effectiveness' => 0.69, 'observed' => true],
    'backup' => ['effectiveness' => 0.95, 'observed' => true],
];
$stacked = RiskEngine::score($bluekeep, $edgeAsset, $stack);
check('no control stack is trusted below a 5% residual',
    $stacked['control_gap'] >= 0.05, 'got ' . $stacked['control_gap']);

check('an unscored CVE still produces a number', RiskEngine::score(
    ['cve_id' => 'CVE-X', 'source' => 'nvd', 'title' => 't', 'description' => '',
     'cvss_score' => null, 'cvss_version' => null, 'cvss_vector' => null,
     'epss_score' => null, 'epss_asof' => null, 'kev_listed' => 0, 'kev_ransomware' => 0],
    $internalAsset, [])['raw_risk'] > 0);

// ------------------------------------------------------------- LossModel
echo "\nLossModel\n";

$dataAsset = ['criticality' => 0.80, 'internet_facing' => 1, 'revenue_per_hour' => null, 'pii_records' => 184000];
$ch = LossModel::channels($dataAsset, $model);
check('a system holding records carries a confidentiality loss', $ch['confidentiality'] > 0);
// REGRESSION: a VPN appliance was once charged for 154,000 customer records.
check('a system holding no records carries no record loss',
    LossModel::channels($edgeAsset, $model)['confidentiality'] == 0.0);
check('downtime uses revenue per hour × recovery hours × criticality',
    abs($ch['detail']['downtime'] - 1240000 * 12 * 0.80) < 1);
check('the statutory penalty respects the cap',
    $ch['detail']['penalty'] <= (float) $model['penalty_cap']);

$band = LossModel::band(1000000.0, 0.95);
check('a high-confidence band is tight', $band['max'] / $band['min'] < 2.0);
$wide = LossModel::band(1000000.0, 0.50);
check('a low-confidence band is wider', $wide['max'] / $wide['min'] > $band['max'] / $band['min']);
check('the point estimate sits inside its own band',
    $wide['min'] < 1000000.0 && $wide['max'] > 1000000.0);

// ------------------------------------------------------------ Aggregator
echo "\nAggregator\n";

$loss = ['availability' => 10000000.0, 'confidentiality' => 5000000.0, 'integrity' => 1000000.0];
$all  = ['availability' => true, 'confidentiality' => true, 'integrity' => true];

// REGRESSION: the bug that put ₹201 Cr on one gateway. Three ways into a server
// is not three servers.
$one   = Aggregator::forAsset([['id' => 1, 'raw_risk' => 0.5, 'channels' => $all]], $loss);
$three = Aggregator::forAsset([
    ['id' => 1, 'raw_risk' => 0.5, 'channels' => $all],
    ['id' => 2, 'raw_risk' => 0.5, 'channels' => $all],
    ['id' => 3, 'raw_risk' => 0.5, 'channels' => $all],
], $loss);
check('more findings raise the asset total', $three['asset_ale'] > $one['asset_ale']);
check('three findings do NOT cost three times one',
    $three['asset_ale'] < $one['asset_ale'] * 3,
    "one={$one['asset_ale']} three={$three['asset_ale']}");
check('an asset can never lose more than it is worth',
    $three['asset_ale'] <= array_sum($loss) + 0.01);

check('the per-finding shares sum exactly to the asset total',
    abs(array_sum($three['per_finding']) - $three['asset_ale']) < 0.01,
    'drift ' . (array_sum($three['per_finding']) - $three['asset_ale']));

// A finding that cannot touch a channel must not be paid out of it.
$split = Aggregator::forAsset([
    ['id' => 1, 'raw_risk' => 0.4, 'channels' => ['availability' => true,  'confidentiality' => false, 'integrity' => false]],
    ['id' => 2, 'raw_risk' => 0.4, 'channels' => ['availability' => false, 'confidentiality' => true,  'integrity' => false]],
], $loss);
check('the availability finding takes the larger share (bigger channel)',
    $split['per_finding'][1] > $split['per_finding'][2]);
check('a certain finding claims its whole channel',
    abs(Aggregator::forAsset(
        [['id' => 1, 'raw_risk' => 1.0, 'channels' => ['availability' => true, 'confidentiality' => false, 'integrity' => false]]],
        $loss)['asset_ale'] - $loss['availability']) < 0.01);
check('an asset with no findings is worth zero exposure',
    Aggregator::forAsset([], $loss)['asset_ale'] == 0.0);

// ------------------------------------------------------------------ done
echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
