<?php
/**
 * Portfolio — the tenant's whole estate in memory, and the one place that can
 * answer "what would exposure be IF…".
 *
 * Every consumer goes through this: the nightly recompute, the optimizer's
 * counterfactuals, and the what-if simulator. That is deliberate — if the
 * optimizer used its own copy of the arithmetic, it would eventually disagree
 * with the dashboard, and the first time a customer noticed, the product would
 * be finished.
 *
 * Load once (a few queries), then evaluate as many hypotheticals as you like
 * with no further database work.
 */
require_once __DIR__ . '/RiskEngine.php';
require_once __DIR__ . '/LossModel.php';
require_once __DIR__ . '/Aggregator.php';

class Portfolio
{
    public int $tenantId;
    public array $model = [];
    /** @var array<int,array> asset row by asset id */
    public array $assets = [];
    /** @var array<int,array> finding rows (vulnerability joined) by finding id */
    public array $findings = [];
    /** @var array<int,array<string,array>> asset id => control_key => [effectiveness, observed] */
    public array $controls = [];

    public static function load(PDO $pdo, string $slug): self
    {
        $p = new self();

        $t = $pdo->prepare("SELECT id FROM tenants WHERE slug = ?");
        $t->execute([$slug]);
        $tid = (int) $t->fetchColumn();
        if (!$tid) {
            throw new RuntimeException("no such tenant: $slug");
        }
        $p->tenantId = $tid;

        $m = $pdo->prepare("SELECT * FROM loss_models WHERE tenant_id = ? AND is_active = 1
                            ORDER BY version DESC LIMIT 1");
        $m->execute([$tid]);
        $p->model = $m->fetch() ?: [];
        if (!$p->model) {
            throw new RuntimeException("tenant $slug has no active loss model");
        }

        $a = $pdo->prepare("SELECT * FROM assets WHERE tenant_id = ? AND decommissioned_at IS NULL");
        $a->execute([$tid]);
        foreach ($a as $row) {
            $p->assets[(int) $row['id']] = $row;
        }

        $c = $pdo->prepare(
            "SELECT ac.asset_id, c.control_key, c.claimed_effectiveness, c.observed_effectiveness
               FROM asset_controls ac
               JOIN controls c ON c.id = ac.control_id
              WHERE c.tenant_id = ? AND ac.status <> 'absent'"
        );
        $c->execute([$tid]);
        foreach ($c as $row) {
            $observed = $row['observed_effectiveness'] !== null;
            $p->controls[(int) $row['asset_id']][$row['control_key']] = [
                'effectiveness' => (float) ($observed ? $row['observed_effectiveness'] : $row['claimed_effectiveness']),
                'observed'      => $observed,
            ];
        }

        $f = $pdo->prepare(
            "SELECT f.id, f.asset_id, f.status, f.port, f.detector, f.first_seen_at,
                    v.id AS vuln_id, v.cve_id, v.local_key, v.source, v.title, v.description,
                    v.cvss_score, v.cvss_version, v.cvss_severity, v.cvss_vector,
                    v.epss_score, v.epss_asof, v.kev_listed, v.kev_ransomware, v.kev_date_added,
                    v.impact_c, v.impact_i, v.impact_a
               FROM findings f
               JOIN vulnerabilities v ON v.id = f.vulnerability_id
              WHERE f.tenant_id = ? AND f.status = 'open'"
        );
        $f->execute([$tid]);
        foreach ($f as $row) {
            if (isset($p->assets[(int) $row['asset_id']])) {
                $p->findings[(int) $row['id']] = $row;
            }
        }

        return $p;
    }

    /**
     * Evaluate the estate, optionally under a hypothetical.
     *
     * @param array $what {
     *   remove_findings: int[]                  findings that would no longer exist
     *   control_effectiveness: [key => float]   a control gets better everywhere it is deployed
     *   add_control_to: [key => int[]]          a control gets deployed to these assets
     * }
     * @return array{total:float, per_finding:array, per_asset:array, scores:array}
     */
    public function evaluate(array $what = []): array
    {
        $removed  = array_flip($what['remove_findings'] ?? []);
        $better   = $what['control_effectiveness'] ?? [];
        $deployTo = $what['add_control_to'] ?? [];

        // Controls, with the hypothetical applied.
        $controls = $this->controls;
        foreach ($deployTo as $key => $assetIds) {
            foreach ($assetIds as $aid) {
                $aid = (int) $aid;
                if (!isset($this->assets[$aid])) {
                    continue;
                }
                $controls[$aid][$key] = [
                    'effectiveness' => (float) ($better[$key] ?? $controls[$aid][$key]['effectiveness'] ?? 0.5),
                    'observed'      => false,   // not yet observed — it does not exist yet
                ];
            }
        }
        foreach ($better as $key => $eff) {
            foreach ($controls as $aid => $set) {
                if (isset($set[$key])) {
                    $controls[$aid][$key]['effectiveness'] = max($set[$key]['effectiveness'], (float) $eff);
                }
            }
        }

        // Pass 1 — score every surviving finding.
        $scores  = [];
        $byAsset = [];
        foreach ($this->findings as $fid => $f) {
            if (isset($removed[$fid])) {
                continue;
            }
            $aid   = (int) $f['asset_id'];
            $asset = $this->assets[$aid];
            $s = RiskEngine::score($f, $asset, $controls[$aid] ?? []);
            $scores[$fid] = $s;
            $byAsset[$aid][] = [
                'id'       => $fid,
                'raw_risk' => $s['raw_risk'],
                'channels' => [
                    'availability'    => (bool) $f['impact_a'],
                    'confidentiality' => (bool) $f['impact_c'],
                    'integrity'       => (bool) $f['impact_i'],
                ],
            ];
        }

        // Pass 2 — value each asset once, split across its findings.
        $perFinding = [];
        $perAsset   = [];
        $total      = 0.0;
        foreach ($byAsset as $aid => $list) {
            $loss = LossModel::channels($this->assets[$aid], $this->model);
            $agg  = Aggregator::forAsset($list, $loss);
            $perAsset[$aid] = $agg['asset_ale'];
            $total += $agg['asset_ale'];
            foreach ($agg['per_finding'] as $fid => $ale) {
                $perFinding[$fid] = $ale;
            }
        }

        return [
            'total'       => round($total, 2),
            'per_finding' => $perFinding,
            'per_asset'   => $perAsset,
            'scores'      => $scores,
        ];
    }

    /** Convenience: the exposure figure alone. */
    public function exposure(array $what = []): float
    {
        return $this->evaluate($what)['total'];
    }
}
