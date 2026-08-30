<?php
/**
 * Optimizer — given a budget, choose the remediations that remove the most
 * exposure. A 0/1 knapsack, solved exactly by dynamic programming.
 *
 * WHY NOT OR-TOOLS. The problem is one knapsack over a few dozen items with a
 * single constraint. DP solves that exactly in milliseconds, in the language the
 * rest of the backend already speaks. Adding a Python service to call a solver
 * would buy nothing and cost a second runtime in the deployment.
 * ponytail: exact DP over one budget constraint. If scheduling constraints ever
 * appear (crew availability, change windows, dependencies between fixes), that
 * is a different problem and OR-Tools earns its place then.
 *
 * THE OVERLAP PROBLEM, stated plainly. Two options can cover the same finding.
 * Their values are then not additive — fixing the same hole twice removes it
 * once. So:
 *   1. each option is valued alone, against the real baseline (a counterfactual
 *      through Portfolio, not an estimate),
 *   2. DP selects on those values,
 *   3. the selected SET is then re-evaluated JOINTLY, and that is the number
 *      reported.
 * The headline is therefore always true, even where overlap made the selection
 * slightly short of optimal. A run records the gap so it is never invisible.
 */
require_once __DIR__ . '/Portfolio.php';

class Optimizer
{
    /**
     * DP granularity. Costs are bucketed to ₹1,000 so the table stays small;
     * a ₹50 lakh budget is 5,000 columns, which is nothing.
     */
    private const UNIT = 1000;

    /**
     * @param Portfolio $p
     * @param array $options each: ['id'=>int,'name'=>string,'cost'=>float,'effect'=>array]
     *                       where effect is a Portfolio::evaluate() hypothetical
     * @param float $budget
     * @return array{selected:array, rejected:array, baseline:float, removed:float,
     *               allocated:float, overlap:float, solved_ms:int}
     */
    public static function solve(Portfolio $p, array $options, float $budget): array
    {
        $t0 = microtime(true);
        $baseline = $p->exposure();

        // ---- value each option on its own, against the real estate
        $items = [];
        foreach ($options as $o) {
            $after = $p->exposure($o['effect']);
            $value = max(0.0, $baseline - $after);
            $items[] = [
                'id'     => (int) $o['id'],
                'name'   => (string) $o['name'],
                'cost'   => (float) $o['cost'],
                'value'  => $value,
                'effect' => $o['effect'],
                'ratio'  => $o['cost'] > 0 ? $value / $o['cost'] : INF,
            ];
        }

        // ---- 0/1 knapsack, exact
        $cap = (int) floor($budget / self::UNIT);
        $n   = count($items);
        $affordable = [];
        foreach ($items as $i => $it) {
            $w = (int) ceil($it['cost'] / self::UNIT);
            if ($w <= $cap && $w > 0) {
                $affordable[$i] = $w;
            }
        }

        // dp[c] = best value at capacity c; keep[i][c] = was item i taken
        $dp   = array_fill(0, $cap + 1, 0.0);
        $keep = [];
        foreach ($affordable as $i => $w) {
            $row = array_fill(0, $cap + 1, false);
            for ($c = $cap; $c >= $w; $c--) {
                $cand = $dp[$c - $w] + $items[$i]['value'];
                if ($cand > $dp[$c]) {
                    $dp[$c]  = $cand;
                    $row[$c] = true;
                }
            }
            $keep[$i] = $row;
        }

        // walk the table back to recover the chosen set
        $chosen = [];
        $c = $cap;
        foreach (array_reverse(array_keys($affordable), true) as $i) {
            if (!empty($keep[$i][$c])) {
                $chosen[] = $i;
                $c -= $affordable[$i];
            }
        }
        $chosen = array_reverse($chosen);

        // ---- re-evaluate the chosen set JOINTLY. This is the honest number.
        $joint = ['remove_findings' => [], 'control_effectiveness' => [], 'add_control_to' => []];
        $allocated = 0.0;
        $naiveSum  = 0.0;
        foreach ($chosen as $i) {
            $e = $items[$i]['effect'];
            $joint['remove_findings'] = array_merge($joint['remove_findings'], $e['remove_findings'] ?? []);
            foreach (($e['control_effectiveness'] ?? []) as $k => $v) {
                $joint['control_effectiveness'][$k] = max($joint['control_effectiveness'][$k] ?? 0, $v);
            }
            foreach (($e['add_control_to'] ?? []) as $k => $ids) {
                $joint['add_control_to'][$k] = array_unique(array_merge($joint['add_control_to'][$k] ?? [], $ids));
            }
            $allocated += $items[$i]['cost'];
            $naiveSum  += $items[$i]['value'];
        }
        $joint['remove_findings'] = array_values(array_unique($joint['remove_findings']));
        $removed = $chosen ? max(0.0, $baseline - $p->exposure($joint)) : 0.0;

        // ---- report, including what lost and why
        $selected = [];
        foreach ($chosen as $i) {
            $selected[] = [
                'id'    => $items[$i]['id'],
                'name'  => $items[$i]['name'],
                'cost'  => round($items[$i]['cost'], 2),
                'value' => round($items[$i]['value'], 2),
                'ratio' => round($items[$i]['ratio'], 2),
            ];
        }
        $chosenSet = array_flip($chosen);
        $rejected  = [];
        foreach ($items as $i => $it) {
            if (isset($chosenSet[$i])) {
                continue;
            }
            $reason = !isset($affordable[$i])
                ? 'costs more than the whole budget'
                : ($it['value'] <= 0
                    ? 'removes no exposure the estate actually carries'
                    : 'a better return was available for the same money');
            $rejected[] = [
                'id'     => $it['id'],
                'name'   => $it['name'],
                'cost'   => round($it['cost'], 2),
                'value'  => round($it['value'], 2),
                'ratio'  => is_finite($it['ratio']) ? round($it['ratio'], 2) : null,
                'reason' => $reason,
            ];
        }
        usort($selected, static fn($a, $b) => $b['value'] <=> $a['value']);
        usort($rejected, static fn($a, $b) => $b['value'] <=> $a['value']);

        return [
            'baseline'  => round($baseline, 2),
            'budget'    => round($budget, 2),
            'allocated' => round($allocated, 2),
            'unspent'   => round($budget - $allocated, 2),
            'removed'   => round($removed, 2),
            // How much the individual values overstated the set. Non-zero means
            // the options overlap; it is shown, not hidden.
            'overlap'   => round(max(0.0, $naiveSum - $removed), 2),
            'selected'  => $selected,
            'rejected'  => $rejected,
            'solved_ms' => (int) ((microtime(true) - $t0) * 1000),
        ];
    }

    /**
     * Exposure removed at a range of budgets — the diminishing-returns curve.
     * It answers the budget-request question before it is asked, and it is the
     * argument for NOT asking for more money once the curve flattens.
     */
    public static function curve(Portfolio $p, array $options, array $budgets): array
    {
        $out = [];
        foreach ($budgets as $b) {
            $r = self::solve($p, $options, (float) $b);
            $out[] = [
                'budget'    => (float) $b,
                'removed'   => $r['removed'],
                'allocated' => $r['allocated'],
                'count'     => count($r['selected']),
            ];
        }
        return $out;
    }
}
