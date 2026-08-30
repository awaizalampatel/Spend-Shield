<?php
/**
 * Remediations — turns stored remediation rows into optimizer options.
 *
 * A remediation says what it CHANGES, not what it is worth. Its worth is
 * computed against the live estate every time (Optimizer values it through
 * Portfolio), so an option's value falls automatically as the findings it
 * covers get fixed by something else. Nothing here caches a rupee figure.
 */
class Remediations
{
    /**
     * @return array<int,array{id:int,name:string,cost:float,effect:array,meta:array}>
     */
    public static function catalog(PDO $pdo, int $tenantId): array
    {
        $rows = $pdo->prepare(
            "SELECT r.*, GROUP_CONCAT(rf.finding_id) AS finding_ids
               FROM remediations r
          LEFT JOIN remediation_findings rf ON rf.remediation_id = r.id
              WHERE r.tenant_id = ? AND r.status <> 'done'
           GROUP BY r.id
           ORDER BY r.cost_inr ASC"
        );
        $rows->execute([$tenantId]);

        // Which assets each remediation touches — needed when it deploys a control.
        $assetsFor = [];
        $aq = $pdo->prepare(
            "SELECT rf.remediation_id, f.asset_id
               FROM remediation_findings rf
               JOIN findings f ON f.id = rf.finding_id
              WHERE f.tenant_id = ?
           GROUP BY rf.remediation_id, f.asset_id"
        );
        $aq->execute([$tenantId]);
        foreach ($aq as $r) {
            $assetsFor[(int) $r['remediation_id']][] = (int) $r['asset_id'];
        }

        $out = [];
        foreach ($rows as $r) {
            $id = (int) $r['id'];
            $findingIds = $r['finding_ids']
                ? array_map('intval', explode(',', (string) $r['finding_ids']))
                : [];

            $effect = ['remove_findings' => [], 'control_effectiveness' => [], 'add_control_to' => []];

            if ((int) $r['eliminates'] === 1) {
                // A patch or a config fix: the finding stops existing.
                $effect['remove_findings'] = $findingIds;
            }
            if ($r['control_key'] !== null && $r['effectiveness_target'] !== null) {
                // A control gets better, and reaches the assets this covers.
                $effect['control_effectiveness'][$r['control_key']] = (float) $r['effectiveness_target'];
                $effect['add_control_to'][$r['control_key']] = $assetsFor[$id] ?? [];
            }

            $out[] = [
                'id'     => $id,
                'name'   => (string) $r['name'],
                'cost'   => (float) $r['cost_inr'],
                'effect' => $effect,
                'meta'   => [
                    'description'  => (string) ($r['description'] ?? ''),
                    'effort_days'  => (int) $r['effort_days'],
                    'control_key'  => $r['control_key'],
                    'covers'       => count($findingIds),
                    'finding_ids'  => $findingIds,
                    'status'       => (string) $r['status'],
                ],
            ];
        }
        return $out;
    }
}
