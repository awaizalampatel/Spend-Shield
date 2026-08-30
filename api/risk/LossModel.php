<?php
/**
 * LossModel — what a loss event costs, per asset, per impact channel.
 *
 * THE CORRECTION THAT MATTERS. The obvious implementation charges every finding
 * the full cost of losing its asset and sums them. That is wrong, and badly:
 * citrix-gw-01 carried three findings and came out at ₹201 Cr, because the model
 * lost the same gateway three times. There is one gateway. It can be lost once.
 *
 * So loss is valued PER ASSET, split into the three channels an attack can hurt:
 *
 *   availability     production stops · revenue/hour × recovery hours + rebuild
 *   confidentiality  records leave · records × cost/record + regulatory penalty
 *   integrity        contracts, customers, the next tender
 *
 * A finding's money figure is then its share of its asset's expected loss, not a
 * loss of its own — see Aggregator. Channels are switched on by the real CVSS
 * vector (C:H / I:H / A:H), so a confidentiality-only bug is never charged for
 * downtime and an availability bug is never charged a data-protection penalty.
 */
class LossModel
{
    /**
     * Statutory penalty, as a fraction of the record-loss value and bounded by
     * the cap in the tenant's model (₹250 Cr under the DPDP Act 2023).
     *
     * Kept low on purpose: a per-record breach benchmark ALREADY contains the
     * average regulatory fine, so charging a full penalty on top counts the same
     * money twice. This fraction stands only for the INCREMENTAL Indian statutory
     * exposure that an international average does not carry.
     */
    private const PENALTY_FRACTION = 0.25;

    /**
     * What one full loss event costs this asset, per channel.
     *
     * @return array{availability:float, confidentiality:float, integrity:float, detail:array}
     */
    public static function channels(array $asset, array $model): array
    {
        $crit = max(0.0, min(1.0, (float) $asset['criticality']));

        // --- availability
        $perHour  = $asset['revenue_per_hour'] !== null
            ? (float) $asset['revenue_per_hour']
            : (float) $model['revenue_per_hour'];
        $hours    = (float) $model['median_recovery_hours'];
        $downtime = $perHour * $hours * $crit;
        $rebuild  = (float) $model['ransom_recovery_cost'] * $crit;

        // --- confidentiality. Only systems that actually hold records carry
        //     record loss. A VPN appliance holds none, and charging it for
        //     184,000 customer records is how a model produces a number nobody
        //     believes.
        $records    = (int) ($asset['pii_records'] ?? 0);
        $recordLoss = $records * (float) $model['cost_per_record'];
        $penalty    = min((float) $model['penalty_cap'], $recordLoss * self::PENALTY_FRACTION);

        // --- integrity
        $reputational = (float) $model['reputational_cost'] * $crit;

        return [
            'availability'    => round($downtime + $rebuild, 2),
            'confidentiality' => round($recordLoss + $penalty, 2),
            'integrity'       => round($reputational, 2),
            'detail' => [
                'downtime'        => round($downtime, 2),
                'rebuild'         => round($rebuild, 2),
                'records_at_risk' => $records,
                'record_loss'     => round($recordLoss, 2),
                'penalty'         => round($penalty, 2),
                'reputational'    => round($reputational, 2),
                'revenue_per_hour'=> $perHour,
                'recovery_hours'  => $hours,
            ],
        ];
    }

    /**
     * Band around a point estimate. A figure we are unsure of must LOOK unsure —
     * the band is shown next to the number everywhere it appears.
     */
    public static function band(float $ale, float $confidence): array
    {
        $k = 1.25 + 1.25 * (1 - max(0.0, min(1.0, $confidence)));
        return ['min' => round($ale / $k, 2), 'max' => round($ale * $k, 2)];
    }
}
