<?php
/**
 * Aggregator — combines many findings on one asset into one expected loss,
 * then hands each finding back its fair share.
 *
 * The naive sum double-counts: three ways into the same server is not three
 * servers. For each impact channel we take the probability that AT LEAST ONE
 * finding lands, assuming the attempts are independent:
 *
 *     P(channel) = 1 − Π (1 − raw_risk_i)      over findings that hit that channel
 *     ALE(asset) = Σ  P(channel) × loss(channel)
 *
 * That is the standard independence model. It is an assumption — a shared root
 * cause (one unpatched OS behind five findings) correlates them and the true
 * probability is lower — and it is stated here rather than buried, because it
 * errs toward over-stating risk and a reader deserves to know which way a model
 * leans.
 *
 * Attribution: each finding's share is its marginal contribution to the asset
 * total, normalized so the parts sum exactly to the whole. Nobody can add up a
 * findings table and get a different number from the dashboard.
 */
class Aggregator
{
    public const CHANNELS = ['availability', 'confidentiality', 'integrity'];

    /**
     * @param array $findings each: ['id'=>int, 'raw_risk'=>float, 'channels'=>['availability'=>bool,…]]
     * @param array $loss     LossModel::channels() output for this asset
     * @return array{asset_ale:float, per_finding:array<int,float>, channel:array}
     */
    public static function forAsset(array $findings, array $loss): array
    {
        $channelP   = [];
        $assetAle   = 0.0;
        $channelAle = [];

        foreach (self::CHANNELS as $ch) {
            $survive = 1.0;                       // P(nothing lands on this channel)
            foreach ($findings as $f) {
                if (!empty($f['channels'][$ch])) {
                    $survive *= (1 - max(0.0, min(1.0, (float) $f['raw_risk'])));
                }
            }
            $p = 1 - $survive;
            $channelP[$ch]   = $p;
            $channelAle[$ch] = $p * (float) ($loss[$ch] ?? 0);
            $assetAle       += $channelAle[$ch];
        }

        // Weight each finding by the loss it can reach, times how likely it is.
        $weights = [];
        $sum = 0.0;
        foreach ($findings as $f) {
            $w = 0.0;
            foreach (self::CHANNELS as $ch) {
                if (!empty($f['channels'][$ch])) {
                    $w += (float) $f['raw_risk'] * (float) ($loss[$ch] ?? 0);
                }
            }
            $weights[$f['id']] = $w;
            $sum += $w;
        }

        $per = [];
        foreach ($weights as $id => $w) {
            $per[$id] = $sum > 0 ? round($assetAle * ($w / $sum), 2) : 0.0;
        }

        // Rounding must not lose or invent rupees: push the remainder onto the
        // largest share, so Σ per-finding == asset ALE exactly.
        if ($per) {
            $drift = round($assetAle, 2) - array_sum($per);
            if (abs($drift) >= 0.01) {
                $biggest = array_keys($per, max($per))[0];
                $per[$biggest] = round($per[$biggest] + $drift, 2);
            }
        }

        return [
            'asset_ale'   => round($assetAle, 2),
            'per_finding' => $per,
            'channel'     => ['p' => $channelP, 'ale' => $channelAle],
        ];
    }
}
