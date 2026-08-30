<?php
/**
 * RiskEngine — the five-factor score.
 *
 *   raw_risk = severity × threat_probability × asset_criticality × exposure × control_gap
 *
 * This is deliberately PLAIN PHP with no model call anywhere in it. The number a
 * CFO acts on has to be deterministic (same inputs, same output, every time) and
 * auditable line by line, which an LLM cannot promise. The language model's job
 * in this product is to explain a score and to fill inputs it can cite — never to
 * produce the score itself.
 *
 * Every factor lands in [0,1] and every one records where it came from, so
 * /findings/:id can print the arithmetic back to the person questioning it.
 */
class RiskEngine
{
    /** EPSS is a 30-day probability; risk is annualized. 365/30 windows. */
    private const EPSS_WINDOWS_PER_YEAR = 365 / 30;

    /**
     * Floors for the KEV catalog. A CVE on the KEV list is not a prediction —
     * CISA has observed it being exploited against real targets. Whatever EPSS
     * says, the probability of someone trying it against an exposed host in a
     * year is not low, so the listing sets a floor rather than a value.
     */
    private const KEV_FLOOR             = 0.70;
    private const KEV_RANSOMWARE_FLOOR  = 0.85;

    /** No EPSS (config weaknesses have no CVE): fall back to a weak severity prior. */
    private const NO_EPSS_PRIOR = 0.45;

    /**
     * Floor on the residual gap. Multiplying independent controls together is the
     * right shape but it gets generous fast: EDR 0.71 × WAF 0.69 × backups 0.95
     * composes to a 99.5% reduction, and no security programme on earth stops
     * 99.5% of attacks on an internet-reachable ERP. Real stacks share blind
     * spots — same admins, same identity provider, same missed patch. So no
     * stack is trusted below a 5% residual, whatever the arithmetic says.
     */
    private const MIN_CONTROL_GAP = 0.05;

    /**
     * Reachability by CVSS attack vector, for an asset that is NOT internet-facing.
     * An internet-facing asset is 1.0 regardless — it is already reachable.
     */
    private const AV_EXPOSURE = ['N' => 0.60, 'A' => 0.40, 'L' => 0.25, 'P' => 0.10];

    /**
     * Which controls can plausibly reduce which kind of weakness. A control that
     * cannot touch a weakness must not be allowed to reduce its score — that is
     * how a security programme talks itself into a low number.
     */
    private const CONTROL_APPLIES = [
        'mfa'          => ['auth'],
        'edr'          => ['rce', 'malware', 'privesc'],
        'segmentation' => ['network'],
        'waf'          => ['web'],
        'backup'       => ['availability'],
        'patch'        => ['patchable'],
    ];

    /**
     * Score one finding.
     *
     * @param array $v vulnerability row  (cvss_score, cvss_vector, epss_score, kev_*, source)
     * @param array $a asset row          (criticality, internet_facing, environment)
     * @param array $controls  [control_key => ['effectiveness'=>float,'observed'=>bool], …]
     *                         only the controls actually present on this asset
     * @return array factors + raw_risk + confidence + per-factor provenance
     */
    public static function score(array $v, array $a, array $controls): array
    {
        $vector = (string) ($v['cvss_vector'] ?? '');
        $tags   = self::tags($v, $vector);

        // 1 — SEVERITY. CVSS base, straight off NVD.
        $cvss = $v['cvss_score'] !== null ? (float) $v['cvss_score'] : 5.0;
        $severity = self::clamp($cvss / 10);

        // 2 — THREAT PROBABILITY, annualized.
        [$threat, $threatWhy] = self::threatProbability($v);

        // 3 — ASSET CRITICALITY. Owned by the customer, edited on the asset page.
        $criticality = self::clamp((float) ($a['criticality'] ?? 0.5));

        // 4 — EXPOSURE. Internet-facing is already reachable; otherwise the CVSS
        //     attack vector says how close an attacker must get.
        if (!empty($a['internet_facing'])) {
            $exposure = 1.00;
            $exposureWhy = 'internet-facing asset';
        } else {
            $av = self::vectorPart($vector, 'AV') ?: 'N';
            $exposure = self::AV_EXPOSURE[$av] ?? 0.50;
            $exposureWhy = 'internal asset, CVSS attack vector AV:' . $av;
        }

        // 5 — CONTROL GAP. Independent controls compose multiplicatively:
        //     gap = Π(1 − effectiveness) over the controls that actually apply.
        //     Assumption: controls fail independently. It is the standard
        //     defence-in-depth model and it is stated, not hidden.
        $gap = 1.0;
        $applied = [];
        foreach ($controls as $key => $c) {
            $covers = self::CONTROL_APPLIES[$key] ?? [];
            if (!array_intersect($covers, $tags)) {
                continue;                       // cannot touch this weakness
            }
            $e = self::clamp((float) $c['effectiveness']);
            $gap *= (1 - $e);
            $applied[] = $key . ' ' . number_format($e, 2) . ($c['observed'] ? ' (observed)' : ' (claimed)');
        }
        $controlGap = $applied ? max(self::MIN_CONTROL_GAP, self::clamp($gap)) : 1.0;

        $raw = $severity * $threat * $criticality * $exposure * $controlGap;

        return [
            'severity_factor'    => round($severity, 4),
            'threat_probability' => round($threat, 4),
            'asset_criticality'  => round($criticality, 4),
            'exposure_factor'    => round($exposure, 4),
            'control_gap'        => round($controlGap, 4),
            'raw_risk'           => round($raw, 6),
            'confidence'         => round(self::confidence($v, $controls), 3),
            'tags'               => $tags,
            'why' => [
                'severity'    => $v['cvss_score'] !== null
                                    ? 'CVSS ' . $v['cvss_version'] . ' base ' . $v['cvss_score'] . ' (NVD)'
                                    : 'no CVSS published, assumed 5.0',
                'threat'      => $threatWhy,
                'criticality' => 'asset criticality set by the customer',
                'exposure'    => $exposureWhy,
                'controls'    => $applied ? implode(', ', $applied) : 'no applicable control on this asset',
            ],
        ];
    }

    /**
     * Annualized probability that this weakness is exploited against a reachable host.
     * @return array{0:float,1:string} value + the sentence explaining it
     */
    private static function threatProbability(array $v): array
    {
        $kev  = !empty($v['kev_listed']);
        $ran  = !empty($v['kev_ransomware']);
        $epss = $v['epss_score'] !== null ? (float) $v['epss_score'] : null;

        if ($epss !== null) {
            // EPSS is P(exploited in the next 30 days). Compound to a year.
            $p = 1 - pow(max(0.0, 1 - $epss), self::EPSS_WINDOWS_PER_YEAR);
            $why = 'EPSS ' . rtrim(rtrim(number_format($epss, 5, '.', ''), '0'), '.')
                 . ' (30-day) annualized to ' . number_format($p, 3)
                 . ' · as of ' . ($v['epss_asof'] ?? 'unknown');
        } else {
            $p = self::NO_EPSS_PRIOR * (($v['cvss_score'] ?? 5.0) / 10);
            $why = 'no EPSS for a configuration weakness — severity-scaled prior';
        }

        if ($ran && $p < self::KEV_RANSOMWARE_FLOOR) {
            $p = self::KEV_RANSOMWARE_FLOOR;
            $why .= ' · raised to the ransomware floor (CISA links this CVE to ransomware campaigns)';
        } elseif ($kev && $p < self::KEV_FLOOR) {
            $p = self::KEV_FLOOR;
            $why .= ' · raised to the KEV floor (CISA has observed exploitation in the wild)';
        }

        return [self::clamp($p), $why];
    }

    /**
     * What kind of weakness this is, so only the controls that could actually
     * stop it are allowed to reduce the score. Read off the real CVSS vector
     * plus the KEV metadata we already hold.
     */
    private static function tags(array $v, string $vector): array
    {
        $t = [];
        $text = strtolower(((string) ($v['title'] ?? '')) . ' ' . ((string) ($v['description'] ?? ''))
              . ' ' . ((string) ($v['local_key'] ?? '')));

        if (self::vectorPart($vector, 'AV') === 'N' || self::vectorPart($vector, 'AV') === 'A') {
            $t[] = 'network';
        }
        if (self::vectorPart($vector, 'A') === 'H' || !empty($v['kev_ransomware'])) {
            $t[] = 'availability';
        }
        if (str_contains($text, 'remote code execution') || str_contains($text, 'code execution')
            || str_contains($text, 'deserializ') || str_contains($text, 'injection')) {
            $t[] = 'rce';
        }
        if (str_contains($text, 'privilege') || self::vectorPart($vector, 'PR') === 'N') {
            $t[] = 'privesc';
        }
        if (str_contains($text, 'authentication') || str_contains($text, 'credential')
            || str_contains($text, 'mfa') || str_contains($text, 'remote desktop')
            || str_contains($text, 'vpn') || str_contains($text, 'login')) {
            $t[] = 'auth';
        }
        if (str_contains($text, 'http') || str_contains($text, 'web') || str_contains($text, 'tls')
            || str_contains($text, 'server') && str_contains($text, 'apache')) {
            $t[] = 'web';
        }
        if (!empty($v['kev_ransomware']) || str_contains($text, 'ransomware') || str_contains($text, 'malware')) {
            $t[] = 'malware';
        }
        // Anything with a published CVE has a vendor fix path; a config weakness does not.
        if (($v['source'] ?? 'nvd') === 'nvd') {
            $t[] = 'patchable';
        }
        return array_values(array_unique($t));
    }

    /**
     * How much we trust this row. Drives the width of the money band — a figure
     * we are unsure of must LOOK unsure, not just be unsure.
     */
    private static function confidence(array $v, array $controls): float
    {
        $c = 0.50;
        if ($v['epss_score'] !== null)          { $c += 0.20; }
        if (!empty($v['kev_listed']))           { $c += 0.15; }
        if (!empty($v['cvss_vector']))          { $c += 0.10; }
        foreach ($controls as $ctl) {
            if (!empty($ctl['observed'])) { $c += 0.05; break; }
        }
        return min(0.95, $c);
    }

    /** Pull one metric out of a CVSS vector string, e.g. AV from CVSS:3.1/AV:N/AC:L/… */
    private static function vectorPart(string $vector, string $key): ?string
    {
        if ($vector === '') {
            return null;
        }
        foreach (explode('/', $vector) as $part) {
            $kv = explode(':', $part, 2);
            if (count($kv) === 2 && $kv[0] === $key) {
                return $kv[1];
            }
        }
        return null;
    }

    private static function clamp(float $x): float
    {
        return max(0.0, min(1.0, $x));
    }
}
