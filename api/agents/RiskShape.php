<?php
/**
 * RiskShape — the canonical signature of a finding.
 *
 * Two findings have the same SHAPE when they are the same kind of problem, even
 * on different hosts: a Windows RDP service exposed to the internet on a crown
 * jewel is one shape, whether it is plant-jump-01 or br-office-01.
 *
 * This is the cheap half of reuse and it needs no API at all. Because a finding
 * is structured data — a product, an asset class, an exposure, a control set —
 * a deterministic signature already catches most repeats. Embeddings are for the
 * fuzzy tail, not the common case, and building the common case on a paid third
 * party would have made the whole reuse ladder fail when that key ran dry.
 *
 * Two granularities:
 *   familyKey()  what KIND of problem this is         -> picks the agent
 *   shapeHash()  the same problem in the same setting -> replays an assessment
 */
class RiskShape
{
    /**
     * Product families we recognise by name. Order matters — the first match
     * wins, so more specific entries sit above general ones.
     */
    private const PRODUCTS = [
        'microsoft exchange'    => 'exchange',
        'remote desktop'        => 'rdp',
        'terminal services'     => 'rdp',
        'windows'               => 'windows',
        'fortinet'              => 'fortinet',
        'fortios'               => 'fortinet',
        'citrix'                => 'citrix',
        'vmware vcenter'        => 'vcenter',
        'vmware'                => 'vmware',
        'apache log4j'          => 'log4j',
        'log4j'                 => 'log4j',
        'apache struts'         => 'struts',
        'apache tomcat'         => 'tomcat',
        'apache'                => 'apache',
        'oracle weblogic'       => 'weblogic',
        'oracle'                => 'oracle',
        'sap netweaver'         => 'sap',
        'sap'                   => 'sap',
        'moveit'                => 'moveit',
        'cisco'                 => 'cisco',
        'pulse'                 => 'vpn_appliance',
        'ivanti'                => 'vpn_appliance',
        'linux'                 => 'linux',
    ];

    /** Impact shorthand, from the real CVSS vector. */
    private static function impacts(array $v): string
    {
        $s = '';
        $s .= !empty($v['impact_c']) ? 'c' : '';
        $s .= !empty($v['impact_i']) ? 'i' : '';
        $s .= !empty($v['impact_a']) ? 'a' : '';
        return $s ?: 'none';
    }

    /** Product family, from the vulnerability title and the asset's OS. */
    public static function product(array $v, array $asset): string
    {
        $hay = strtolower(((string) ($v['title'] ?? '')) . ' ' . ((string) ($asset['os'] ?? '')));
        foreach (self::PRODUCTS as $needle => $family) {
            if (str_contains($hay, $needle)) {
                return $family;
            }
        }
        return 'other';
    }

    /** How reachable, in three buckets rather than a continuous number. */
    public static function exposure(array $asset): string
    {
        if (!empty($asset['internet_facing'])) {
            return 'internet';
        }
        return ($asset['environment'] ?? '') === 'ot' ? 'ot' : 'internal';
    }

    /** Severity band, so a 9.8 and a 9.9 do not count as different shapes. */
    public static function band(?float $cvss): string
    {
        if ($cvss === null)  { return 'unrated'; }
        if ($cvss >= 9.0)    { return 'critical'; }
        if ($cvss >= 7.0)    { return 'high'; }
        if ($cvss >= 4.0)    { return 'medium'; }
        return 'low';
    }

    /**
     * What KIND of problem this is — the key an agent is created for.
     * Deliberately coarse: an agent should cover a family of findings, not one.
     */
    public static function familyKey(array $v, array $asset): string
    {
        return implode('|', [
            ($v['source'] ?? 'nvd') === 'config' ? 'config' : 'vuln',
            ($v['source'] ?? '') === 'config'
                ? (string) ($v['local_key'] ?? 'unknown')
                : self::product($v, $asset),
            self::exposure($asset),
        ]);
    }

    /**
     * The same problem in the same setting — the key an assessment is replayed
     * for. Finer than the family: it includes the severity band, what the
     * weakness can hurt, and which controls stand in front of it, because those
     * are exactly the inputs that would change the answer.
     *
     * @param string[] $controlKeys control keys present on the asset
     */
    public static function shapeText(array $v, array $asset, array $controlKeys): string
    {
        sort($controlKeys);
        return implode(' · ', [
            'family=' . self::familyKey($v, $asset),
            'severity=' . self::band($v['cvss_score'] !== null ? (float) $v['cvss_score'] : null),
            'kev=' . (!empty($v['kev_listed']) ? (!empty($v['kev_ransomware']) ? 'ransomware' : 'yes') : 'no'),
            'impacts=' . self::impacts($v),
            'criticality=' . self::criticalityBand((float) ($asset['criticality'] ?? 0.5)),
            'records=' . (((int) ($asset['pii_records'] ?? 0)) > 0 ? 'yes' : 'no'),
            'controls=' . ($controlKeys ? implode('+', $controlKeys) : 'none'),
        ]);
    }

    public static function shapeHash(array $v, array $asset, array $controlKeys): string
    {
        return sha1(self::shapeText($v, $asset, $controlKeys));
    }

    /** Criticality in bands — 0.90 and 0.92 are the same situation. */
    private static function criticalityBand(float $c): string
    {
        if ($c >= 0.85) { return 'crown'; }
        if ($c >= 0.60) { return 'high'; }
        if ($c >= 0.35) { return 'normal'; }
        return 'low';
    }

    /**
     * A human sentence describing the family, for the deriver to name and for
     * dedup to compare. This is the text that gets embedded when embeddings
     * are available.
     */
    public static function describe(array $v, array $asset): string
    {
        $product = self::product($v, $asset);
        $exposure = self::exposure($asset);
        if (($v['source'] ?? '') === 'config') {
            return trim((string) ($v['title'] ?? 'configuration weakness'))
                 . ' on an ' . $exposure . ' ' . strtolower((string) ($asset['asset_class'] ?? 'system'));
        }
        return 'A ' . str_replace('_', ' ', $product) . ' vulnerability on an '
             . $exposure . '-reachable ' . strtolower((string) ($asset['asset_class'] ?? 'system'))
             . ', ' . self::band($v['cvss_score'] !== null ? (float) $v['cvss_score'] : null) . ' severity'
             . (!empty($v['kev_listed']) ? ', known to be exploited in the wild' : '');
    }
}
