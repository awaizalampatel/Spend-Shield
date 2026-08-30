# Threshold calibration

Similarity thresholds are **measured, not inherited**. A number copied from
another project is a number nobody has checked against this domain's text.

## Agent dedup — `MERGE_SIM`

Two agents doing the same job must merge onto one row, or the registry fills with
twins (`risk.exposed_rdp`, `risk.open_remote_desktop`, `risk.rdp_internet_facing`)
each carrying a diluted quality score.

Dedup compares an agent's **name + description**, embedded with
`jina-embeddings-v3` (`retrieval.passage`, 1024 dims), by cosine similarity.

### First measurement — 30 Aug 2026

Six hand-written agent descriptions in this domain: three phrasings of the same
RDP-exposure job, plus three genuinely different jobs.

| Pair | Cosine | |
|---|---|---|
| RDP-a ↔ RDP-c | 0.6733 | twin |
| RDP-a ↔ RDP-b | 0.6291 | twin |
| RDP-b ↔ RDP-c | 0.5319 | twin — **worst twin** |
| RDP-a ↔ mail | 0.4506 | **closest non-twin** |
| bucket ↔ mail | 0.3831 | distinct |
| RDP-a ↔ OT-seg | 0.3625 | distinct |
| RDP-a ↔ bucket | 0.3025 | distinct |
| OT-seg ↔ mail | 0.2693 | distinct |
| bucket ↔ OT-seg | 0.1688 | distinct |

**Twins: 0.53 – 0.67. Non-twins: at most 0.45.** A clean gap sits between them.

### Consequence

soundd.ai uses `MERGE_SIM = 0.80`, calibrated there on 903 live pairs of its own
agent text. **Carried over unchanged, it would catch none of the duplicates above** —
the worst twin here scores 0.5319, nowhere near 0.80.

This is the same failure soundd.ai already had once and documented: its earlier
0.90 threshold "caught 0 of 13 known duplicates" and `findSimilarAgent` embedded the
whole roster on every creation only to always return null. Inheriting a stranger's
threshold reproduces the bug rather than the fix.

Risk-family descriptions are shorter and more formulaic than conversational task
descriptions, so their vectors spread differently. Same model, same metric,
different distribution.

### Starting value

```
MERGE_SIM = 0.50
```

Above the closest non-twin (0.4506) with a small margin, below the worst twin
(0.5319). Deliberately closer to the non-twin edge: a missed merge costs one
redundant agent row, while a wrong merge destroys a real specialist's history.

### Before trusting it

Six hand-written samples is a starting point, **not a calibration**. Re-measure on
real agent rows once the registry has traffic — soundd.ai used 903 live pairs —
and move the constant with the evidence recorded here.

## Assessment reuse — thresholds still to measure

The reuse ladder needs two more, and neither should be copied either:

| Threshold | Purpose | Status |
|---|---|---|
| answer replay | equivalent finding already assessed → replay the assessment | **not yet measured** |
| topic grouping | same CVE, different asset → reuse the evidence, skip the intel fetch | **not yet measured** |

soundd.ai's values (0.80 and 0.62) are recorded here only as a reminder that they
exist, not as defaults to adopt.
