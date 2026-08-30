<div align="center">

# SpendShield

**AI-Powered Continuous Cyber Risk Quantification and Investment Optimization**

Smart India Hackathon 2026 · Problem Statement **SIH26105** · Software

*Prices every weakness in your estate in rupees, then spends your security budget
where it removes the most exposure.*

</div>

---

## The problem, in one line

Organizations know **how many** vulnerabilities they have. They cannot say **which
ones cost money**, and they allocate security budget without knowing what any of it buys.

A CISO can produce a list of 1,284 findings sorted by CVSS. A CFO cannot act on that
list, because CVSS is a severity score, not a rupee figure, and it says nothing about
*this* company's systems, *this* company's controls, or *this* company's revenue.

SpendShield closes that gap in three steps:

| | |
|---|---|
| **1 · Price it** | Every finding gets an annualized loss figure in rupees, with a confidence band and the evidence behind it |
| **2 · Rank it** | The risk register sorts by money, not severity — the single default that changes how the tool is used |
| **3 · Spend it** | Give it a budget; it returns the exact set of fixes that removes the most exposure inside that budget, and shows what it rejected and why |

---

## What is real and what is synthetic

This matters more than any feature, and the product should never blur it.

| Data | Source | Real? |
|---|---|---|
| Exploited-in-the-wild status | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | **Real** — 1,685 CVEs, synced live |
| Exploitation probability | [FIRST EPSS](https://www.first.org/epss/) | **Real** — synced live, dated |
| CVSS base score + vector | [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) | **Real** — synced live |
| Ransomware campaign linkage | CISA KEV metadata | **Real** — 352 flagged |
| Asset inventory, revenue, headcount | seeded demo tenant | **Synthetic** |

No public source has a real company's asset inventory, so the estate is invented.
But findings are **not** invented pairings: each asset declares the product it actually
runs, and its findings are drawn from real KEV entries for that product. `mail-01` gets
Exchange CVEs because CISA lists those against Exchange.

---

## How the number is built

### The five-factor score

```
raw_risk = severity × threat_probability × asset_criticality × exposure × control_gap
```

Every factor lands in `[0,1]` and records where it came from, so the finding page can
print its own arithmetic back to whoever questions it.

| Factor | Where it comes from |
|---|---|
| **Severity** | CVSS base score from NVD, divided by 10 |
| **Threat probability** | EPSS, **annualized** — it is a 30-day figure, compounded over `365/30` windows. A KEV listing sets a **floor** (0.70, or 0.85 when CISA links the CVE to ransomware), because CISA has *observed* exploitation and a low EPSS must not talk that down |
| **Asset criticality** | Owned by the customer, edited on the asset page |
| **Exposure** | Internet-facing assets are 1.00. Otherwise the real CVSS attack vector decides: `AV:N` 0.60, `AV:A` 0.40, `AV:L` 0.25, `AV:P` 0.10 |
| **Control gap** | `Π(1 − effectiveness)` over the controls that **can actually touch** this weakness. A WAF gets no credit against an RDP exploit |

**No language model appears anywhere in this path.** A number a CFO acts on must be
deterministic and auditable line by line. The model's job in this product is to *explain*
a score and to fill inputs it can cite — never to produce the score.

### From score to rupees

Loss is valued **per asset**, split into the three channels an attack can hurt:

- **Availability** — `revenue/hour × recovery hours × criticality` + rebuild cost
- **Confidentiality** — `records × cost/record` + statutory penalty (capped)
- **Integrity** — contractual and reputational cost

Channels are switched on by the real CVSS vector (`C:H` / `I:H` / `A:H`), so a
confidentiality-only bug is never charged for production downtime.

### Aggregation — the correction that matters

The obvious implementation charges every finding the full cost of losing its asset and
sums them. **That is wrong.** During development it put ₹201 Cr on one Citrix gateway,
because the model lost the same gateway three times. There is one gateway.

So for each channel:

```
P(channel) = 1 − Π (1 − raw_risk_i)      over findings that hit that channel
ALE(asset) = Σ  P(channel) × loss(channel)
```

Each finding then receives its **share** of the asset total, normalized so the parts sum
exactly to the whole — nobody can add up the findings table and get a different number
from the dashboard.

This assumes findings fail independently. A shared root cause correlates them and the
true probability is lower, so the model **errs toward over-stating** risk. That is
stated rather than buried, because a reader deserves to know which way a model leans.

### Guards learned the hard way

| Guard | Why |
|---|---|
| Control gap floored at **0.05** | EDR 0.71 × WAF 0.69 × backups 0.95 composed to a 99.5% reduction. No security programme on earth stops 99.5% of attacks — real stacks share blind spots |
| PII lives on **specific assets** | Smearing 184,000 records across every asset charged a VPN appliance for 154,000 customer records |
| Penalty fraction kept at **0.25** | A per-record breach benchmark already contains the average fine; charging a full penalty on top counts the same money twice |
| Bands widen as confidence falls | A figure we are unsure of must *look* unsure |

---

## The optimizer

An exact **0/1 knapsack**, solved by dynamic programming at ₹1,000 granularity.

At an ₹18 lakh budget against the demo estate:

```
SELECTED                                          COST      REMOVES   RETURN
Close public object storage                    ₹40,000    ₹40.91 Cr  10,228x
Patch SAP NetWeaver                             ₹1.80 L    ₹5.13 Cr     285x
Patch Exchange to current CU                    ₹1.10 L    ₹4.44 Cr     404x
Patch Oracle WebLogic                           ₹1.50 L    ₹3.74 Cr     249x
Cut the patch SLA 30d → 7d                     ₹12.00 L    ₹2.25 Cr      19x
Patch Citrix ADC                                ₹85,000    ₹2.00 Cr     236x
─────────────────────────────────────────────────────────────────────────────
₹17.65 L allocated  →  ₹56.91 Cr removed  =  93.1% of exposure, in 29ms
```

Three deliberate properties:

- **Options are valued against the live estate**, never estimated. Each runs a real
  counterfactual through `Portfolio` — the same evaluator the dashboard uses. If the
  optimizer kept its own copy of the arithmetic it would eventually disagree with the
  dashboard, and that is the kind of bug that ends a product.
- **Overlap is reported, not hidden.** Two fixes can cover the same finding; their values
  are not additive. The chosen set is re-evaluated *jointly* and that is the headline;
  the gap against the sum of parts is shown.
- **Rejected options come back with reasons** — *"costs more than the whole budget"*,
  *"a better return was available for the same money"*. An optimizer that shows only its
  picks is a black box.

**Why not OR-Tools?** One knapsack, one constraint. DP solves it exactly in
milliseconds, in the language the backend already speaks. A Python sidecar would buy
nothing and cost a second runtime in the deployment. If scheduling constraints ever
appear — change windows, crew availability, dependencies between fixes — that is a
different problem and OR-Tools earns its place then.

---

## Stack

| Layer | Choice |
|---|---|
| Backend | **PHP 8.1**, no framework, flat endpoints under `api/` |
| Database | **MariaDB / MySQL**, 17 tables |
| Frontend | **React 19 + Vite + Tailwind** *(Phase 4)* |
| Models | **OpenRouter**, lane-routed *(Phase 5)* |
| Embeddings | **Jina v3**, DB-cached *(Phase 5)* |
| Scanners | Nmap, OpenVAS, Wazuh via ingestion workers |
| Deploy | Docker + GitHub Actions |

---

## Setup

Requires XAMPP (Apache + MySQL/MariaDB) and PHP 8.1+.

```bash
# 1. credentials
cp api/config/secrets.example.php api/config/secrets.php
#    edit it — DB credentials, and API keys when you reach Phase 5

# 2. database + real threat data (~5 minutes, mostly NVD's rate limit)
bash tools/reset_db.sh
```

Or step by step:

```bash
php tools/install.php --fresh              # database + 17 tables
php api/ingest/sync_feeds.php --kev        # CISA KEV catalog   (~1,700 CVEs, ~1s)
php api/ingest/sync_feeds.php --epss       # EPSS scores        (~20s, 100/request)
php api/ingest/seed_estate.php --reset     # demo tenant, assets, controls, findings
php api/ingest/sync_feeds.php --nvd --limit=45   # CVSS for CVEs in use (~6s each)
php api/ingest/seed_remediations.php --reset     # the optimizer's option catalogue
php api/risk/recompute.php                 # score everything
```

Then:

```bash
php api/risk/recompute.php                 # exposure, top findings, by asset
php api/risk/optimize.php --budget=1800000 # the plan
php api/risk/optimize.php --curve          # what another rupee buys
```

**Demo login:** `awaiz@acme.co.in` / `spendshield-demo` (analyst). Also
`priya@acme.co.in` (owner), `cfo-office@acme.co.in` (executive), `ops@acme.co.in` (viewer).

---

## API

Every endpoint is under `api/v1/` and requires a bearer token from `login.php`.
**There is no dev bypass** — a security product whose API answers unauthenticated
requests "because it's only localhost" is arguing against itself.

| Endpoint | What it returns |
|---|---|
| `POST login.php` | 12-hour bearer token; throttled, timing-safe, no user enumeration |
| `GET dashboard.php` | KPIs, exposure trend with annotations, severity composition, coverage, top findings — one request, because the page is read as one picture |
| `GET findings.php` | Risk register. Filters (severity, exposure, asset, KEV, agent, text), whitelisted sorts, pagination |
| `GET finding.php?id=` | One finding **and the arithmetic behind its money figure** — every factor, its value, its source |
| `GET assets.php[?id=]` | Estate list, or one asset with controls, findings and history |
| `GET controls.php` | Claimed vs observed effectiveness, coverage, and what each control is worth in rupees |
| `GET exposure.php` | Total, band, drivers by channel, every assumption in force |
| `GET optimizer.php?budget=` | The plan, the rejects and why. `&curve=1` for diminishing returns |
| `POST simulate.php` | What-if. Separates movement from **actions** vs movement from **assumptions** |
| `GET monitor.php` | Feed health as *consequence* not status, alerts in money, activity log |

### Roles

| Role | Can |
|---|---|
| **owner** | Everything, including billing, integrations, role changes |
| **executive** | Dashboard, exposure, optimizer, reports. **Not** raw findings |
| **analyst** | Full technical access within scope; can accept risk with an expiry |
| **viewer** | Read-only within scope; no export, no risk acceptance |

Verified: an executive token on `findings.php` returns **403**; on `exposure.php`, **200**.

---

## Tests

No framework. Plain PHP scripts that assert and exit non-zero.

```bash
php tests/risk_engine_test.php   # 27 checks — factors, floors, loss model, aggregation
php tests/optimizer_test.php     # 19 checks — knapsack, counterfactuals, overlap, curve
```

Every regression in the "guards" table above has a test, including *"three findings must
not cost three times one"* and *"a WAF gets no credit against an RDP exploit"*.

---

## Layout

```
api/
  schema.sql              the whole schema, one file
  config/db.php           PDO connection
  config/secrets.php      real credentials — GITIGNORED
  ingest/
    sync_feeds.php        KEV / EPSS / NVD sync
    seed_estate.php       demo tenant
    seed_remediations.php the optimizer's option catalogue
  risk/
    RiskEngine.php        the five factors — deterministic, no model call
    LossModel.php         per-asset loss by impact channel
    Aggregator.php        combine findings without double counting
    Portfolio.php         the estate in memory + "what if" evaluation
    Optimizer.php         0/1 knapsack DP
    Remediations.php      stored rows -> optimizer options
    recompute.php         CLI: score everything
    optimize.php          CLI: solve a budget
  v1/                     the JSON API
tests/                    self-checks
tools/install.php         database installer
tools/reset_db.sh         full rebuild
```

---

## Phases

- [x] **1 · Database** — schema, real threat feeds, seeded estate
- [x] **2 · Risk engine** — five-factor score, loss model, per-asset aggregation, bands
- [x] **3 · Optimizer + API** — knapsack, counterfactual portfolio, 10 endpoints, auth
- [ ] **4 · Frontend** — React app across 22 routes
- [ ] **5 · Agent layer** — registry, reuse ladder, learning loops, AI copilot

### Phase 5 — the agent architecture

An **agent is a database row, not a process**: a stored capability with a model, a
template, a learned retrieval policy and a quality score. Specialists build themselves
per risk family (`risk.exposed_rdp`, `risk.cloud_storage`), get deduplicated at a
calibrated similarity threshold, are graded on six quality bundles, and are retired
automatically when they underperform.

Reuse runs three depths, cheapest first — exact cache, then semantic warehouse
(equivalent finding already assessed), then knowledge store (same CVE topic, different
asset → reuse the evidence, skip the paid intel fetch). The second identical finding
costs **₹0** to assess.

---

## Known limitations

Stated because a risk tool that hides its own uncertainty has no business asking for
anyone's trust.

- **Independence assumption.** Findings on one asset are treated as independent attack
  paths. Shared root causes correlate them; the model over-states rather than under-states.
- **The estate is synthetic.** Vulnerability data is real; hostnames, revenue and record
  counts are invented for the demo tenant.
- **Config weaknesses have no EPSS**, so their threat probability uses a severity-scaled
  prior. A world-readable bucket is found by scanners faster than that prior suggests.
- **Loss model constants are seeded**, not audited. `cost_per_record` is anchored to
  published India breach benchmarks; every customer replaces these with their own figures.
- **Control effectiveness is seeded** in the demo. The learning loop that decays it from
  real Wazuh detections lands with the agent layer.

---

<div align="center">
<sub>Team <b>Elite Developers</b> · Smart India Hackathon 2026</sub>
</div>
