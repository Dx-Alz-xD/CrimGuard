# CrimGuard risk formula (v2)

`crimguard/risk/` turns a user's daily feature snapshots (the 100 variables in
`database/crimguard/05_feature_catalog.sql`) into a 0–100 risk score, a level, a
scenario and a per-feature explanation. The output matches the `risk_scores` table. It is
plain Node.js with no dependencies.

```bash
node crimguard/risk/demo.js                           # the deck's Case A and Case B, plus false-positive rates
node --test test/crimguard/                           # tests for the formula
```

## From the deck formula to v2

The pitch deck used:

```
risk_score = deviation_score × sensitivity_weight × (1 − context_match_confidence)
```

v2 keeps that shape, but works out each term more carefully and adds what production UEBA
tools add around it:

| Deck term | Problem | v2 |
| --- | --- | --- |
| `deviation_score` (z-score) | Unbounded (a 40× spike gives z = 127). Mean and σ are pulled around by the outliers they're meant to catch. The same z means different things at 3 files and 3,000. Blind to slow creep (Case B). | Robust baseline (median/MAD) on a variance-stabilised scale, corrected for small samples, shrunk towards peers for new users, plus an anchored drift detector. Mapped to an anomaly strength **A ∈ [0, 1]**. |
| `sensitivity_weight` (1–5) | Only one kind of weight: every signal counts the same. | Split into **impact I** (data value, 1–5 ÷ 5, plus blast radius for privileged accounts) and **signal weight W** (how strongly this kind of signal indicates insider risk). This is Splunk RBA's impact × confidence. |
| `context_match_confidence` | One number, with no rule for computing it. | **C** = reliability × timing × scope × proportionality of the best ledger item, capped at 0.9. |
| — | One feature at a time. | Categories combined with noisy-OR, collect → stage → exfiltrate sequences, an optional Isolation Forest score, risk that builds over two weeks, HR amplifier, honeytoken and anti-forensics floors. |

## The formula

For user *u* on day *t*, for every indicator feature *f* in the catalog with a value that day:

```
r_f = W_f × I_f × A_f × (1 − C_f)                     each factor in [0, 1], so r_f ∈ [0, 1]
```

Then for the day:

```
r̃_f   = max( r_f,  max over the last 14 days of  r_f(past) × 2^(−age / 3) )
R_c   = 1 − Π_i (1 − r̃_(i) × 0.5^(i−1))                  per category, strongest first
R     = 1 − Π_c (1 − R_c)                                 over categories, sequence and Isolation Forest
R'    = 1 − (1 − R)^H                                     H ∈ [1, 2], HR amplifier
score = max(100 × R', floor)
```

Levels: **low** < 40 ≤ **medium** < 70 ≤ **high** < 90 ≤ **critical**. These match the
`response_policies` examples: step-up MFA at 70, freeze the session at 90.

### 1. Baseline and z-score (per numeric feature)

1. **Transform** so one threshold fits every scale:
   counts `y = 2√(x + 3/8)` (Anscombe; Poisson counts get σ ≈ 1),
   MB `y = ln(1 + x/10)`, seconds `y = ln(1 + x/60)` (Tukey's started log),
   ratios and scores unchanged.
2. **Self baseline** over the previous 30 days: median *m* and robust spread
   *s = 1.4826 · MAD* (or 1.2533 · mean absolute deviation when MAD = 0). The spread is never
   below a floor (1 for counts, ±22% for MB and seconds, 10% of the median for ratios and scores).
3. **Peer shrinkage** (empirical Bayes). With *n* days of own history and a peer group (the
   same role), `m = λ·m_self + (1−λ)·m_peer`, `s = λ·s_self + (1−λ)·s_peer`, `λ = n / (n + 10)`.
   A new user is judged against peers; after about 10 days their own history counts equally.
   With fewer than 7 days and no peers, the detector abstains.
4. **z** = (y − m) / s, keeping only the tail the catalog marks as suspicious
   (`anomaly_direction`).
5. **Small-sample correction.** A MAD from *n* days is as precise as a standard deviation from
   0.37·*n* days. So z is read as Student's t with ν = 0.37·n − 1 and turned into the normal z with
   the same tail probability. In calibration this step took ordinary users from 3 high-risk days
   in 1,105 to none (see below).

**Peer detector.** The same z against the peer group alone, capped at half strength: some
people are always busier than their team.

**Drift detector (Case B).** A rolling baseline gradually absorbs slow creep, so v2 also compares
against an **anchored** reference window (default: 180 to 90 days ago; set
`subject.anchorPeriod` to freeze one):

```
CUSUM   S = max(0, S + z_day − 0.5)  over the last 28 days   (Page; k = 0.5σ, h = 5σ)
level   z_level = z of the last 14 days' median vs the anchor
z_drift = min( θ × S / 5,  z_level )
```

CUSUM shows the shift is sustained and z_level shows it is large. Using the smaller of the two
means neither a sustained +10% nor a single spike counts as drift.

### 2. Anomaly strength A

```
A = 1 − 2^(−u²),   u = (z − 1.5) / (θ_f − 1.5)      (A = 0 for z ≤ 1.5)
```

θ_f is the catalog's `default_z_threshold` (2.6 for exfiltration-adjacent features, 3.0
elsewhere), overridable per org. A is 0.5 exactly at the threshold, 0.16 halfway to it, and 0.94
one threshold-width above. A_f is the largest of the self, peer (capped at 0.5) and drift
strengths, and the detector that produced it is reported.

**Flags.** Beta-smoothed rate over 90 days, `p = (hits + 4·p₀) / (days + 4)`, with p₀ the peer
rate (or 5%). Then z = Φ⁻¹(1 − p) and θ = 2.326, the z of a 1-in-100 event. A first-ever weekend
login is strong evidence; for someone who works most weekends it is nothing.

### 3. Signal weight W and impact I

- **W** (`params.js`): data movement 1.0, access and privilege 0.9, authentication and device
  0.8, communication 0.7, biometrics and physical 0.6, temporal 0.5. Strong precursors
  (compression before transfer, personal cloud, USB, audit log tampering, impossible travel,
  token reuse, auto-forward rules, access with no ticket) are 1.0. Noisy ones (app switching,
  message volume) are 0.3–0.4. `org_feature_settings.weight` overrides W.
- **I** = asset weight ÷ 5, using the deck's 1–5 scale: `resources.criticality_weight`, or
  sensitivity public 1, internal 2, confidential 4, restricted 5. The engine uses the highest
  weight touched that day, or per feature via `featureAssetWeights`. Privileged accounts get
  +0.2 on authentication, device and privilege signals (blast radius).

### 4. Context confidence C

For each ledger item that covers the feature (tickets: access, data movement, temporal and
privilege; projects: access, data movement, temporal and communication; role changes: everything):

```
c = reliability × timing × scope × proportion
C = min(0.9, max over items of c)          C = 0 for features with context_explainable = false
```

| Factor | Value |
| --- | --- |
| reliability | approved ticket 1.0, unapproved ticket 0.7, project 0.7, role change 0.6; snapshot mitigator flag with no details 0.3 |
| timing | 0 if the activity is more than 1 day before the assignment (back-dated justification) or the ticket is cancelled; 1 while active; halves every 3 days after close or due date. Role changes halve every 30 days and stop after 90. |
| scope | share of touched resources in `ticket_resource_scope` or the role's entitlements; 0.7 if unknown |
| proportion | ρ = observed / expected (`expected_daily_file_volume`, or `expected_access_multiplier` × baseline median). 1 if ρ ≤ 1.25, else (1.25 / ρ)². So 2× expected gives 0.39, 5× gives 0.06. Unknown: 0.6. Flags: 1. |

The 0.9 cap means a ticket never fully erases risk: it could be cover. The best single item is
used, because two weak excuses don't add up to one strong one.

### 5. Combining evidence

- **Within a category** features are correlated (a bulk copy raises files, MB and confidential
  hits together), so the 2nd strongest counts ×0.5, the 3rd ×0.25, and so on.
- **Across categories** evidence is treated as independent: noisy-OR, `1 − Π(1 − R_c)`.
- **Exfiltration sequence.** The stages are collection (bulk or confidential access, downloads),
  staging (compression, renaming, clipboard bursts) and exfiltration (upload, USB, personal
  cloud, share links, email attachments, printing). When 2 or 3 stages reach strength 0.5 on
  the same day, the day gets an extra `0.9 × I_max × (1 − C_min) × (stages − 1) / 2`.
- **Isolation Forest** (optional input `isolationForestScore`, Liu et al.'s score in [0, 1]):
  `A = 1 − 2^(−(s − 0.55)/0.1)` above 0.55, then `0.6 × I_max × A × (1 − C_min)`.
- **Over time.** Each feature keeps its strongest recent risk, decayed with a 3-day half-life
  (79% the next day, 20% after a week, dropped after 14 days). A sustained anomaly counts once;
  different signals on different days add up. Each result's `carry` holds the values later
  days need.

### 6. HR amplifier H and floors

`H = 1 + min(1, Σ boosts)`, applied as `R' = 1 − (1 − R)^H`. Stressors raise existing risk but
can't create it: R = 0 stays 0.

| Stressor (dated HR timeline) | Boost |
| --- | --- |
| Termination or resignation date within 30 days, or already past | 0.6 (ramps from 0 at 90 days out) |
| Disciplinary action | 0.35, halving every 45 days, stops at 180 |
| Negative performance review | 0.3, same decay |
| PTO dump (≥ 80% of the balance, ≥ 5 days) | 0.25, halving every 30 days |
| Negative compensation change | 0.2, halving every 45 days |
| Manager change | 0.1, halving every 30 days |
| Contractor or temp | 0.1 |
| Hired within 90 days | 0.05 |

Without a dated timeline, the snapshot's `hr_org_context` flags are used at the undecayed values.

Floors: a honeytoken trip is **100** (critical, `honeytoken_trip`), whatever the context. Audit
log modification and session token reuse are at least **70**.

### 7. Explanation

`−ln(1 − R)` equals the sum of every piece's `−ln(1 − r)` (including the within-category
discounts), and H multiplies them all equally. So each feature's **points** are its exact share
of the final score, and they add up to it. `feature_contributions` stores these points, and
`dashboard_payload` stores every factor (observed value, baseline, z by detector, W, I, A, C
with its ticket and ratio).

## Results on synthetic data

From `node crimguard/risk/demo.js` (seeded, reproducible):

| Case | Classic 3σ UEBA | CrimGuard v2 |
| --- | --- | --- |
| **A**: 15 → 608 files/day on an approved migration ticket | z = 164.5, **flagged** | **17.8 low**, `legitimate_spike`; each feature 90% explained by DBM-142 |
| A with no ticket on file | flagged | **96.3 critical** |
| **B**: 15 → 70 files/day over 90 days, nothing on file | z = 0.5, **not flagged** | **72.9 high**, `slow_exfiltration`, drift detector, +377% vs anchor; first high day about 7½ weeks into the creep |
| 5 ordinary users, ~220 weekdays each | — | median 1–3, p95 12–20, **0 high days**, 0–2 medium days |

## Inputs

```js
const { createRiskEngine, loadFeatureCatalog, toRiskScoreRow } = require('./crimguard/risk');
const engine = createRiskEngine({
  catalog: loadFeatureCatalog(),        // or normalizeCatalog(rows from feature_catalog)
  orgSettings: { files_accessed_count: { weight: 0.8, zThreshold: 2.8, isEnabled: true } },
});

const results = engine.scoreTimeline({
  subject: {
    isPrivileged: false, employmentType: 'full_time', hireDate: '2024-03-01',
    anchorPeriod: { start: '2026-01-01', end: '2026-03-31' },          // optional frozen baseline
    hr: {
      terminationDate: null,
      events: [{ type: 'performance_review', isNegative: true, effectiveDate: '2026-05-02', recordedAt: '2026-05-03' }],
      leave: [{ requestedAt: '2026-06-01', daysRequested: 15, balanceBefore: 16 }],
    },
  },
  peers: { files_accessed_count: [14, 17, 12] },                      // same-role values, or (date) => ({ ... })
  days: [{
    date: '2026-06-04',
    features: { files_accessed_count: 608, weekend_holiday_access_flag: false },  // null = not collected
    assetWeight: 4,                                                    // highest criticality_weight touched
    featureAssetWeights: { daily_download_volume_mb: 5 },
    isolationForestScore: 0.61,
    honeytokenTrips: 0,
    context: {
      tickets: [{ key: 'DBM-142', approved: true, status: 'in_progress', openedAt: '2026-06-01',
                  assignedAt: '2026-06-03', dueAt: '2026-07-19', closedAt: null, unassignedAt: null,
                  expectedDailyFileVolume: 600, expectedAccessMultiplier: 15, scopeCoverage: 0.95,
                  explains: undefined /* or ['access_resource', 'files_accessed_count'] */ }],
      projects: [{ name: 'Data platform', joinedOn: '2026-05-01', startsOn: '2026-05-01', endsOn: null, leftOn: null }],
      roleChanges: [{ role: 'DBA', validFrom: '2026-05-20', scopeCoverage: 1 }],
    },
  }],
});

const row = toRiskScoreRow(results.at(-1), { snapshotId: 1, userId: 42 });    // → INSERT INTO risk_scores
```

To score one day at a time (a nightly job), call `engine.scoreDay({ subject, day, history, peers, previous })`.
`history` is the earlier snapshots (180 days is enough), and `previous` is the last 14 days of
`{ date, carry }` read back from `risk_scores.dashboard_payload`.

## UEBA sources drawn on

- **Microsoft Sentinel UEBA.** Baselines per user *and* per peer group; "first time" and
  "uncommon among peers" insights; blast radius of the account.
- **Microsoft Purview Insider Risk Management.** HR-connector triggers (resignation and
  termination dates), risk-score boosters for activity above the user's usual level and for
  priority users, sequence detection (collect → obfuscate → exfiltrate), and cumulative
  exfiltration.
- **Exabeam Advanced Analytics.** Risk from many small signals accumulated over a session or
  timeline instead of one alert per rule; context enrichment before scoring.
- **Splunk ES risk-based alerting.** Risk = impact × confidence, collected per entity over time.
- **CERT/SEI insider-threat research** (Common Sense Guide to Mitigating Insider Threats). HR
  stressors are precursors, and theft of intellectual property clusters in the weeks around
  departure.
- **Statistics.** Iglewicz & Hoaglin (1993), MAD-based modified z-scores; Anscombe (1948),
  variance-stabilising transform; Page (1954) and Montgomery, CUSUM with k = 0.5σ, h = 5σ;
  Efron & Morris (1975), empirical-Bayes shrinkage; Liu, Ting & Zhou (2008), Isolation Forest;
  Pearl (1988), noisy-OR.

## Not done yet

- **Nothing runs it on real data.** No job reads Postgres and writes `risk_scores`. This
  machine has no Postgres or pg driver, and the Red website doesn't use the CrimGuard schema.
- **Isolation Forest isn't trained here.** Its score is an input.
- **Every number in `params.js` is a default** tuned on synthetic users. Re-tune on real telemetry.
  Analyst verdicts in `alerts.status` / `resolution_notes` are the ground truth to tune against,
  and `MODEL_VERSION` must change whenever a value does.
- **No weekday or seasonal baselines.** Month-end or on-call rotations will look unusual until
  the rolling window has seen them. Supplying a peer group or a longer anchor helps.
