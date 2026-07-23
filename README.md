# Team 3 --- Risk Scoring Engine (ThreatGraph)

Vulnerability & Risk Analysis module. Computes a composite risk score
for each finding (asset + CVE) using **CVSS**, **EPSS**, **CISA KEV**,
**asset criticality**, **reachability**, and **blast radius** ---
producing a priority tier (P1--P4) with a recommended SLA.

Reads asset context from **Team 2's shared Supabase project**
(read-only, via `supabase-py`). Writes results to our own `risk_scores`
table in that same project, which Team 4 (attack path visualization) and
Team 5 (alerting/dashboard) read directly --- no message broker.

**No Docker. No Redis. No NATS/Kafka. No local Postgres.** Supabase is
the only datastore and the only integration point across teams.

---

## 1. How scoring works

```
 Finding (asset_id + CVE)
        |
        v
 Resolve asset context
   1. Team 2 Supabase `assets` table (matched on asset_id -> hostname -> fqdn -> ip_address)
   2. Team 1 REST API, if configured
   3. Deterministic sample data (dev/testing only, clearly tagged)
        |
        v
 Live fetch (every call, no cache):
   CVSS  - CIRCL (primary) -> NVD 2.0 (fallback)
   EPSS  - FIRST.org
   KEV   - CISA
        |
        v
 Composite Scoring Engine (formula + P1-P4 tiering + mismatch flag)
        |
        v
 Upsert into Supabase `risk_scores` (Team 3-owned table)
        |
        v
 Team 4 / Team 5 query the table directly (or subscribe via Supabase Realtime)
```

### Formula

```
Base Score          = CVSS_Base x 10        (0-100; defaults to a neutral
                                               midpoint of 5.0 -> 50 if CVSS
                                               is unknown to both CIRCL and
                                               NVD - the `cvss` output field
                                               stays null in that case)
Exploit Likelihood    = EPSS x 100            (0-100)
KEV Multiplier         = 1.5 if KEV-listed else 1.0
Asset Weight            = 1.0 / 1.5 / 2.0 / 3.0   by Low / Medium / High / Critical
Reachability Mult.      = 1.0 / 1.5 / 2.5         by Restricted / Internal / Internet-facing
Blast Radius Mult.      = 1.0 (stub today - see section 4)

Composite Score = (Base x Exploit x KEV x AssetWeight x Reachability x BlastRadius)
                   / NORMALIZATION_FACTOR
```

`NORMALIZATION_FACTOR` is derived from the max possible value of every
factor (`app/config.py`), sized with headroom for Blast Radius
eventually exceeding 1.0, so the composite score is always rescaled into
0--100 and never needs re-normalizing later when real blast radius data
arrives.

### Tiering (P1--P4)

---

Tier Criteria SLA

---

P1 -- KEV-listed **OR** (High EPSS + 72 hours
 Critical Internet-facing + Critical asset)

P2 -- High (High EPSS + High CVSS) **OR** Critical 7 days
 asset + internet-facing

P3 -- (Medium EPSS + Medium CVSS) **OR** 14 days
 Medium High-criticality asset

P4 -- Low everything else 30 days /
 risk-accepted

---

Thresholds: EPSS High ≥ 0.50, Medium 0.10--0.50; CVSS High ≥ 7.0, Medium
4.0--7.0 (configurable in `.env`). "Compensating controls" (P3 criteria)
isn't data we have from any team yet --- treated as always absent.

---

## 2. Data sources --- all free, nothing paid

---

Signal Source Auth

---

CVSS CIRCL none
 (primary) Vulnerability-Lookup

CVSS NVD API 2.0 none required; optional free key
 (fallback) raises rate limit

EPSS FIRST.org none

KEV CISA none

Asset Team 2's Supabase shared project, key from Team 2
 context `assets` table

---

No caching layer (Redis was evaluated and dropped) --- every scoring
call live-fetches CVSS/EPSS/KEV fresh. See [Section
6](#6-known-limitations--assumptions) for the performance trade-off this
implies.

---

## 3. Team 2's real asset schema

Team 2's `assets` table exposes both a numeric primary key and
human-readable identifiers. Identity should be resolved from the
following ordered list of columns --- first match wins:

```
asset_id -> hostname -> fqdn -> ip_address
```

Example real row (from Team 2):

```json
{
  "asset_name": "Web Server 01",
  "asset_type": "server",
  "hostname": "web01",
  "fqdn": "web01.example.com",
  "ip_address": "10.0.0.10",
  "network_zone": "internal",
  "environment": "production",
  "criticality": "high",
  "status": "active"
}
```

We take exactly **6 raw fields** from Team 2: `asset_id`, `hostname`,
`fqdn`, `ip_address`, `criticality`, and `network_zone`. Everything else
in our formula (`exposure`, `reachability_multiplier`, `asset_weight`)
is **computed by Team 3**, not read from them.

`network_zone` → `exposure` mapping (`app/config.py`):

---

Team 2 `network_zone` Team 3 `exposure` Reachability multiplier

---

`external` `internet-facing` 2.5

`internet` `internet-facing` 2.5

`dmz` `internet-facing` 2.5

`internal` `internal` 1.5

`restricted` `restricted` 1.0

`cloud_vpc` `internal` 1.5

anything else/missing `internal` (default) 1.5

**`network_zone` is preserved untouched** in our output, alongside our
derived `exposure` --- both are always present so it's clear which of
Team 2's raw labels we mapped from.

---

## 4. Blast Radius --- stub today, one swap point later

Blast Radius ("how many other assets are affected if this one is
compromised") is a graph-connectivity question that belongs to **Team
4's** attack path graph, which doesn't exist yet.
`app/ingestion/blast_radius.py` exposes one function:

```python
get_blast_radius(asset_id) -> BlastRadius(multiplier, affected_count, source)
```

Today it always returns `multiplier=1.0`, `affected_count=None`,
`source="stub"`. When Team 4's graph is ready: set `TEAM4_GRAPH_API` in
`.env` and implement `_fetch_from_team4_graph()` in that one file.
Nothing else --- formula, API contract, Supabase schema --- needs to
change. Every output row already has
`blast_radius_multiplier`/`blast_radius_affected_count`/`blast_radius_source`,
so no later schema migration either.

---

## 5. Asset criticality --- passed through, never overwritten

Team 2's `criticality` label (business importance) and our computed
`tier` (current exploitation danger) are different things and both stay
in every output row. We are a **read-only** client of Team 2's tables
--- we never write to `assets` or any of their other tables, only to our
own `risk_scores`.

When our computed tier is more severe (P1/P2) than Team 2's stated
criticality suggests (Low/Medium), we set `criticality_mismatch: true`
on our own row --- a flag for review, not a correction:

```bash
curl "http://localhost:8000/risk-scores?criticality_mismatch=true"
```

---

## 6. Known limitations / assumptions

- **No cache layer** --- every scoring call live-fetches
  CVSS/EPSS/KEV, and the KEV feed in particular is a multi-MB JSON
  file fetched in full each time. Fine for low/moderate request
  volume; will get slow under heavy batch scoring. Revisit if this
  becomes a bottleneck.
- **Blast Radius is a stub** until Team 4's graph is queryable
  (Section 4).
- **CVSS defaults to a neutral midpoint (5.0 -\> base score 50)** in
  the *formula* only when unknown to both CIRCL and NVD --- the `cvss`
  output field itself stays `null` in that case, and `cvss_source`
  reports `"unknown"`, so the default is never mistaken for a real
  value.
- **`id` is a deterministic UUID5** derived from `(asset_id, cve)`,
  not random --- re-scoring the same finding **upserts** the same row
  (updates `updated_at`, leaves `created_at` untouched) rather than
  creating duplicates. This means `risk_scores` holds current state
  per finding, not full history --- if you need historical score
  trends later, that's a design change (e.g. a separate append-only
  log table).
- **`created_at`/`updated_at` on API responses (POST endpoints)**
  reflect the time of that call, not necessarily the authoritative
  DB-persisted value if you re-score an existing finding in rapid
  succession --- `GET` endpoints always return the authoritative
  values from Supabase.
- **We are read-only on Team 2's tables.**
- **Supabase key permissions are unconfirmed** --- whether you get the
  `anon` key (subject to Row-Level-Security policies) or
  `service_role` key (bypasses RLS) from Team 2 changes whether reads
  against `assets` might return empty due to RLS. Confirm which one
  you're given.
- **Sample fallback asset data** (used only if Team 2's table and Team
  1's API both fail to resolve an identifier) is randomized but seeded
  by `asset_id`, tagged `"source": "sample-data-fallback"` --- never
  real.

---

## 7. Prerequisites & setup

```bash
git clone <this-repo-url>
cd team3-risk-engine
python3 -m venv venv && source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Only **Python 3.11+** is required locally --- no Redis, no NATS, no
Postgres, no Docker.

You need, from **Team 2**:

- Their Supabase project URL --- already defaulted in `.env.example`
  (`https://eqlolqdgviakidyinwrt.supabase.co`, per their README)
- The Supabase **key** --- must be requested from them directly (their
  README says the same). Ask specifically whether it's `anon` or
  `service_role` --- see [Section
  6](#6-known-limitations--assumptions).
- Confirmation of their real `assets` table column names if different
  from our defaults (`asset_id`, `hostname`, `fqdn`, `ip_address`,
  `criticality`, `network_zone`) --- adjust `TEAM2_COL_*` in `.env`,
  no code changes needed.

### One-time database setup

Run `migrations/001_create_risk_scores.sql` **once**, manually, in Team
2's Supabase SQL Editor (or
`psql <connection-string> -f migrations/001_create_risk_scores.sql` if
you have direct DB access). Not run automatically by the app --- this is
a shared project, so schema changes should be a deliberate, visible
step.

The migration now also:

- links `risk_scores` rows back to Team 2 CTEM tables when possible
- maintains `updated_at` with a DB trigger on every update
- exposes a `risk_scores_enriched` view for joined reads
- includes an optional, commented step to enable Supabase Realtime on
  `risk_scores`

---

## 8. Running

```bash
uvicorn app.main:app --reload --port 8000
```

- Interactive docs: http://localhost:8000/docs
- Health check: http://localhost:8000/health

### Example usage

**Score a single finding (asset context supplied inline):**

```bash
curl -X POST http://localhost:8000/scan/risk-score \
  -H "Content-Type: application/json" \
  -d '{
    "asset": {
      "asset_id": "web01",
      "asset_type": "server",
      "fqdn": "web01.example.com",
      "ip_address": "10.0.0.10",
      "criticality": "high",
      "network_zone": "internal",
      "exposure": "internal",
      "environment": "production"
    },
    "cve": "CVE-2024-3400",
    "tool": "nuclei"
  }'
```

**Score using Team 2's live asset data** (tries `asset_id` -\>
`hostname` -\> `fqdn` -\> `ip_address`):

```bash
curl -X POST "http://localhost:8000/scan/risk-score/by-asset-id?asset_id=web01&cve=CVE-2024-3400&tool=nuclei"
```

**Batch scoring** --- see `sample_data/sample_scan_input.json` /
`sample_scan_output.json` (output file was generated by actually running
the scoring engine, not hand-written):

```bash
curl -X POST http://localhost:8000/scan/risk-score/batch \
  -H "Content-Type: application/json" -d @sample_data/sample_scan_input.json
```

**Raw scan ingestion** --- feed raw scanner output directly and let Team
3 extract findings before scoring:

```bash
curl -X POST "http://localhost:8000/scan/ingest-results?default_tool=nuclei" \
  -H "Content-Type: application/json" \
  -d @sample_data/sample_raw_findings.json
```

**Retrieve scores:**

```bash
curl http://localhost:8000/risk-scores/web01
curl http://localhost:8000/risk-scores/42
curl "http://localhost:8000/risk-scores?tier=P1&limit=20"
curl "http://localhost:8000/risk-scores?criticality_mismatch=true"
```

`GET /risk-scores/{asset_id}` first checks the provided identifier
directly, then retries with the canonical Team 2 asset primary key if
the original lookup was a hostname, FQDN, or IP alias.

### Testing

Formula/tiering/mismatch-flag/id-stability logic runs standalone, no
network or Supabase access needed:

```bash
python -m tests.test_risk_engine
python -m tests.test_scan_ingestion
```

### CLI ingestion

To extract findings from a raw JSON scan file, score them, and write the
results to Supabase without going through the HTTP API:

```bash
python ingest_scan_results.py \
  --input sample_data/sample_raw_findings.json \
  --default-tool nuclei \
  --output scored_results.json
```

---

## 9. What Team 4 and Team 5 get

Every row in `risk_scores` is the **full** record --- not a trimmed
per-team view. See `sample_data/sample_scan_output.json` for real
generated examples.

- **Team 4** (attack path graph) will mainly key off `asset_id`,
  `tier`/`risk_score`, `kev_listed`/`hard_gated`, and `id` (stable per
  finding, usable as a reference key from a graph node/edge back to
  this row). `blast_radius_*` fields are ready to receive real data
  from them later.
- **Team 5** (alerts/dashboard) will mainly key off
  `tier`/`severity`/`sla_hours` for alert routing and SLA tracking,
  and `asset_criticality` for business-impact context alongside the
  technical severity.

Both teams can query via Supabase's REST API directly
(`GET /rest/v1/risk_scores?tier=eq.P1`), or subscribe to
`INSERT`/`UPDATE` events via Supabase Realtime if enabled (see Section
7's migration note) instead of polling.

---

## 10. Project structure

```
team3-risk-engine/
├── app/
│   ├── main.py             # FastAPI app & routes
│   ├── config.py           # env settings, formula weights, network_zone mapping, SLA table
│   ├── models.py           # Pydantic schemas (JSON contract)
│   ├── scan_ingestion.py   # raw scan payload extraction -> existing ScoreRequest contract
│   ├── supabase_client.py  # shared supabase-py client
│   ├── risk_engine.py      # composite formula + P1-P4 tiering + mismatch flag + stable id
│   ├── risk_store.py       # read/write our own risk_scores table via supabase-py
│   ├── asset_context.py    # Team 2 Supabase (asset_id/hostname/fqdn/ip_address) -> Team 1 REST -> sample fallback
│   └── ingestion/
│       ├── kev.py          # CISA KEV feed (live fetch)
│       ├── epss.py         # FIRST EPSS API (live fetch)
│       ├── cvss.py         # CIRCL (primary) + NVD 2.0 (fallback), live fetch
│       └── blast_radius.py # stub, single swap point for Team 4's graph later
├── migrations/
│   └── 001_create_risk_scores.sql   # run once, manually, in Supabase
├── ingest_scan_results.py           # CLI ingestion path for raw scan files
├── tests/
│   ├── test_risk_engine.py
│   └── test_scan_ingestion.py
├── sample_data/
│   ├── sample_scan_input.json
│   ├── sample_scan_output.json      # generated by running the actual engine
│   └── sample_raw_findings.json     # raw-scan-style ingestion input example
├── requirements.txt
├── .env.example
└── README.md
```
