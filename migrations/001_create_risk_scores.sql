<<<<<<< HEAD
-- Team 3: Risk Scoring Engine - risk_scores table
--
-- Run this ONCE, manually, against Team 2's shared Supabase project
-- (Supabase SQL Editor, or `psql <connection-string> -f migrations/001_create_risk_scores.sql`).
-- Not run automatically on app startup - deliberate, visible step on a shared project.
--
-- Team 3 owns this table. We never modify Team 2's existing tables
-- (assets, vulnerabilities, exposures, etc.) - read-only access to those.

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- for gen_random_uuid(), if not already enabled

CREATE TABLE IF NOT EXISTS risk_scores (
    id                              UUID PRIMARY KEY,       -- deterministic per (asset_id, cve) - see app/risk_engine.py
=======
-- Team 3: Risk Scoring Engine - shared Supabase `risk_scores` table
--
-- Run this ONCE, manually, against Team 2's shared Supabase project.
-- This version preserves Team 3's write contract while also linking rows
-- back into Team 2's normalized CTEM tables when enough data is present.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS risk_scores (
    id                              UUID PRIMARY KEY,
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    asset_id                        VARCHAR NOT NULL,
    cve                             VARCHAR NOT NULL,
    tool                            VARCHAR,

<<<<<<< HEAD
    cvss                            FLOAT,                   -- NULL if unknown to CIRCL + NVD
    cvss_source                     VARCHAR NOT NULL DEFAULT 'unknown',  -- circl / nvd / unknown
    epss                            FLOAT NOT NULL,
    kev_listed                      BOOLEAN NOT NULL DEFAULT FALSE,

    asset_criticality               VARCHAR NOT NULL,        -- low/medium/high/critical (from Team 2, pass-through)
    network_zone                    VARCHAR,                 -- Team 2's raw field, preserved untouched
    exposure                        VARCHAR NOT NULL,        -- restricted/internal/internet-facing (Team 3-derived)
=======
    cvss                            FLOAT,
    cvss_source                     VARCHAR NOT NULL DEFAULT 'unknown',
    epss                            FLOAT NOT NULL,
    kev_listed                      BOOLEAN NOT NULL DEFAULT FALSE,

    asset_criticality               VARCHAR NOT NULL,
    network_zone                    VARCHAR,
    exposure                        VARCHAR NOT NULL,
>>>>>>> 0ac9c00 (Update Team 3 risk engine)

    base_score                      FLOAT NOT NULL,
    exploit_score                   FLOAT NOT NULL,
    asset_weight                    FLOAT NOT NULL,
    reachability_multiplier         FLOAT NOT NULL,
    blast_radius_multiplier         FLOAT NOT NULL,
<<<<<<< HEAD
    blast_radius_affected_count     INTEGER,                 -- NULL until Team 4's graph is live
=======
    blast_radius_affected_count     INTEGER,
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
    blast_radius_source             VARCHAR NOT NULL DEFAULT 'stub',
    raw_composite                   FLOAT NOT NULL,

    risk_score                      FLOAT NOT NULL,
<<<<<<< HEAD
    tier                            VARCHAR NOT NULL,        -- P1 / P2 / P3 / P4
    severity                        VARCHAR NOT NULL,        -- critical / high / medium / low
    sla_hours                       INTEGER NOT NULL,
    hard_gated                      BOOLEAN NOT NULL DEFAULT FALSE,
    criticality_mismatch            BOOLEAN NOT NULL DEFAULT FALSE,  -- flag only, never overwrites Team 2's criticality

    created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- set once, on first insert
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW()   -- refreshed on every re-score (upsert)
);

CREATE INDEX IF NOT EXISTS idx_risk_scores_asset_id ON risk_scores (asset_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_cve ON risk_scores (cve);
CREATE INDEX IF NOT EXISTS idx_risk_scores_tier ON risk_scores (tier);
CREATE INDEX IF NOT EXISTS idx_risk_scores_risk_score ON risk_scores (risk_score);
CREATE INDEX IF NOT EXISTS idx_risk_scores_criticality_mismatch ON risk_scores (criticality_mismatch);

-- Optional but recommended: enable Realtime on this table so Team 4/5 can
-- subscribe to INSERT/UPDATE events instead of only polling.
-- In Supabase: Database -> Replication -> toggle `risk_scores` on for the
-- `supabase_realtime` publication. Or run:
=======
    tier                            VARCHAR NOT NULL,
    severity                        VARCHAR NOT NULL,
    sla_hours                       INTEGER NOT NULL,
    hard_gated                      BOOLEAN NOT NULL DEFAULT FALSE,
    criticality_mismatch            BOOLEAN NOT NULL DEFAULT FALSE,

    asset_pk                        INT REFERENCES assets(asset_id) ON DELETE SET NULL,
    vuln_id                         INT REFERENCES vulnerabilities(vuln_id) ON DELETE SET NULL,
    asset_vulnerability_id          INT REFERENCES asset_vulnerabilities(id) ON DELETE SET NULL,
    exposure_id                     INT REFERENCES exposures(exposure_id) ON DELETE SET NULL,
    snapshot_id                     INT REFERENCES scan_snapshots(snapshot_id) ON DELETE SET NULL,

    created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_risk_scores_cvss CHECK (cvss IS NULL OR (cvss >= 0 AND cvss <= 10)),
    CONSTRAINT chk_risk_scores_epss CHECK (epss >= 0 AND epss <= 1),
    CONSTRAINT chk_risk_scores_risk_score CHECK (risk_score >= 0 AND risk_score <= 100),
    CONSTRAINT chk_risk_scores_tier CHECK (tier IN ('P1', 'P2', 'P3', 'P4')),
    CONSTRAINT chk_risk_scores_severity CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    CONSTRAINT chk_risk_scores_asset_criticality CHECK (asset_criticality IN ('low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS idx_risk_scores_asset_id ON risk_scores (asset_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_asset_pk ON risk_scores (asset_pk);
CREATE INDEX IF NOT EXISTS idx_risk_scores_cve ON risk_scores (cve);
CREATE INDEX IF NOT EXISTS idx_risk_scores_vuln_id ON risk_scores (vuln_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_tier ON risk_scores (tier);
CREATE INDEX IF NOT EXISTS idx_risk_scores_risk_score ON risk_scores (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_risk_scores_criticality_mismatch ON risk_scores (criticality_mismatch);
CREATE INDEX IF NOT EXISTS idx_risk_scores_updated_at ON risk_scores (updated_at DESC);

CREATE OR REPLACE FUNCTION set_risk_scores_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_set_risk_scores_updated_at ON risk_scores;
CREATE TRIGGER trg_set_risk_scores_updated_at
BEFORE UPDATE ON risk_scores
FOR EACH ROW
EXECUTE FUNCTION set_risk_scores_updated_at();

CREATE OR REPLACE FUNCTION sync_risk_score_ctem_links()
RETURNS TRIGGER AS $$
DECLARE
    matched_asset_pk INT;
    matched_vuln_id INT;
BEGIN
    matched_asset_pk := NULL;
    matched_vuln_id := NULL;

    SELECT a.asset_id
      INTO matched_asset_pk
      FROM assets a
     WHERE NEW.asset_id = a.asset_id::text
        OR NEW.asset_id = a.hostname
        OR NEW.asset_id = a.fqdn
        OR NEW.asset_id = a.ip_address::text
     ORDER BY CASE
        WHEN NEW.asset_id = a.asset_id::text THEN 1
        WHEN NEW.asset_id = a.hostname THEN 2
        WHEN NEW.asset_id = a.fqdn THEN 3
        WHEN NEW.asset_id = a.ip_address::text THEN 4
        ELSE 5
     END
     LIMIT 1;

    NEW.asset_pk := matched_asset_pk;

    SELECT v.vuln_id
      INTO matched_vuln_id
      FROM vulnerabilities v
     WHERE UPPER(v.cve_id) = UPPER(NEW.cve)
     LIMIT 1;

    NEW.vuln_id := matched_vuln_id;

    IF matched_asset_pk IS NOT NULL AND matched_vuln_id IS NOT NULL THEN
        SELECT av.id
          INTO NEW.asset_vulnerability_id
          FROM asset_vulnerabilities av
         WHERE av.asset_id = matched_asset_pk
           AND av.vuln_id = matched_vuln_id
         LIMIT 1;

        SELECT e.exposure_id
          INTO NEW.exposure_id
          FROM exposures e
         WHERE e.asset_id = matched_asset_pk
           AND e.vuln_id = matched_vuln_id
         ORDER BY CASE e.status
            WHEN 'active' THEN 1
            WHEN 'mitigated' THEN 2
            WHEN 'accepted' THEN 3
            WHEN 'closed' THEN 4
            ELSE 5
         END,
         e.identified_on DESC
         LIMIT 1;

        SELECT ss.snapshot_id
          INTO NEW.snapshot_id
          FROM scan_snapshots ss
         WHERE ss.asset_id = matched_asset_pk
         ORDER BY ss.snapshot_taken_at DESC
         LIMIT 1;
    ELSE
        NEW.asset_vulnerability_id := NULL;
        NEW.exposure_id := NULL;
        NEW.snapshot_id := NULL;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sync_risk_score_ctem_links ON risk_scores;
CREATE TRIGGER trg_sync_risk_score_ctem_links
BEFORE INSERT OR UPDATE ON risk_scores
FOR EACH ROW
EXECUTE FUNCTION sync_risk_score_ctem_links();

CREATE OR REPLACE VIEW risk_scores_enriched AS
SELECT
    rs.id,
    rs.asset_id AS risk_asset_identifier,
    rs.asset_pk,
    a.asset_name,
    a.hostname,
    a.fqdn,
    a.ip_address,
    a.asset_type,
    a.environment,
    a.criticality AS team2_asset_criticality,
    rs.cve,
    rs.vuln_id,
    v.title AS vulnerability_title,
    v.severity AS vulnerability_severity,
    rs.tool,
    rs.cvss,
    rs.cvss_source,
    rs.epss,
    rs.kev_listed,
    rs.network_zone,
    rs.exposure,
    rs.base_score,
    rs.exploit_score,
    rs.asset_weight,
    rs.reachability_multiplier,
    rs.blast_radius_multiplier,
    rs.blast_radius_affected_count,
    rs.blast_radius_source,
    rs.raw_composite,
    rs.risk_score,
    rs.tier,
    rs.severity,
    rs.sla_hours,
    rs.hard_gated,
    rs.criticality_mismatch,
    rs.asset_vulnerability_id,
    rs.exposure_id,
    rs.snapshot_id,
    rs.created_at,
    rs.updated_at
FROM risk_scores rs
LEFT JOIN assets a ON a.asset_id = rs.asset_pk
LEFT JOIN vulnerabilities v ON v.vuln_id = rs.vuln_id;

-- Optional: enable Realtime for consumers that subscribe to score changes.
>>>>>>> 0ac9c00 (Update Team 3 risk engine)
-- ALTER PUBLICATION supabase_realtime ADD TABLE risk_scores;
