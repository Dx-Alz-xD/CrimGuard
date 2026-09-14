-- =============================================================================
-- CrimGuard: behavioural biometrics verdicts
-- One row per window of typing and pointer movement a signed-in browser sends,
-- judged against that person's own profile (src/biometrics/). biometric_samples
-- keeps the coarse per-window averages; this table keeps the richer timing
-- vector, the verdict and the session trust it produced.
--
-- The feature vector never identifies keys or pointer positions: keys are reduced
-- to hand zones and the pointer to stroke statistics before they leave the page.
-- =============================================================================

CREATE TABLE biometric_windows (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id           BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id         BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    session_ref       TEXT,                      -- user_sessions.idp_session_id of the session that typed it
    window_start      TIMESTAMPTZ NOT NULL,
    window_seconds    INTEGER NOT NULL CHECK (window_seconds > 0),
    keystrokes        INTEGER NOT NULL DEFAULT 0 CHECK (keystrokes >= 0),
    pointer_strokes   INTEGER NOT NULL DEFAULT 0 CHECK (pointer_strokes >= 0),
    features          JSONB NOT NULL DEFAULT '{}'::jsonb,
    keys_z            DOUBLE PRECISION,          -- typing distance from the profile, in the owner's own sigma
    pointer_z         DOUBLE PRECISION,          -- pointer distance, likewise
    distance_z        DOUBLE PRECISION,          -- the two combined
    match_probability DOUBLE PRECISION CHECK (match_probability IS NULL OR (match_probability >= 0 AND match_probability <= 1)),
    verdict           TEXT NOT NULL CHECK (verdict IN ('enrolling', 'insufficient', 'match', 'uncertain', 'mismatch')),
    session_trust     DOUBLE PRECISION,
    decision          TEXT CHECK (decision IS NULL OR decision IN ('ok', 'watch', 'challenge')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_biometric_windows_user_time ON biometric_windows (user_id, window_start);
