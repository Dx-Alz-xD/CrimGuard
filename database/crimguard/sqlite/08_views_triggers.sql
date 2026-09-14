-- =========================================================
-- CrimGuard — SQLite versions of ../08_views_triggers.sql
-- src/db/sqlite-schema.js swaps these in when it builds database/crimguard.db,
-- because SQLite has no LATERAL joins, array_agg, or PL/pgSQL trigger functions.
-- Keep each view's output columns identical to the PostgreSQL version.
-- Only CREATE VIEW and CREATE TRIGGER statements belong in this folder.
-- =========================================================

-- SQLite triggers can't modify NEW, so update the row after the fact. The inner
-- UPDATE doesn't re-fire the trigger because recursive triggers are off by default.
CREATE TRIGGER trg_users_updated_at
AFTER UPDATE ON users FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

CREATE TRIGGER trg_alerts_updated_at
AFTER UPDATE ON alerts FOR EACH ROW
BEGIN
    UPDATE alerts SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

-- current_roles and active_ticket_keys are JSON arrays here (text[] in PostgreSQL);
-- src/db/crimguard.js parses them, so both databases return JavaScript arrays.
-- Like array_agg, they are NULL when there is nothing to list.
CREATE VIEW v_active_user_context AS
SELECT
    u.id                  AS user_id,
    u.org_id,
    u.employment_type,
    u.employment_status,
    u.termination_date,
    r.current_roles,
    (SELECT max(ura.valid_from) FROM user_role_assignments ura WHERE ura.user_id = u.id)
                          AS last_role_change_on,
    tk.active_ticket_keys,
    COALESCE(tk.active_ticket_count, 0)   AS active_ticket_count,
    tk.max_expected_daily_file_volume,
    (SELECT count(*)
       FROM project_members pm
       JOIN projects p ON p.id = pm.project_id
      WHERE pm.user_id = u.id
        AND pm.left_on IS NULL
        AND date('now') >= p.starts_on
        AND (p.ends_on IS NULL OR date('now') <= p.ends_on))
                          AS active_project_count,
    EXISTS (
        SELECT 1 FROM leave_periods lp
        WHERE lp.user_id = u.id AND lp.approved
          AND date('now') BETWEEN lp.starts_on AND lp.ends_on
    )                     AS on_leave_today
FROM users u
LEFT JOIN (
    SELECT user_id, json_group_array(name) AS current_roles
    FROM (SELECT ura.user_id, ro.name
            FROM user_role_assignments ura
            JOIN roles ro ON ro.id = ura.role_id
           WHERE ura.valid_to IS NULL
           ORDER BY ura.user_id, ro.name)
    GROUP BY user_id
) r ON r.user_id = u.id
LEFT JOIN (
    SELECT user_id,
           json_group_array(external_key)   AS active_ticket_keys,
           count(*)                         AS active_ticket_count,
           max(expected_daily_file_volume)  AS max_expected_daily_file_volume
    FROM (SELECT ta.user_id, t.external_key, t.expected_daily_file_volume
            FROM ticket_assignments ta
            JOIN tickets t ON t.id = ta.ticket_id
           WHERE ta.unassigned_at IS NULL
             AND t.status IN ('open', 'in_progress', 'blocked')
           ORDER BY ta.user_id, t.opened_at)
    GROUP BY user_id
) tk ON tk.user_id = u.id;

CREATE VIEW v_shadow_ai_activity AS
SELECT 'clipboard_paste'         AS vector,
       c.id                      AS event_id,
       c.user_id,
       c.occurred_at,
       ed.domain,
       ed.app_name,
       c.char_count              AS size_value,
       'chars'                   AS size_unit,
       c.content_classification  AS sensitivity,
       c.enforcement
FROM clipboard_events c
JOIN external_domains ed ON ed.id = c.external_domain_id
WHERE ed.category = 'genai_llm' AND NOT ed.is_sanctioned
UNION ALL
SELECT 'file_upload',
       t.id,
       t.user_id,
       t.occurred_at,
       ed.domain,
       ed.app_name,
       t.bytes,
       'bytes',
       t.sensitivity_detected,
       t.enforcement
FROM data_transfer_events t
JOIN external_domains ed ON ed.id = t.external_domain_id
WHERE ed.category = 'genai_llm' AND NOT ed.is_sanctioned;
