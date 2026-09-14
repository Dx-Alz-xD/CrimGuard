-- =========================================================
-- CrimGuard — 08: Helper views and triggers
-- =========================================================

CREATE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_alerts_updated_at
    BEFORE UPDATE ON alerts FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Today's context for each user: what the context-match step checks
-- before deciding whether a spike is explained.
CREATE VIEW v_active_user_context AS
SELECT
    u.id                  AS user_id,
    u.org_id,
    u.employment_type,
    u.employment_status,
    u.termination_date,
    r.current_roles,
    r.last_role_change_on,
    tk.active_ticket_keys,
    COALESCE(tk.active_ticket_count, 0)   AS active_ticket_count,
    tk.max_expected_daily_file_volume,
    COALESCE(pj.active_project_count, 0)  AS active_project_count,
    EXISTS (
        SELECT 1 FROM leave_periods lp
        WHERE lp.user_id = u.id AND lp.approved
          AND CURRENT_DATE BETWEEN lp.starts_on AND lp.ends_on
    )                                     AS on_leave_today
FROM users u
LEFT JOIN LATERAL (
    SELECT array_agg(ro.name ORDER BY ro.name) FILTER (WHERE ura.valid_to IS NULL) AS current_roles,
           max(ura.valid_from)                                                    AS last_role_change_on
    FROM user_role_assignments ura
    JOIN roles ro ON ro.id = ura.role_id
    WHERE ura.user_id = u.id
) r ON true
LEFT JOIN LATERAL (
    SELECT array_agg(t.external_key ORDER BY t.opened_at) AS active_ticket_keys,
           count(*)                                       AS active_ticket_count,
           max(t.expected_daily_file_volume)              AS max_expected_daily_file_volume
    FROM ticket_assignments ta
    JOIN tickets t ON t.id = ta.ticket_id
    WHERE ta.user_id = u.id
      AND ta.unassigned_at IS NULL
      AND t.status IN ('open', 'in_progress', 'blocked')
) tk ON true
LEFT JOIN LATERAL (
    SELECT count(*) AS active_project_count
    FROM project_members pm
    JOIN projects p ON p.id = pm.project_id
    WHERE pm.user_id = u.id
      AND pm.left_on IS NULL
      AND CURRENT_DATE >= p.starts_on
      AND (p.ends_on IS NULL OR CURRENT_DATE <= p.ends_on)
) pj ON true;

-- Shadow AI: sensitive pastes and uploads into unsanctioned GenAI tools.
-- Ingestion should resolve external_domain_id to the org-specific row
-- first (an org may sanction a tool that is unsanctioned globally).
CREATE VIEW v_shadow_ai_activity AS
SELECT 'clipboard_paste'::text   AS vector,
       c.id                      AS event_id,
       c.user_id,
       c.occurred_at,
       ed.domain,
       ed.app_name,
       c.char_count::bigint      AS size_value,
       'chars'::text             AS size_unit,
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
