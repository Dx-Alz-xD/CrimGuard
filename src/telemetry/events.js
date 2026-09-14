'use strict';

// Writes rows into the CrimGuard raw-event tables (04_events.sql). Everything the website
// observes lands here first; features.js aggregates these into the daily snapshot later.
//
// Nothing in this file stores content. Clipboard and keystroke activity arrive as counts and
// timing statistics, and search terms are kept only where the catalog needs the term itself
// (unusual_search_query_count), truncated and never joined to a person's text.

const MAX_TEXT = 255;

const text = (value, max = MAX_TEXT) => (typeof value === 'string' && value ? value.slice(0, max) : null);
const count = (value) => (Number.isFinite(value) && value >= 0 ? Math.round(value) : null);
const real = (value) => (Number.isFinite(value) ? value : null);
const when = (value) => (typeof value === 'string' && value ? value : new Date().toISOString());

function createEvents(db) {
  const insert = (sql, params) => db.query(sql, params);

  return {
    // --- sessions ------------------------------------------------------------------
    async startSession({ userId, deviceId, sessionRef, startedAt, ip, countryCode, userAgent }) {
      await insert(
        `INSERT INTO user_sessions (user_id, device_id, idp_session_id, started_at, source_ip, country_code, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [userId, deviceId, text(sessionRef, 64), when(startedAt), text(ip, 64), text(countryCode, 2), text(userAgent)],
      );
      const { rows } = await db.query(
        'SELECT id FROM user_sessions WHERE user_id = ? AND idp_session_id = ? ORDER BY id DESC LIMIT 1',
        [userId, text(sessionRef, 64)],
      );
      return rows[0]?.id ?? null;
    },

    async endSession({ sessionRef, endedAt }) {
      if (!sessionRef) return;
      await insert('UPDATE user_sessions SET ended_at = ? WHERE idp_session_id = ? AND ended_at IS NULL',
        [when(endedAt), text(sessionRef, 64)]);
    },

    async openSessionId(userId, sessionRef) {
      if (!sessionRef) return null;
      const { rows } = await db.query('SELECT id FROM user_sessions WHERE user_id = ? AND idp_session_id = ? ORDER BY id DESC LIMIT 1',
        [userId, text(sessionRef, 64)]);
      return rows[0]?.id ?? null;
    },

    // --- activity ------------------------------------------------------------------
    fileAccess({ userId, sessionId, deviceId, resourceId, action, occurredAt, bytes, filePath, previousPath, searchQuery, filesInBatch }) {
      return insert(
        `INSERT INTO file_access_events
           (user_id, session_id, device_id, resource_id, action, occurred_at, bytes, file_path, previous_path, search_query, process_name, files_in_batch)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'red-web', ?)`,
        [userId, sessionId, deviceId, resourceId, action, when(occurredAt), count(bytes), text(filePath),
          text(previousPath), text(searchQuery, 120), count(filesInBatch)],
      );
    },

    transfer({ userId, deviceId, resourceId, channel, occurredAt, bytes, fileName, destination, isCompressed, renamedBeforeExport, sensitivity, enforcement }) {
      return insert(
        `INSERT INTO data_transfer_events
           (user_id, device_id, resource_id, channel, occurred_at, bytes, file_name, destination, is_compressed, renamed_before_export, sensitivity_detected, enforcement)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, deviceId, resourceId, channel, when(occurredAt), count(bytes) ?? 0, text(fileName), text(destination),
          Boolean(isCompressed), Boolean(renamedBeforeExport), sensitivity ?? null, enforcement || 'logged'],
      );
    },

    // detectedPatterns names the kinds of secret matched ('api_key', 'password'), never the text.
    clipboard({ userId, deviceId, occurredAt, charCount, sourceApp, destinationApp, classification, detectedPatterns, enforcement }) {
      return insert(
        `INSERT INTO clipboard_events
           (user_id, device_id, occurred_at, char_count, source_app, destination_app, content_classification, detected_patterns, enforcement)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, deviceId, when(occurredAt), count(charCount) ?? 0, text(sourceApp, 64), text(destinationApp, 64),
          classification ?? null, JSON.stringify(Array.isArray(detectedPatterns) ? detectedPatterns.slice(0, 8) : []),
          enforcement || 'logged'],
      );
    },

    auth({ userId, sessionId, deviceId, eventType, occurredAt, ip, countryCode, city, userAgent, isVpn }) {
      return insert(
        `INSERT INTO auth_events
           (user_id, session_id, device_id, event_type, occurred_at, source_ip, country_code, city, user_agent, is_vpn)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, sessionId, deviceId, eventType, when(occurredAt), text(ip, 64), text(countryCode, 2), text(city, 64),
          text(userAgent), isVpn === undefined ? null : Boolean(isVpn)],
      );
    },

    endpoint({ userId, deviceId, eventType, occurredAt, appName, isSanctionedApp, details }) {
      return insert(
        `INSERT INTO endpoint_events (user_id, device_id, event_type, occurred_at, app_name, is_sanctioned_app, details)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [userId, deviceId, eventType, when(occurredAt), text(appName, 64),
          isSanctionedApp === undefined ? null : Boolean(isSanctionedApp), JSON.stringify(details || {})],
      );
    },

    network({ userId, deviceId, occurredAt, ip, destinationDomain, bytesOut, bytesIn }) {
      return insert(
        `INSERT INTO network_events (user_id, device_id, occurred_at, source_ip, destination_domain, bytes_out, bytes_in, process_name)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'red-web')`,
        [userId, deviceId, when(occurredAt), text(ip, 64), text(destinationDomain), count(bytesOut) ?? 0, count(bytesIn) ?? 0],
      );
    },

    // Aggregated micro-behaviour. Raw keystrokes and pointer paths never leave the browser;
    // only the timing statistics in this row do.
    biometric({ userId, sessionId, deviceId, windowStart, windowSeconds, keystrokeIntervalMeanMs, keystrokeIntervalStdMs,
      keyDwellMeanMs, mouseVelocityMeanPxS, mouseVelocityStdPxS, scrollEvents, scrollVelocityMean, appSwitches,
      idleSeconds, openWindowCount, copyPasteEvents }) {
      return insert(
        `INSERT INTO biometric_samples
           (user_id, session_id, device_id, window_start, window_seconds, keystroke_interval_mean_ms, keystroke_interval_std_ms,
            key_dwell_mean_ms, mouse_velocity_mean_px_s, mouse_velocity_std_px_s, scroll_events, scroll_velocity_mean,
            app_switches, idle_seconds, open_window_count, copy_paste_events)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, sessionId, deviceId, when(windowStart), count(windowSeconds) || 300, real(keystrokeIntervalMeanMs),
          real(keystrokeIntervalStdMs), real(keyDwellMeanMs), real(mouseVelocityMeanPxS), real(mouseVelocityStdPxS),
          count(scrollEvents), real(scrollVelocityMean), count(appSwitches), count(idleSeconds), count(openWindowCount),
          count(copyPasteEvents)],
      );
    },

    privilege({ userId, targetUserId, resourceId, ticketId, eventType, occurredAt, targetGroup, systemName, details }) {
      return insert(
        `INSERT INTO privilege_events
           (user_id, target_user_id, resource_id, ticket_id, event_type, occurred_at, target_group, system_name, details)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, targetUserId ?? null, resourceId ?? null, ticketId ?? null, eventType, when(occurredAt),
          text(targetGroup, 64), text(systemName, 64), JSON.stringify(details || {})],
      );
    },

    // Used for the text people write inside Red, which is the only "message" the app has.
    communication({ userId, channel, eventType, occurredAt, isExternal, recipientCount, attachmentCount, attachmentBytes, sensitiveKeywordHits }) {
      return insert(
        `INSERT INTO communication_events
           (user_id, channel, event_type, occurred_at, is_external, recipient_count, attachment_count, attachment_bytes, sensitive_keyword_hits)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, channel, eventType, when(occurredAt), Boolean(isExternal), count(recipientCount), count(attachmentCount) ?? 0,
          count(attachmentBytes) ?? 0, count(sensitiveKeywordHits) ?? 0],
      );
    },
  };
}

module.exports = { createEvents };
