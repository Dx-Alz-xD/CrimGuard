'use strict';

const fs = require('node:fs');
const path = require('node:path');

const CATALOG_SQL = path.join(__dirname, '..', '..', 'database', 'crimguard', '05_feature_catalog.sql');

// Feature value types the anomaly detectors can score. Dates, categories and tenure are HR context.
const SCORABLE_TYPES = new Set(['count', 'flag', 'ratio', 'score', 'volume_mb', 'seconds']);

// Accepts rows as they come out of the feature_catalog table (snake_case, NUMERIC as strings).
function normalizeCatalog(rows) {
  return rows.map((row) => ({
    key: row.feature_key,
    category: row.category,
    valueType: row.value_type,
    signalRole: row.signal_role ?? 'indicator',
    direction: row.anomaly_direction ?? 'high',
    contextExplainable: row.context_explainable === true || row.context_explainable === 't',
    zThreshold: row.default_z_threshold == null ? null : Number(row.default_z_threshold),
  }));
}

// Reads the INSERT in 05_feature_catalog.sql, so the engine can run against the real catalog without
// a database. Each tuple sits on one line; strings use SQL '' escaping.
function parseFeatureCatalogSql(sql) {
  const start = sql.indexOf('INSERT INTO feature_catalog');
  if (start < 0) throw new Error('No INSERT INTO feature_catalog found');
  const body = sql.slice(start);
  const columns = /\(([^)]*)\)\s*VALUES/.exec(body)[1].split(',').map((c) => c.trim());

  const rows = [];
  for (const line of body.split('\n')) {
    const m = /^\((.*)\)[,;]\s*$/.exec(line.trim());
    if (!m) continue;
    const values = splitSqlTuple(m[1]);
    if (values.length !== columns.length) throw new Error(`Expected ${columns.length} values: ${line}`);
    rows.push(Object.fromEntries(columns.map((c, i) => [c, values[i]])));
  }
  return rows;
}

function splitSqlTuple(text) {
  const values = [];
  let i = 0;
  while (i < text.length) {
    while (text[i] === ' ' || text[i] === ',') i++;
    if (i >= text.length) break;
    if (text[i] === "'") {
      let s = '';
      for (i++; i < text.length; i++) {
        if (text[i] === "'" && text[i + 1] === "'") { s += "'"; i++; } else if (text[i] === "'") break; else s += text[i];
      }
      values.push(s);
      i++;
    } else {
      const end = text.indexOf(',', i);
      const raw = text.slice(i, end < 0 ? text.length : end).trim();
      i = end < 0 ? text.length : end;
      values.push(raw === 'NULL' ? null : raw === 'true' ? true : raw === 'false' ? false : Number(raw));
    }
  }
  return values;
}

function loadFeatureCatalog(file = CATALOG_SQL) {
  return normalizeCatalog(parseFeatureCatalogSql(fs.readFileSync(file, 'utf8')));
}

module.exports = { SCORABLE_TYPES, normalizeCatalog, parseFeatureCatalogSql, loadFeatureCatalog };
