'use strict';

// Builds the SQLite version of the CrimGuard schema from the PostgreSQL files in
// database/crimguard/, so there is one source of truth and the two can't drift apart.
// Views and triggers that use PostgreSQL-only syntax are swapped for the hand-written
// SQLite versions in database/crimguard/sqlite/. Anything this translator doesn't
// recognise throws, rather than producing a schema that silently differs.

const fs = require('node:fs');
const path = require('node:path');

const SCHEMA_DIR = path.join(__dirname, '..', '..', 'database', 'crimguard');
const SQLITE_DIR = path.join(SCHEMA_DIR, 'sqlite');

// ISO 8601 UTC, the same text the PostgreSQL adapter returns for TIMESTAMPTZ columns.
const SQLITE_NOW = "(strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))";

const POSTGRES_ONLY = /::|\bLATERAL\b|\barray_agg\b|\bFILTER\s*\(|\bILIKE\b|\bDISTINCT\s+ON\b|\bnow\(\)|\bplpgsql\b/i;

const sqlFiles = (dir) =>
  fs.readdirSync(dir).filter((file) => /^\d+_.*\.sql$/.test(file)).sort().map((file) => path.join(dir, file));

// Skips over a quoted string or identifier starting at `start`; returns the index of its closing quote.
function closingQuote(sql, start) {
  const quote = sql[start];
  let i = start + 1;
  while (i < sql.length && !(sql[i] === quote && sql[i + 1] !== quote)) i += sql[i] === quote ? 2 : 1;
  return i;
}

// Splits a script into statements and drops -- comments. Semicolons inside quotes,
// $$ bodies and SQLite trigger BEGIN ... END blocks don't end a statement.
function splitStatements(sql) {
  const statements = [];
  let current = '';
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (ch === '-' && sql[i + 1] === '-') {
      const end = sql.indexOf('\n', i);
      i = end === -1 ? sql.length : end - 1;
    } else if (ch === "'" || ch === '"') {
      const end = closingQuote(sql, i);
      current += sql.slice(i, end + 1);
      i = end;
    } else if (ch === '$' && sql[i + 1] === '$') {
      const end = sql.indexOf('$$', i + 2);
      if (end === -1) throw new Error('Unterminated $$ block');
      current += sql.slice(i, end + 2);
      i = end + 1;
    } else if (ch === ';' && !(/^\s*CREATE\s+TRIGGER\b[\s\S]*\bBEGIN\b/i.test(current) && !/\bEND\s*$/i.test(current))) {
      if (current.trim()) statements.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) statements.push(current.trim());
  return statements;
}

// Applies `transform` to every stretch of SQL outside quotes.
function mapOutsideQuotes(sql, transform) {
  let out = '';
  let code = '';
  for (let i = 0; i < sql.length; i++) {
    if (sql[i] !== "'" && sql[i] !== '"') {
      code += sql[i];
      continue;
    }
    const end = closingQuote(sql, i);
    out += transform(code) + sql.slice(i, end + 1);
    code = '';
    i = end;
  }
  return out + transform(code);
}

// The SQL with every quoted string and identifier removed, for syntax checks.
function codeOnly(sql) {
  let code = '';
  mapOutsideQuotes(sql, (part) => {
    code += part;
    return part;
  });
  return code;
}

// Index of the ")" matching the "(" at `open`.
function closingParen(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "'" || text[i] === '"') i = closingQuote(text, i);
    else if (text[i] === '(') depth++;
    else if (text[i] === ')' && --depth === 0) return i;
  }
  throw new Error(`Unbalanced parentheses in: ${text.slice(open, open + 80)}`);
}

// Splits on commas that aren't inside parentheses or quotes.
function splitTopLevel(text) {
  const parts = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "'" || text[i] === '"') i = closingQuote(text, i);
    else if (text[i] === '(') depth++;
    else if (text[i] === ')') depth--;
    else if (text[i] === ',' && depth === 0) {
      parts.push(text.slice(start, i).trim());
      start = i + 1;
    }
  }
  parts.push(text.slice(start).trim());
  return parts.filter(Boolean);
}

// num_nonnulls(a, b) = 1  ->  ((a IS NOT NULL) + (b IS NOT NULL)) = 1
function expandNumNonnulls(sql) {
  let out = sql;
  for (let at = out.search(/\bnum_nonnulls\s*\(/i); at !== -1; at = out.search(/\bnum_nonnulls\s*\(/i)) {
    const open = out.indexOf('(', at);
    const close = closingParen(out, open);
    const args = splitTopLevel(out.slice(open + 1, close)).map((arg) => `(${arg} IS NOT NULL)`);
    out = `${out.slice(0, at)}(${args.join(' + ')})${out.slice(close + 1)}`;
  }
  return out;
}

const normalizeSpace = (sql) => sql.replace(/\s+/g, ' ').trim();

// PostgreSQL type -> SQLite declared type. BOOLEAN and JSONB are kept as declared type
// names because src/db/crimguard.js reads them to return true/false and parsed JSON.
const TYPES = [
  [/^BIGINT\s+GENERATED\s+ALWAYS\s+AS\s+IDENTITY\s+PRIMARY\s+KEY\b/i, 'INTEGER PRIMARY KEY AUTOINCREMENT', null],
  [/^(BIGINT|INTEGER|SMALLINT)\b/i, 'INTEGER', null],
  [/^DOUBLE\s+PRECISION\b/i, 'REAL', null],
  [/^NUMERIC(\s*\(\s*\d+\s*,\s*\d+\s*\))?/i, 'NUMERIC', null],
  [/^BOOLEAN\b/i, 'BOOLEAN', (col) => `CHECK (${col} IN (0, 1))`],
  [/^TIMESTAMPTZ\b/i, 'TIMESTAMPTZ', null],
  [/^DATE\b/i, 'DATE', null],
  [/^TIME\b/i, 'TIME', null],
  [/^TEXT\s*\[\s*\]/i, 'JSONB', (col) => `CHECK (json_valid(${col}) AND json_type(${col}) = 'array')`],
  [/^TEXT\b/i, 'TEXT', null],
  [/^CHAR\s*\(\s*\d+\s*\)/i, 'TEXT', null],
  [/^INET\b/i, 'TEXT', null],
  [/^JSONB\b/i, 'JSONB', (col) => `CHECK (json_valid(${col}))`],
];

function translateColumn(definition, enums, table) {
  const match = definition.match(/^(\w+)\s+([\s\S]+)$/);
  if (!match) throw new Error(`Can't parse column in ${table}: ${definition}`);
  const [, name, rest] = match;

  let type;
  let check = null;
  let constraints;
  const typeRule = TYPES.find(([pattern]) => pattern.test(rest));
  if (typeRule) {
    const [pattern, sqliteType, makeCheck] = typeRule;
    type = sqliteType;
    constraints = rest.replace(pattern, '');
    check = makeCheck && makeCheck(name);
  } else {
    const enumName = rest.match(/^(\w+)/)[1];
    if (!enums.has(enumName)) throw new Error(`Unknown type "${enumName}" for ${table}.${name}`);
    type = 'TEXT';
    constraints = rest.slice(enumName.length);
    check = `CHECK (${name} IN (${enums.get(enumName).map((value) => `'${value}'`).join(', ')}))`;
  }

  constraints = expandNumNonnulls(constraints)
    .replace(/\bDEFAULT\s+now\(\)/gi, `DEFAULT ${SQLITE_NOW}`)
    .replace(/\bDEFAULT\s+('(?:[^']|'')*')::jsonb\b/gi, 'DEFAULT $1')
    .replace(/\bDEFAULT\s+true\b/gi, 'DEFAULT 1')
    .replace(/\bDEFAULT\s+false\b/gi, 'DEFAULT 0');
  if (POSTGRES_ONLY.test(codeOnly(constraints))) {
    throw new Error(`PostgreSQL-only syntax in ${table}.${name}: ${constraints}`);
  }

  const kind = type === 'BOOLEAN' ? 'boolean' : type === 'JSONB' ? 'json' : null;
  return {
    column: { name, kind },
    sql: normalizeSpace([name, type, constraints, check].filter(Boolean).join(' ')),
  };
}

function translateTable(statement, enums) {
  const match = statement.match(/^CREATE\s+TABLE\s+(\w+)\s*\(/i);
  const table = match[1];
  const open = statement.indexOf('(');
  const close = closingParen(statement, open);
  if (statement.slice(close + 1).trim()) throw new Error(`Unsupported table options on ${table}`);

  const columns = [];
  const lines = [];
  const extraIndexes = [];
  for (const element of splitTopLevel(statement.slice(open + 1, close))) {
    const nullsNotDistinct = element.match(/^UNIQUE\s+NULLS\s+NOT\s+DISTINCT\s*\(([^)]*)\)$/i);
    if (nullsNotDistinct) {
      // SQLite always treats NULLs as distinct in UNIQUE, so index the NULLs as a value instead.
      const cols = nullsNotDistinct[1].split(',').map((col) => col.trim());
      extraIndexes.push(
        `CREATE UNIQUE INDEX ${table}_${cols.join('_')}_key ON ${table} (${cols.map((col) => `IFNULL(${col}, '')`).join(', ')})`,
      );
    } else if (/^(CHECK|UNIQUE|PRIMARY\s+KEY|FOREIGN\s+KEY)\b/i.test(element)) {
      lines.push(normalizeSpace(expandNumNonnulls(element)));
    } else {
      const { column, sql } = translateColumn(element, enums, table);
      columns.push(column);
      lines.push(sql);
    }
  }
  return {
    table: { name: table, columns },
    sql: [`CREATE TABLE ${table} (\n    ${lines.join(',\n    ')}\n)`, ...extraIndexes],
  };
}

function translateIndex(statement) {
  const match = statement.match(/^CREATE\s+(UNIQUE\s+)?INDEX\s+(\w+)\s+ON\s+(\w+)(?:\s+USING\s+(\w+))?\s*\(/i);
  if (!match) throw new Error(`Can't parse index: ${statement}`);
  const [, unique = '', name, table, method] = match;
  // BRIN is a PostgreSQL storage optimisation; an ordinary index serves the same queries.
  if (method && !/^(btree|brin)$/i.test(method)) throw new Error(`No SQLite equivalent for USING ${method} (${name})`);
  const open = statement.indexOf('(', match[0].length - 1);
  const close = closingParen(statement, open);
  const where = statement.slice(close + 1).trim();
  if (where && !/^WHERE\b/i.test(where)) throw new Error(`Unsupported index clause on ${name}: ${where}`);
  return normalizeSpace(`CREATE ${unique.toUpperCase()}INDEX ${name} ON ${table} ${statement.slice(open, close + 1)} ${where}`);
}

function objectName(statement, kind) {
  const match = statement.match(new RegExp(`^CREATE\\s+(?:OR\\s+REPLACE\\s+)?${kind}\\s+(\\w+)`, 'i'));
  return match && match[1];
}

function readOverrides() {
  const overrides = new Map();
  for (const file of sqlFiles(SQLITE_DIR)) {
    for (const statement of splitStatements(fs.readFileSync(file, 'utf8'))) {
      const name = objectName(statement, 'VIEW') || objectName(statement, 'TRIGGER');
      if (!name) throw new Error(`${path.basename(file)} may only contain CREATE VIEW and CREATE TRIGGER: ${statement.slice(0, 80)}`);
      overrides.set(name, statement);
    }
  }
  return overrides;
}

// Returns { sql, tables } where tables lists every table's columns in PostgreSQL order.
function buildSqliteSchema() {
  const enums = new Map();
  const overrides = readOverrides();
  const used = new Set();
  const tables = [];
  const output = [];

  const override = (name) => {
    if (!overrides.has(name)) return null;
    used.add(name);
    return overrides.get(name);
  };

  for (const file of sqlFiles(SCHEMA_DIR)) {
    for (const statement of splitStatements(fs.readFileSync(file, 'utf8'))) {
      const where = `${path.basename(file)}: ${statement.slice(0, 60).replace(/\s+/g, ' ')}`;

      if (/^CREATE\s+TYPE\s+\w+\s+AS\s+ENUM\b/i.test(statement)) {
        const [, name, body] = statement.match(/^CREATE\s+TYPE\s+(\w+)\s+AS\s+ENUM\s*\(([\s\S]*)\)$/i);
        enums.set(name, splitTopLevel(body).map((value) => value.replace(/^'|'$/g, '')));
      } else if (/^CREATE\s+TABLE\b/i.test(statement)) {
        const { table, sql } = translateTable(statement, enums);
        tables.push(table);
        output.push(...sql);
      } else if (/^CREATE\s+(UNIQUE\s+)?INDEX\b/i.test(statement)) {
        output.push(translateIndex(statement));
      } else if (objectName(statement, 'VIEW')) {
        const name = objectName(statement, 'VIEW');
        const replacement = override(name);
        if (!replacement && POSTGRES_ONLY.test(codeOnly(statement))) {
          throw new Error(`View ${name} uses PostgreSQL-only syntax. Add a SQLite version to database/crimguard/sqlite/.`);
        }
        output.push(replacement || statement);
      } else if (objectName(statement, 'TRIGGER')) {
        const name = objectName(statement, 'TRIGGER');
        const replacement = override(name);
        if (!replacement) throw new Error(`Trigger ${name} needs a SQLite version in database/crimguard/sqlite/.`);
        output.push(replacement);
      } else if (objectName(statement, 'FUNCTION')) {
        // PL/pgSQL functions only back triggers, which have SQLite versions above.
      } else if (/^INSERT\s+INTO\b/i.test(statement)) {
        const sql = mapOutsideQuotes(statement, (code) => {
          if (code.includes('::')) throw new Error(`PostgreSQL cast in ${where}`);
          return code.replace(/\btrue\b/gi, '1').replace(/\bfalse\b/gi, '0');
        });
        output.push(sql);
      } else {
        throw new Error(`Unsupported statement in ${where}`);
      }
    }
  }

  const unused = [...overrides.keys()].filter((name) => !used.has(name));
  if (unused.length) throw new Error(`SQLite versions with no PostgreSQL counterpart: ${unused.join(', ')}`);

  const header = '-- Generated from database/crimguard/*.sql by src/db/sqlite-schema.js. Do not edit.';
  return { sql: `${header}\n${output.join(';\n\n')};\n`, tables };
}

module.exports = { buildSqliteSchema, mapOutsideQuotes, SCHEMA_DIR };
