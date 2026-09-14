'use strict';

// Shadow AI: work leaving the organisation into a model nobody sanctioned.
//
// ---------------------------------------------------------------------------------------------
// What Red can and cannot see, said plainly, because the difference decides how this is built.
//
// Red is a website. Its collector runs inside its own pages and sees its own pages: it cannot read
// another tab, another application, or a browser extension, and no amount of JavaScript changes
// that. So Red can see, first-hand and with certainty:
//
//   * that a selection was copied *out of* one of its documents, how large it was, which project
//     and file it came from, how confidential that file is, and whether it carried anything
//     secret-shaped.
//
// and it cannot see, ever, on its own:
//
//   * where that clipboard went afterwards.
//
// The honest shape of the feature is therefore two halves that meet in the middle. Red measures
// the half it owns - the document leaving the page - and accepts the other half from something
// that can actually watch the endpoint: a managed browser extension, an EDR agent, or a DLP or
// forward proxy, all of which already exist in a real deployment and any of which can POST what it
// saw to /api/telemetry/egress. Where the two line up, the answer is no longer "a document left
// the page" but "this document went into that model", which is the thing worth an alert.
//
// Where nothing reports, the destination stays NULL - not "safe". That is the same rule the rest
// of the pipeline keeps (telemetry/coverage.js): "no DLP proxy" and "nothing was uploaded" are
// different facts, and writing the first as the second would quietly clear an account nobody
// watched. `external_upload_volume_mb` and `personal_cloud_transfer_flag` are NULL today for
// exactly this reason, and they fill in the moment a reporter exists.
// ---------------------------------------------------------------------------------------------

// Hosts whose whole purpose is to take text and give back a model's answer. Matched on the
// registrable suffix, so any subdomain counts. The list is a default: an organisation keeps its
// own in external_domains, where a sanctioned enterprise tenant can be marked as such and stops
// counting against anyone.
const GENAI_DOMAINS = Object.freeze([
  // Assistants and chat front ends
  'openai.com', 'chatgpt.com', 'claude.ai', 'anthropic.com', 'gemini.google.com', 'bard.google.com',
  'copilot.microsoft.com', 'bing.com/chat', 'perplexity.ai', 'poe.com', 'character.ai', 'pi.ai',
  'mistral.ai', 'chat.mistral.ai', 'deepseek.com', 'chat.deepseek.com', 'x.ai', 'grok.com',
  'meta.ai', 'huggingface.co', 'cohere.com', 'you.com', 'phind.com', 'kagi.com',
  // Coding assistants that accept pasted source
  'github.com/copilot', 'cursor.sh', 'cursor.com', 'codeium.com', 'tabnine.com', 'replit.com',
  'v0.dev', 'bolt.new', 'lovable.dev',
  // Writing and document tools that send content to a model
  'notion.so/ai', 'jasper.ai', 'copy.ai', 'quillbot.com', 'grammarly.com', 'writesonic.com',
  'gamma.app', 'tome.app', 'otter.ai', 'fireflies.ai',
  // Direct API endpoints, which is what a script rather than a person would use
  'api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com', 'api.groq.com',
  'api.together.xyz', 'api.replicate.com', 'openrouter.ai', 'api.deepseek.com',
]);

// Extension ids that wrap a model and read page content. An endpoint agent reports these by id.
const GENAI_EXTENSIONS = Object.freeze({
  // Chrome
  bjgnpmlflfnpldpnhlmlkbaebnhchnnn: 'ChatGPT for Google',
  cbgecfllfhmmnknmamkejadjmnmpfjmp: 'Merlin AI',
  oallhdmefljfmoncmbpghaogmlbfglfp: 'Sider AI',
  dhoenijjpgpeimemopealfcbiecgceod: 'Monica AI',
  jbmelbbnmohpfdmkcdhmmldjegiadgle: 'Compose AI',
  hmbnhhjkfkhbllabhcncbpcgoeadpgfa: 'Harpa AI',
});

// The other destinations worth telling apart, so "shadow AI" stays a specific claim rather than a
// synonym for "anywhere we do not run".
const CATEGORIES = Object.freeze({
  GENAI: 'genai_llm',
  PERSONAL_CLOUD: 'personal_cloud',
  WEBMAIL: 'webmail',
  FILE_SHARING: 'file_sharing',
  EPHEMERAL: 'ephemeral_messaging',
  OTHER: 'other',
});

const PERSONAL_CLOUD = Object.freeze(['drive.google.com', 'dropbox.com', 'box.com', 'icloud.com', 'mega.nz', 'pcloud.com', 'sync.com']);
const WEBMAIL = Object.freeze(['mail.google.com', 'gmail.com', 'outlook.com', 'outlook.live.com', 'mail.yahoo.com', 'proton.me', 'protonmail.com', 'zoho.com']);
const FILE_SHARING = Object.freeze(['wetransfer.com', 'file.io', 'transfer.sh', 'anonfiles.com', 'gofile.io', 'sendgb.com']);
const EPHEMERAL = Object.freeze(['pastebin.com', 'privnote.com', 'telegram.org', 'web.telegram.org', 'signal.org', 'ghostbin.com', 'dpaste.com']);

// Volume at which one copy stops looking like quoting a line and starts looking like handing over a
// document. About a page and a half of prose.
const LARGE_PASTE_CHARS = 4000;
// Several large copies inside this window is the shape of feeding a document in piece by piece,
// which is what a model's context limit makes people do.
const BURST_WINDOW_MS = 5 * 60 * 1000;
const BURST_COPIES = 3;
const BURST_CHARS = 10_000;

// Strips scheme, credentials, port and path so a destination reported as a URL, a bare host or an
// app name all reduce to the same thing.
function hostOf(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  let text = value.trim().toLowerCase();
  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  text = text.split('@').pop();
  text = text.split(/[/?#]/)[0];
  text = text.split(':')[0];
  return text || null;
}

// True when `host` is the domain itself or a subdomain of it, never when it merely ends with the
// same letters: "notopenai.com" is not openai.com.
const under = (host, domain) => host === domain || host.endsWith(`.${domain}`);

// Some entries carry a path ("github.com/copilot"), which only a full URL can match.
function matchesEntry(value, host, entry) {
  if (!entry.includes('/')) return under(host, entry);
  const [domain, ...rest] = entry.split('/');
  const path = `/${rest.join('/')}`;
  return under(host, domain) && String(value).toLowerCase().includes(path);
}

const inList = (value, host, list) => list.some((entry) => matchesEntry(value, host, entry));

// What a destination is. `extensionId` comes from an endpoint agent that can see which extension
// made the request; a domain alone is enough for everything else.
function classify(destination, { extensionId = null, known = [] } = {}) {
  if (extensionId && Object.hasOwn(GENAI_EXTENSIONS, extensionId)) {
    return { category: CATEGORIES.GENAI, app: GENAI_EXTENSIONS[extensionId], host: null, sanctioned: false, via: 'extension' };
  }
  const host = hostOf(destination);
  if (!host) return { category: null, app: null, host: null, sanctioned: false, via: null };

  // An organisation's own list wins: a sanctioned enterprise tenant is not shadow AI.
  for (const row of known) {
    if (row.domain && under(host, String(row.domain).toLowerCase())) {
      return { category: row.category, app: row.app_name || null, host, sanctioned: Boolean(row.is_sanctioned), via: 'org' };
    }
  }

  if (inList(destination, host, GENAI_DOMAINS)) return { category: CATEGORIES.GENAI, app: host, host, sanctioned: false, via: 'default' };
  if (inList(destination, host, PERSONAL_CLOUD)) return { category: CATEGORIES.PERSONAL_CLOUD, app: host, host, sanctioned: false, via: 'default' };
  if (inList(destination, host, WEBMAIL)) return { category: CATEGORIES.WEBMAIL, app: host, host, sanctioned: false, via: 'default' };
  if (inList(destination, host, FILE_SHARING)) return { category: CATEGORIES.FILE_SHARING, app: host, host, sanctioned: false, via: 'default' };
  if (inList(destination, host, EPHEMERAL)) return { category: CATEGORIES.EPHEMERAL, app: host, host, sanctioned: false, via: 'default' };
  return { category: CATEGORIES.OTHER, app: host, host, sanctioned: false, via: 'default' };
}

// Shadow AI is specifically an unsanctioned model: the sanctioned enterprise tenant an
// organisation pays for is the thing people are supposed to use instead.
const isShadowAi = (verdict) => verdict.category === CATEGORIES.GENAI && !verdict.sanctioned;

// How much a single reported egress is worth worrying about, given what went and where. Returns a
// severity and the reasons behind it, so an alert can say why rather than only how much.
function assess({ destination, extensionId = null, known = [], chars = 0, bytes = 0, sensitivity = null, patterns = [], document: doc = null }) {
  const verdict = classify(destination, { extensionId, known });
  const reasons = [];
  let severity = 0;

  if (isShadowAi(verdict)) {
    severity += 2;
    reasons.push(`Unsanctioned model: ${verdict.app || verdict.host}`);
  } else if (verdict.category && verdict.category !== CATEGORIES.OTHER && !verdict.sanctioned) {
    severity += 1;
    reasons.push(`Unsanctioned ${verdict.category.replace(/_/g, ' ')}: ${verdict.app || verdict.host}`);
  }

  const size = Math.max(Number(chars) || 0, Number(bytes) || 0);
  if (size >= LARGE_PASTE_CHARS) {
    severity += 1;
    reasons.push(`${size.toLocaleString('en')} characters in one go`);
  }
  // A file out of Red is the claim the whole feature is for: this document, that model.
  if (doc) {
    severity += 1;
    reasons.push(`From "${doc.name}"${doc.project ? ` in ${doc.project}` : ''}`);
  }
  if (Number(sensitivity) >= 4) {
    severity += 2;
    reasons.push(`The document is level ${sensitivity}`);
  } else if (Number(sensitivity) === 3) {
    severity += 1;
    reasons.push('The document is Confidential');
  }
  if (patterns.length) {
    severity += 2;
    reasons.push(`Secret-shaped content: ${patterns.slice(0, 4).join(', ')}`);
  }

  return {
    ...verdict,
    shadowAi: isShadowAi(verdict),
    severity: Math.min(10, severity),
    level: severity >= 6 ? 'critical' : severity >= 4 ? 'high' : severity >= 2 ? 'medium' : 'low',
    reasons,
  };
}

// Several large copies close together: one document handed over in the pieces a context window
// forces, rather than one careless paste. Takes events newest-first or oldest-first.
function burstsIn(events, { windowMs = BURST_WINDOW_MS, minCopies = BURST_COPIES, minChars = BURST_CHARS } = {}) {
  const sorted = [...events]
    .map((event) => ({ at: Date.parse(event.occurredAt ?? event.occurred_at), chars: Number(event.chars ?? event.char_count) || 0 }))
    .filter((event) => Number.isFinite(event.at))
    .sort((a, b) => a.at - b.at);

  const bursts = [];
  let start = 0;
  for (let end = 0; end < sorted.length; end += 1) {
    while (sorted[end].at - sorted[start].at > windowMs) start += 1;
    const window = sorted.slice(start, end + 1);
    const chars = window.reduce((sum, event) => sum + event.chars, 0);
    if (window.length >= minCopies && chars >= minChars) {
      const last = bursts.at(-1);
      // One growing burst, not one per event inside it.
      if (last && last.endedAt >= sorted[start].at) {
        last.endedAt = sorted[end].at;
        last.copies = window.length;
        last.chars = chars;
      } else {
        bursts.push({ startedAt: sorted[start].at, endedAt: sorted[end].at, copies: window.length, chars });
      }
    }
  }
  return bursts;
}

module.exports = {
  GENAI_DOMAINS, GENAI_EXTENSIONS, CATEGORIES,
  LARGE_PASTE_CHARS, BURST_WINDOW_MS, BURST_COPIES, BURST_CHARS,
  hostOf, classify, isShadowAi, assess, burstsIn,
};
