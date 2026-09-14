'use strict';

// Which decoy to put in front of a particular person.
//
// A decoy only works if it is the thing *this* person would reach for. Someone searching for
// salary bands is shown compensation data; someone pasting source into an AI tool is shown a
// deploy token; an admin misusing their access is shown break-glass credentials. The choice is
// scored from what CrimGuard already knows - role, job title, recent searches, the scenario the
// engine assigned, the features that drove the score - and is recorded with the planting, so an
// investigator can see why that decoy was chosen.
//
// Tiers set how valuable a decoy may be: a vague suspicion earns a document, a strong one earns
// working-looking credentials.

const LURES = [
  {
    theme: 'compensation',
    tier: 1,
    canary: 'document_link',
    title: 'Compensation bands & bonus pool FY26 (draft)',
    documentName: 'comp-bands-fy26-draft',
    description: 'Salary bands, bonus multipliers and equity refresh by level. Draft for the leadership review - not final.',
    keywords: ['salary', 'salaries', 'payroll', 'compensation', 'bonus', 'raise', 'promotion', 'equity', 'severance', 'pay'],
    scenarios: ['pre_resignation_hoarding'],
    features: ['unusual_search_query_count', 'sensitive_keyword_message_count'],
    roles: [],
  },
  {
    theme: 'customer_export',
    tier: 1,
    canary: 'document_link',
    title: 'Customer master list - contracts & named contacts',
    documentName: 'customer-master-export',
    description: 'Full export from the CRM: account owners, contract values, renewal dates and direct contacts.',
    keywords: ['customer', 'customers', 'client', 'clients', 'contact', 'contacts', 'crm', 'pricing', 'deal', 'accounts', 'export'],
    scenarios: ['pre_resignation_hoarding', 'slow_exfiltration'],
    features: ['files_accessed_count', 'daily_download_volume_mb', 'download_volume_vs_baseline', 'confidential_resource_access_count'],
    roles: [],
  },
  {
    theme: 'restructuring',
    tier: 1,
    canary: 'document_link',
    title: 'Restructuring plan - board pack (confidential)',
    documentName: 'restructuring-board-pack',
    description: 'Proposed team changes, role reductions and timeline, as presented to the board.',
    keywords: ['layoff', 'layoffs', 'redundancy', 'restructuring', 'reorg', 'merger', 'acquisition', 'board', 'termination'],
    scenarios: ['pre_resignation_hoarding'],
    features: ['sensitive_keyword_message_count'],
    roles: [],
  },
  {
    theme: 'cloud_keys',
    tier: 2,
    canary: 'aws_access_key',
    title: 'AWS production access keys',
    service: 'Exports pipeline',
    description: 'Programmatic access for the production exports account. Rotated quarterly.',
    keywords: ['aws', 'cloud', 's3', 'bucket', 'infrastructure', 'deploy', 'key', 'keys', 'api', 'prod', 'production'],
    scenarios: ['shadow_ai_leak', 'credential_compromise'],
    features: ['large_clipboard_copy_event_count', 'unauthorized_app_usage_flag', 'external_upload_volume_mb'],
    roles: ['admin'],
  },
  {
    theme: 'payment_keys',
    tier: 2,
    canary: 'stripe_live_key',
    title: 'Stripe live keys - billing service',
    service: 'Billing service',
    description: 'Live secret key and webhook secret for the billing service. Finance and platform only.',
    keywords: ['stripe', 'billing', 'payment', 'payments', 'invoice', 'invoices', 'finance', 'revenue', 'card'],
    scenarios: ['credential_compromise'],
    features: ['external_upload_volume_mb'],
    roles: [],
  },
  {
    theme: 'source_token',
    tier: 2,
    canary: 'github_token',
    title: 'GitHub org deploy token',
    description: 'CI token with repo and workflow scope for every repository in the organisation.',
    keywords: ['github', 'git', 'repo', 'repository', 'source', 'code', 'ci', 'pipeline', 'token', 'deploy'],
    scenarios: ['shadow_ai_leak'],
    features: ['large_clipboard_copy_event_count', 'copy_paste_frequency_volume', 'unauthorized_app_usage_flag'],
    roles: [],
  },
  {
    theme: 'chat_token',
    tier: 2,
    canary: 'slack_bot_token',
    title: 'Slack bot token - #exec-updates integration',
    description: 'Bot token for the integration that posts to the executive updates channel.',
    keywords: ['slack', 'chat', 'bot', 'channel', 'integration', 'exec', 'executive', 'webhook'],
    scenarios: [],
    features: ['external_message_increase_score', 'competitor_domain_contact_count'],
    roles: [],
  },
  {
    theme: 'database_credentials',
    tier: 3,
    canary: 'database_url',
    title: 'Reporting database - read/write service account',
    database: 'reporting',
    description: 'Connection string for the reporting warehouse service account used by the nightly exports.',
    keywords: ['database', 'db', 'sql', 'postgres', 'warehouse', 'report', 'reports', 'analytics', 'migration', 'query'],
    scenarios: ['slow_exfiltration', 'privilege_abuse'],
    features: ['files_accessed_count', 'distinct_resource_types_touched', 'out_of_scope_resource_access_count'],
    roles: [],
  },
  {
    theme: 'break_glass',
    tier: 3,
    canary: 'service_account',
    title: 'Break-glass administrator credentials',
    description: 'Emergency administrator login for outages. Every use is reviewed.',
    keywords: ['admin', 'administrator', 'password', 'passwords', 'credential', 'credentials', 'vault', 'root', 'access', 'break glass'],
    scenarios: ['privilege_abuse', 'credential_compromise'],
    features: ['privilege_escalation_request_count', 'admin_panel_access_flag', 'permission_change_count', 'least_privilege_violation_flag'],
    roles: ['admin'],
  },
];

const WEIGHTS = { base: 1, keyword: 3, keywordCap: 3, scenario: 4, feature: 1.5, role: 1, title: 2, recentlyUsed: -5 };

const words = (text) => String(text || '').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

function matchesKeyword(keyword, haystackWords, haystackText) {
  return keyword.includes(' ') ? haystackText.includes(keyword) : haystackWords.has(keyword);
}

// profile: { role, jobTitle, department, searchTerms[], scenario, topFeatures[], recentThemes[] }
function scoreLure(lure, profile) {
  const reasons = [];
  let score = WEIGHTS.base;

  const searchText = (profile.searchTerms || []).join(' ').toLowerCase();
  const searchWords = new Set(words(searchText));
  const hits = lure.keywords.filter((k) => matchesKeyword(k, searchWords, searchText));
  if (hits.length) {
    score += WEIGHTS.keyword * Math.min(hits.length, WEIGHTS.keywordCap);
    reasons.push(`searched for ${hits.slice(0, 3).map((h) => `"${h}"`).join(', ')}`);
  }

  const titleText = `${profile.jobTitle || ''} ${profile.department || ''}`.toLowerCase();
  const titleHits = lure.keywords.filter((k) => matchesKeyword(k, new Set(words(titleText)), titleText));
  if (titleHits.length) {
    score += WEIGHTS.title;
    reasons.push(`works in ${(profile.jobTitle || profile.department).trim()}`);
  }

  if (profile.scenario && lure.scenarios.includes(profile.scenario)) {
    score += WEIGHTS.scenario;
    reasons.push(`risk scenario is ${profile.scenario.replace(/_/g, ' ')}`);
  }

  const featureHits = lure.features.filter((f) => (profile.topFeatures || []).includes(f));
  if (featureHits.length) {
    score += WEIGHTS.feature * featureHits.length;
    reasons.push(`score driven by ${featureHits.join(', ')}`);
  }

  if (profile.role && lure.roles.includes(profile.role)) {
    score += WEIGHTS.role;
    reasons.push(`${profile.role} account`);
  }

  if ((profile.recentThemes || []).includes(lure.theme)) {
    score += WEIGHTS.recentlyUsed;
    reasons.push('used for this person before');
  }

  return { score, reasons };
}

// The best lure at or below `tier`. `jitter()` returns [0, 1); it breaks ties so the choice
// can't be predicted by someone who has read this file and knows their own profile.
function chooseLure(profile, { tier, jitter = Math.random, exclude = [] } = {}) {
  const candidates = LURES
    .filter((lure) => lure.tier <= tier && !exclude.includes(lure.theme))
    .map((lure) => {
      const { score, reasons } = scoreLure(lure, profile);
      // Among equally good matches, prefer the most valuable decoy the tier allows.
      return { lure, reasons, score: score + lure.tier * 0.25 + jitter() * 0.5 };
    })
    .sort((a, b) => b.score - a.score);
  if (!candidates.length) return null;
  const best = candidates[0];
  return { lure: best.lure, score: best.score, reasons: best.reasons.length ? best.reasons : ['general interest decoy'] };
}

const slugify = (text) => String(text || 'org').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 24) || 'org';

// Everything a canary template needs to read as if it belonged to this organisation.
function canaryContext(lure, { orgName, department }) {
  return {
    orgName: orgName || 'the company',
    slug: slugify(orgName),
    service: lure.service || lure.title,
    region: 'eu-west-1',
    database: lure.database || 'reporting',
    documentName: lure.documentName || slugify(lure.title),
    documentTitle: department ? `${department} - ${lure.title}` : lure.title,
    updatedBy: department ? `${department} lead` : 'People Ops',
  };
}

module.exports = { LURES, scoreLure, chooseLure, canaryContext, slugify };
