#!/usr/bin/env node
// lean-audit scanner: a cheap first pass that points the agent at the few places worth reading.
// Zero dependencies. Prints a compact report (file:line + one trimmed line per hit), capped per
// rule, so the whole thing costs a couple of thousand tokens instead of reading the codebase.
//
//   node scan.mjs <repo> [--since <git-ref>] [--max <n-per-rule>] [--json] [--only <rule,...>]
//
// --since limits the scan to files changed since that ref (incremental audits).
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const RULES = [
  // ── Trust boundaries: webhooks, secrets, tokens ──
  { id: 'optional-signature', sev: 'high', langs: ['js', 'py'], re: /\bif\s*\(?\s*!?\s*\(?\s*\w*(sig|signature|hmac)\w*\s*(&&|and\b)/i,
    hint: 'Signature checked only when present? A request without the header may skip verification.' },
  { id: 'secret-default', sev: 'high', langs: ['js', 'py'], re: /(SECRET|_KEY|TOKEN|PASSWORD)\w*['"]?\s*\)?\s*(\?\?|\|\||\bor\b)\s*['"][^'"]{0,40}['"]|get(<[^>]*>)?\(\s*['"]\w*(SECRET|_KEY|TOKEN|PASSWORD)\w*['"]\s*,\s*['"]/,
    hint: 'Secret falls back to a fixed or empty value. Does anything fail open when it is unset?' },
  { id: 'jwt-decode', sev: 'high', langs: ['js', 'py'], re: /\bjwt\.decode\(|verify_signature['"]?\s*:\s*False|algorithms\s*[:=]\s*\[?\s*['"]none/i,
    hint: 'Token decoded without verification, or alg "none" allowed.' },
  { id: 'timing-compare', sev: 'medium', langs: ['js', 'py'], re: /(===|!==|==|!=)\s*\w*(signature|hmac|digest|token|secret)\w*\b(?!\s*\()/i,
    hint: 'Secret compared with ==; use a constant-time compare.' },
  { id: 'hardcoded-secret', sev: 'high', langs: ['*'], re: /-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]{20,}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]{10,}/,
    hint: 'Credential in source.' },
  { id: 'weak-random', sev: 'medium', langs: ['js', 'py'], re: /Math\.random\(\)|\brandom\.(randint|choice|random)\(/,
    hint: 'Non-cryptographic randomness. Fine for UI, not for codes, tokens or refs.', fileRe: /(token|code|otp|secret|auth|ref|invite|password)/i },

  // ── Access control: ids from the request reaching the database ──
  { id: 'unscoped-lookup', sev: 'high', langs: ['js'], re: /\.(findOne|findOneBy|findByPk|findById|findUnique|delete|update)\(\s*(\{\s*where:\s*)?\{\s*id\s*:\s*[\w.]+\s*\}\s*\}?\s*[,)]/,
    hint: 'Looked up by id alone. Is the id from the request, and is the tenant or owner checked?' },
  { id: 'unscoped-lookup', sev: 'high', langs: ['py'], re: /\.(get|filter)\(\s*(pk|id)\s*=\s*\w+\s*\)|get_object_or_404\(\s*\w+\s*,\s*(pk|id)\s*=/,
    hint: 'Looked up by id alone. Is the owner or tenant checked?' },
  { id: 'mass-assignment', sev: 'high', langs: ['js', 'py'], re: /Object\.assign\(\s*\w+\s*,\s*(req\.body|body|data|dto|input|payload)\s*\)|\.(update|create|save)\(\s*(req\.body|request\.data|\*\*request\.(data|json))\s*\)|for\s+\w+\s*,\s*\w+\s+in\s+(request\.data|data)\.items\(\)\s*:\s*setattr/,
    hint: 'Request body copied onto a record. Can it set owner, role, status or foreign keys?' },
  { id: 'untyped-body', sev: 'medium', langs: ['js'], re: /@Body\(\)\s*\w+\s*:\s*(any|\{)|@Body\(['"]\w+['"]\)\s*\w+\s*:\s*(string|any)\b/,
    hint: 'Body not validated by a DTO class (ValidationPipe skips it).' },
  { id: 'public-route', sev: 'info', langs: ['js'], re: /@(Public|SkipAuth|AllowAnonymous|SkipCsrf)\(\)/,
    hint: 'Route opts out of auth or CSRF. Confirm it should.' },

  // ── State and money: check-then-act ──
  { id: 'check-then-act', sev: 'medium', langs: ['js', 'py'], re: /if\s*\(?\s*\w+(\.\w+)*\.status\s*(!==|===|!=|==)\s*[\w.'"]+\s*\)?/,
    hint: 'Status read then written later. Two concurrent requests can both pass; use a conditional update or a lock.', fileRe: /(pay|bill|wallet|order|transfer|refund|balance|credit|invoice|checkout|withdraw|crypto)/i },
  { id: 'amount-unchecked', sev: 'medium', langs: ['js', 'py'], re: /amount\s*[:=]\s*(Number|parseFloat|float|parseInt|int)\(\s*(req\.|body\.|data\.|payload|event|tx\.|raw)/i,
    hint: 'Amount parsed from input. Negative, zero, NaN or huge values rejected?' },

  // ── Injection and unsafe sinks ──
  { id: 'sql-interpolation', sev: 'high', langs: ['js'], re: /\.(query|raw|execute|\$queryRawUnsafe|\$executeRawUnsafe)\(\s*`[^`]*\$\{/,
    hint: 'SQL built with ${...}. Is every interpolated value a constant?' },
  { id: 'sql-interpolation', sev: 'high', langs: ['py'], re: /\.(execute|raw|executemany)\(\s*(f["']|["'][^"']*["']\s*%|["'][^"']*["']\s*\.format\()/,
    hint: 'SQL built with string formatting.' },
  { id: 'command-exec', sev: 'high', langs: ['js', 'py'], re: /\b(child_process|execSync|spawnSync|vm\.run\w*)\b|(?<![.\w])(exec|spawn|eval)\(|new Function\(|subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\(|pickle\.loads?\(|yaml\.load\((?![^)]*SafeLoader)/,
    hint: 'Code or command execution, or unsafe deserialisation. Is any input user-controlled?' },
  { id: 'path-from-input', sev: 'high', langs: ['js', 'py'], re: /(readFile|createReadStream|sendFile|download|open|send_file|FileResponse)\w*\(\s*[^'"`)]*(req\.|params|query|body|request\.)/,
    hint: 'File path from the request. Traversal possible?' },
  { id: 'ssrf', sev: 'high', langs: ['js', 'py'], re: /\b(fetch|axios(\.\w+)?|got|request|webpush\.sendNotification|requests\.(get|post)|httpx\.\w+|urlopen)\(\s*(req\.|body\.|dto\.|params\.|query\.|\w*[uU]rl\b|\w*[eE]ndpoint\b|\w*[wW]ebhook\w*\b|sub\b|subscription\b)|IsUrl\(\s*\{[^}]*require_tld\s*:\s*false/,
    hint: 'Server fetches a URL that may come from a user. Internal hosts blocked?' },
  { id: 'xss-sink', sev: 'high', langs: ['js', 'py', 'html'], re: /dangerouslySetInnerHTML|\.innerHTML\s*=|v-html=|\|\s*safe\b|mark_safe\(|\{\{\{/,
    hint: 'Raw HTML rendering. Is the value ever user-supplied?' },
  { id: 'open-redirect', sev: 'medium', langs: ['js', 'py'], re: /(res\.redirect|redirect|router\.(push|replace)|location\.(href|assign|replace))\s*[=(]\s*(req\.|query\.|params\.|searchParams|request\.(GET|args))/,
    hint: 'Redirect target from the request.' },
  { id: 'csv-export', sev: 'low', langs: ['js', 'py'], re: /text\/csv|toCsv\(|csv\.writer\(|\.csv['"`]/,
    hint: 'CSV export: are values starting with = + - @ neutralised (formula injection)?' },

  // ── Browser and HTTP config ──
  { id: 'cors-open', sev: 'medium', langs: ['js', 'py'], re: /origin\s*:\s*(true|['"]\*['"])|Access-Control-Allow-Origin['"]?\s*,\s*['"]\*|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|allow_origins\s*=\s*\[\s*['"]\*/,
    hint: 'Any origin allowed. Combined with credentials?' },
  { id: 'cookie-flags', sev: 'medium', langs: ['js', 'py'], re: /httpOnly\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*['"]none['"]|SESSION_COOKIE_SECURE\s*=\s*False/i,
    hint: 'Weak cookie flag. Does the cookie carry a session?' },
  { id: 'spoofable-ip', sev: 'low', langs: ['js', 'py'], re: /x-forwarded-for|x-real-ip|X-Forwarded-For/,
    hint: 'Client IP from a header. Spoofable unless set by a trusted proxy; used for rate limits?' },
  { id: 'dev-branch', sev: 'info', langs: ['js', 'py'], re: /NODE_ENV\s*!==?\s*['"]production['"]|DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True/,
    hint: 'Behaviour that changes outside production. Can it be reached in prod by misconfiguration?' },
  { id: 'tls-off', sev: 'high', langs: ['js', 'py'], re: /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED/,
    hint: 'TLS verification disabled.' },
  { id: 'security-todo', sev: 'info', langs: ['*'], re: /\b(TODO|FIXME|HACK|XXX)\b.*\b(auth|secur|valid|permission|sanitiz|escape|csrf|rate.?limit|verify)/i,
    hint: 'Security TODO left in code.' },
];

const EXT = { js: /\.(m?[jt]sx?|cjs)$/, py: /\.py$/, html: /\.(html|vue|svelte|hbs|ejs|jinja2?|j2)$/ };
const SKIP = /(^|\/)(node_modules|dist|build|\.next|coverage|vendor|venv|\.venv|__pycache__|migrations?|\.git)\//;
const TESTS = /(\.(spec|test)\.[jt]sx?$|(^|\/)(tests?|__tests__|fixtures)\/|_test\.py$|test_[^/]*\.py$)/;

function langOf(file) {
  for (const [lang, re] of Object.entries(EXT)) if (re.test(file)) return lang;
  return null;
}

export function listFiles(repo, since) {
  const git = (args) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', maxBuffer: 64 << 20 });
  let files;
  try {
    files = since
      ? git(['diff', '--name-only', '--diff-filter=AMR', `${since}...HEAD`]).split('\n')
      : git(['ls-files', '--cached', '--others', '--exclude-standard']).split('\n');
  } catch {
    // Not a git repo: walk the directory.
    files = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(path.join(repo, dir), { withFileTypes: true })) {
        const rel = dir ? `${dir}/${e.name}` : e.name;
        if (SKIP.test(rel + '/')) continue;
        if (e.isDirectory()) walk(rel);
        else files.push(rel);
      }
    };
    walk('');
  }
  return files.filter((f) => f && !SKIP.test(f) && (langOf(f) || /\.(env|pem|key|ya?ml|json)$/.test(f)));
}

export function scan(repo, { since, max = 12, only } = {}) {
  const hits = new Map(); // rule id -> [{file, line, text}]
  const totals = new Map();
  const rules = only ? RULES.filter((r) => only.includes(r.id)) : RULES;
  for (const file of listFiles(repo, since)) {
    if (TESTS.test(file)) continue;
    const lang = langOf(file);
    let text;
    try {
      const full = path.join(repo, file);
      if (fs.statSync(full).size > 1 << 20) continue;
      text = fs.readFileSync(full, 'utf8');
    } catch {
      continue;
    }
    const lines = text.split('\n');
    for (const rule of rules) {
      if (!rule.langs.includes('*') && !rule.langs.includes(lang)) continue;
      if (rule.fileRe && !rule.fileRe.test(file)) continue;
      lines.forEach((l, i) => {
        if (l.length > 400 || !rule.re.test(l)) return;
        totals.set(rule.id, (totals.get(rule.id) ?? 0) + 1);
        const list = hits.get(rule.id) ?? [];
        if (list.length < max) list.push({ file, line: i + 1, text: l.trim().slice(0, 140) });
        hits.set(rule.id, list);
      });
    }
  }
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  const byId = new Map(rules.map((r) => [r.id, r]));
  return [...hits.entries()]
    .map(([id, list]) => ({ id, sev: byId.get(id).sev, hint: byId.get(id).hint, total: totals.get(id), hits: list }))
    .sort((a, b) => order[a.sev] - order[b.sev] || a.id.localeCompare(b.id));
}

function main() {
  const args = process.argv.slice(2);
  const repo = path.resolve(args.find((a) => !a.startsWith('--') && !args[args.indexOf(a) - 1]?.match(/^--(since|max|only)$/)) ?? '.');
  const opt = (k) => (args.includes(k) ? args[args.indexOf(k) + 1] : undefined);
  const result = scan(repo, { since: opt('--since'), max: Number(opt('--max') ?? 12), only: opt('--only')?.split(',') });
  if (args.includes('--json')) return console.log(JSON.stringify(result, null, 1));
  if (!result.length) return console.log('No hits.');
  for (const r of result) {
    console.log(`\n## ${r.id} [${r.sev}] ${r.total} hit${r.total === 1 ? '' : 's'}${r.total > r.hits.length ? ` (first ${r.hits.length})` : ''}\n${r.hint}`);
    for (const h of r.hits) console.log(`  ${h.file}:${h.line}  ${h.text}`);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) main();
