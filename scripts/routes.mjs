#!/usr/bin/env node
// lean-audit route inventory: every HTTP route with the guards that protect it, one line each.
// Routes with no guard are marked PUBLIC, the first place to look for access-control bugs.
// Knows NestJS, Express/Koa/Fastify-style routers, Next.js route handlers, FastAPI and Flask.
//
//   node routes.mjs <repo> [--since <git-ref>] [--public]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { listFiles } from './scan.mjs';

const VERB = '(Get|Post|Put|Patch|Delete|All)';
const GUARD = /@(UseGuards|Roles|Public|SkipAuth|AllowAnonymous|SkipCsrf|Throttle|AllowTreasurer|Auth\w*)\(([^)]*)\)/g;

function nest(file, text) {
  if (!/@Controller\(/.test(text)) return [];
  const out = [];
  // Each class: its prefix and class-level decorators, then its routes.
  const classRe = /((?:\s*@\w+\([^)]*\)\s*)*)export\s+class\s+(\w+)/g;
  const classes = [...text.matchAll(classRe)].map((m) => ({ at: m.index + m[0].length, decorators: m[1], name: m[2] }));
  classes.forEach((c, i) => {
    const prefix = /@Controller\(\s*['"`]?([^'"`)]*)/.exec(c.decorators)?.[1] ?? '';
    const classGuards = [...c.decorators.matchAll(GUARD)].map((g) => g[1] + (g[2] ? `(${g[2].trim()})` : ''));
    const body = text.slice(c.at, classes[i + 1]?.at ?? text.length);
    const lines = body.split('\n');
    const offset = text.slice(0, c.at).split('\n').length - 1;
    lines.forEach((l, j) => {
      const m = new RegExp(`@${VERB}\\(\\s*(?:['"\`]([^'"\`]*)['"\`])?`).exec(l);
      if (!m) return;
      // Route-level decorators sit in the few lines around the verb decorator.
      const near = lines.slice(Math.max(0, j - 4), j + 4).join('\n');
      const routeGuards = [...near.matchAll(GUARD)].map((g) => g[1] + (g[2] ? `(${g[2].trim()})` : ''));
      const guards = [...new Set([...classGuards, ...routeGuards])];
      const authed = guards.some((g) => /UseGuards\(.*(Auth|Jwt|Session|Guard)/i.test(g) && !/^UseGuards\(ThrottlerGuard\)$/.test(g));
      out.push({ method: m[1].toUpperCase(), path: `/${[prefix, m[2] ?? ''].filter(Boolean).join('/')}`.replace(/\/+/g, '/'), file, line: offset + j + 1, guards, public: !authed });
    });
  });
  return out;
}

function express(file, text) {
  const out = [];
  text.split('\n').forEach((l, i) => {
    const m = /\b(app|router|server|api)\.(get|post|put|patch|delete|all)\(\s*['"`]([^'"`]+)['"`]\s*,\s*(.*)$/.exec(l);
    if (!m) return;
    const middleware = m[4].split(',').slice(0, -1).map((s) => s.trim()).filter(Boolean);
    out.push({ method: m[2].toUpperCase(), path: m[3], file, line: i + 1, guards: middleware, public: !middleware.some((s) => /auth|guard|require|protect|session|jwt|login/i.test(s)) });
  });
  return out;
}

function nextRoute(file, text) {
  const m = /(?:^|\/)app\/(.*)\/route\.[jt]sx?$/.exec(file);
  if (!m) return [];
  const route = '/' + m[1].replace(/\([^)]*\)\/?/g, '').replace(/\[([^\]]+)\]/g, ':$1');
  const authed = /(getServerSession|auth\(\)|currentUser|verify\w*Token|cookies\(\)\.get|headers\(\)\.get\(['"]authorization)/i.test(text);
  return [...text.matchAll(/export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b/g)].map((x) => ({
    method: x[1], path: route, file, line: text.slice(0, x.index).split('\n').length, guards: authed ? ['session check in handler'] : [], public: !authed,
  }));
}

function python(file, text) {
  const out = [];
  const lines = text.split('\n');
  lines.forEach((l, i) => {
    const fast = /@(app|router|\w+)\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]/.exec(l);
    const flask = /@(app|bp|\w+)\.route\(\s*['"]([^'"]+)['"](?:.*methods\s*=\s*\[([^\]]*)\])?/.exec(l);
    if (!fast && !flask) return;
    const sig = lines.slice(i, i + 6).join(' ');
    const deps = /Depends\(\s*(\w+)/.exec(sig)?.[1];
    const deco = lines.slice(Math.max(0, i - 3), i + 3).join(' ').match(/@(login_required|\w*auth\w*|permission_required|jwt_required)/i)?.[1];
    const guards = [deps, deco].filter(Boolean);
    out.push({
      method: fast ? fast[2].toUpperCase() : (flask[3] ?? 'GET').replace(/['"\s]/g, ''),
      path: fast ? fast[3] : flask[2], file, line: i + 1, guards, public: !guards.some((g) => /auth|user|login|jwt|permission|current/i.test(g)),
    });
  });
  return out;
}

export function routes(repo, { since } = {}) {
  const out = [];
  for (const file of listFiles(repo, since)) {
    if (/(\.(spec|test)\.|(^|\/)tests?\/)/.test(file)) continue;
    let text;
    try { text = fs.readFileSync(path.join(repo, file), 'utf8'); } catch { continue; }
    if (/\.[mc]?[jt]sx?$/.test(file)) out.push(...nest(file, text), ...express(file, text), ...nextRoute(file, text));
    else if (file.endsWith('.py')) out.push(...python(file, text));
  }
  return out.sort((a, b) => Number(b.public) - Number(a.public) || a.path.localeCompare(b.path));
}

function main() {
  const args = process.argv.slice(2);
  const repo = path.resolve(args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--since') ?? '.');
  const since = args.includes('--since') ? args[args.indexOf('--since') + 1] : undefined;
  let list = routes(repo, { since });
  if (args.includes('--public')) list = list.filter((r) => r.public);
  const pub = list.filter((r) => r.public).length;
  console.log(`${list.length} routes, ${pub} with no auth guard (PUBLIC)\n`);
  for (const r of list) {
    console.log(`${r.public ? 'PUBLIC ' : '       '}${r.method.padEnd(6)} ${r.path}  ${r.file}:${r.line}${r.guards.length ? `  [${r.guards.join(', ')}]` : ''}`);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) main();
