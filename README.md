# lean-audit

A security-audit skill for coding agents (Claude Code and similar) that finds real
vulnerabilities for a small, predictable token cost.

Multi-agent audit workflows send dozens of agents over a codebase. Each one rereads the same
architecture and rules, and every finding is checked twice by fresh agents. That's thorough,
but it costs millions of tokens. lean-audit uses **one agent**:

1. **Scripts do the cheap first pass.** `routes.mjs` lists every HTTP route with its guards,
   unguarded ones first. `scan.mjs` lists risky lines (optional webhook signatures, secret
   defaults, id lookups without a tenant check, mass assignment, SQL interpolation, SSRF,
   check-then-act on money, and more), grouped and capped. Both outputs together run to
   about 2–5k tokens.
2. **The agent reads only what the scan points at**, in 40–80-line windows, never whole files.
3. **Each lead is settled once**: confirmed (with a small local test when that decides it),
   needs a deployment check, or not an issue. At most 15 leads per run.
4. **Incremental re-audits.** `--since <ref>` scans only changed files. A state file
   remembers the last audited commit and earlier findings.

On a 60k-line NestJS + Next.js app, the scan alone pointed at a forgeable crypto deposit
webhook, push-notification SSRF and CSV formula injection, all of them confirmed bugs.

## Install

```sh
git clone https://github.com/Calebux/lean-audit ~/.claude/skills/lean-audit
```

Then ask your agent: *"lean audit this repo"*, or *"lean audit what changed since main"*.

## Use the scripts directly

```sh
node scripts/routes.mjs /path/to/repo            # all routes; add --public for unguarded only
node scripts/scan.mjs   /path/to/repo            # risky lines by rule (--max N, --only rule1,rule2, --json)
node scripts/scan.mjs   /path/to/repo --since main
scripts/isolate.sh /tmp/scratch 120 -- node test.js   # run a proof with no network or credentials
```

Zero dependencies; Node 18+. Covers JavaScript/TypeScript (NestJS, Express, Next.js) and Python
(FastAPI, Flask, Django) out of the box. Rules are plain regexes in `scripts/scan.mjs`, easy to extend.

## What it is not

- It doesn't prove the absence of bugs. It finds the common, high-impact ones cheaply.
  Business-logic flaws with no lexical trace still need a human, or a deeper audit.
- The scanner hits are pointers, not findings. The skill's rules make the agent confirm each one
  against the code before reporting it.
- It never sends traffic to deployed systems.

## Tests

```sh
npm test
```

## License

MIT
