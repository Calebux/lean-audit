---
name: lean-audit
description: Token-frugal security audit of a codebase by a single agent. A scanner and a route inventory point at the risky lines; only those get read; each lead is settled once, with a small local test when it decides the question. Use for "security audit", "find vulnerabilities", "check this app for security issues", or a re-audit of what changed since last time (--since).
---

# Lean audit

Find real vulnerabilities in a codebase for a small, predictable token cost. One agent, no
sub-agents unless the user asks. Read narrowly. Settle each lead once. Report only what
the code proves.

Typical cost: 30–80k tokens for a 50k-line app; an incremental run (`--since`) is a fraction
of that. A multi-agent audit of the same app spends millions.

## Rules that keep it lean

1. **Never read a whole file to "get context".** Read a function with `grep -n` plus a
   bounded window: `sed -n '<start>,<end>p'`, about 40–80 lines. Widen only when a trace needs it.
2. **Scripts first, eyes second.** `scan.mjs` and `routes.mjs` print compact, capped output.
   Do not re-derive with ad-hoc greps what they already list.
3. **One pass per lead.** Decide it and move on: confirmed, needs a deployment check, or not
   an issue. Do not revisit a decided lead.
4. **Cap the work.** At most 15 leads per run, chosen by the priority below. Write the rest
   down as "not reviewed". Never claim coverage you didn't do.
5. **No live systems.** Never send traffic to a deployed app, provider API or shared
   database. Local tests use dummy data, and run through `isolate.sh` when they execute project code.
6. **Don't fix during the audit** unless the user asked for fixes. Findings first.

## Step 1: Scope (about 1k tokens)

- Choose the target and the mode: **full**, or **incremental** with `--since <ref>` (the last
  audited commit, or `main` for a branch review).
- Look at the top-level layout, the package manifests and the deploy files (Dockerfile,
  vercel/railway/fly config) to learn the stack. Nothing deeper yet.
- If `~/.lean-audit/<repo-name>/state.json` exists, read it. It holds the last audited commit and
  earlier findings. Default to `--since <that commit>`, and recheck earlier open findings.

## Step 2: Map and scan (about 3–5k tokens)

```sh
node <skill-dir>/scripts/routes.mjs <repo> [--since <ref>]     # every route, guards, PUBLIC ones first
node <skill-dir>/scripts/scan.mjs   <repo> [--since <ref>]     # risky lines grouped by rule, capped
```

From that output plus the deploy files, write down in five lines or fewer: who the users are,
what is valuable (money, accounts, personal data, keys), the public entry points (webhooks,
signups, share links), and how a request proves who it is.

## Step 3: Pick leads (no extra reading)

Rank candidates and keep the top 15:

1. **Unauthenticated entry points** that change state: webhooks, signups, public POSTs (PUBLIC in `routes.mjs`).
2. **Money and credentials**: payments, balances, payouts, refunds, wallets, password and session flows.
3. **Scanner hits in `high`**: optional signatures, secret defaults, unscoped lookups,
   mass assignment, SQL interpolation, SSRF, command execution.
4. **Authenticated routes that take another object's id** (`:id`, `playerId`, `paymentId` in a body):
   cross-tenant access is the commonest real bug in multi-tenant apps.
5. **`medium` hits** in money or auth files (check-then-act, timing compare, cookies, CORS).

Ignore `info` hits unless they connect to a lead. A scanner hit is a pointer, not a finding.

## Step 4: Settle each lead (about 2–5k tokens each)

For each lead, answer these in order. Stop as soon as one settles it.

1. **Who is the attacker and what can they send?** Name it: an anonymous visitor, a user of
   another tenant, a low-role team member, a webhook sender.
2. **Where should the control be?** Find the guard, signature check, ownership filter, lock or
   validation that ought to stop it. `grep -n` for it; read only that function.
3. **Is it there, and does it bind the right thing?** Present isn't enough. Check it checks *this*
   resource for *this* principal, and on every path to the same effect (a sibling route, a
   batch endpoint, a retry, a webhook).
4. **What happens if it isn't there?** Name the concrete result: money credited, another
   tenant's record changed, a session kept, an internal URL fetched. No result means no finding.

Then decide:

- **Confirmed**: the source path is complete and nothing visible stops it. If a 20–60 line
  test can show it locally (the project's own test runner, mocked repositories, dummy
  secrets), write and run one through `isolate.sh`. It settles arguments and later becomes
  the regression test. Skip the test when the code is unambiguous and a test would cost more than the lead is worth.
- **Needs a deployment check**: the decisive fact is outside the code (an env var, a proxy, a
  provider dashboard setting). Write the exact thing the owner must look at.
- **Not an issue**: say what stops it in one line, so the next run doesn't redo it.

Common false positives to dismiss quickly: lookups by id after a tenant-scoped parent check; Object.assign of a
whitelisted DTO; secret defaults behind a production start-up check; regex `.exec`; public
routes that are meant to be public and only read public data.

## Step 5: Report (about 2k tokens)

Write `~/.lean-audit/<repo-name>/FINDINGS-<date>.md` from `templates/FINDINGS.md`, then
update `~/.lean-audit/<repo-name>/state.json`:

```json
{ "lastAuditedCommit": "<sha>", "date": "<YYYY-MM-DD>",
  "findings": [{ "id": "<file>:<function>:<short-slug>", "status": "confirmed|needs-check|fixed|not-an-issue", "title": "..." }] }
```

Severity, by demonstrated impact only:

- **critical**: anyone on the internet takes over accounts, reads or writes any tenant's data, or moves money.
- **high**: a real control fully bypassed with real consequences (auth bypass, cross-tenant write, forged payment).
- **medium**: a real bypass with narrow reach or unusual preconditions.
- **low**: minor disclosure or hardening with a plausible path.

In the reply, give the user: the confirmed findings table, the deployment checks, what wasn't reviewed, and
the report path. Offer to fix; when fixing, turn each confirmation test into a regression test.

## Running project code safely

`scripts/isolate.sh <scratch-dir> <seconds> -- <command...>` runs a command with no network,
an empty environment, writes only inside `<scratch-dir>`, and CPU/memory/time limits.
It uses sandbox-exec on macOS and `unshare` or Docker (`--network none`) on Linux. Put test files in the scratch
dir and import project code by absolute path. Never install packages inside it; use the
project's existing `node_modules` or virtualenv.
