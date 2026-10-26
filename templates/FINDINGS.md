# Security findings: <repo> @ <short-sha> (<date>)

**Scope:** full | since <ref> · **Leads reviewed:** <n> of <m> · **Not reviewed:** <list or "none">

## Summary
<Two or three sentences: the overall picture, and the one thing to fix first.>

## Confirmed

| # | Severity | Finding | Who can do it | Result |
|---|---|---|---|---|
| 1 | high | <title> | <anonymous / other tenant / low role> | <what happens> |

### 1. <title>
- **Where:** `path/file.ts:123` (`function`)
- **How:** <the request or input, step by step, ending at the effect>
- **Why it works:** <the missing or wrong control, in one or two lines>
- **Proof:** <the local test run and its output, or "source only: <why that's conclusive>">
- **Fix:** <the smallest change at the right place, plus the regression test>

## Needs a deployment check

| Lead | Decisive fact | Exactly what to look at |
|---|---|---|
| <title> | <e.g. PULSE_MODE in production> | <e.g. Railway → API service → Variables: PULSE_MODE=live> |

## Not issues (so the next run skips them)
- `<file>:<line>` <hit>: <what stops it, one line>

## Hardening (no exploit path found)
- <note>
