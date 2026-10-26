import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../scripts/scan.mjs';
import { routes } from '../scripts/routes.mjs';

const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
// The scanner skips test folders in real repos, so each fixture folder is scanned as its own root.
const rulesHit = (dir) => new Set(scan(path.join(fixtures, dir), {}).map((r) => r.id));

test('flags the classic Node/Nest bugs', () => {
  const hit = rulesHit('node');
  for (const id of ['optional-signature', 'secret-default', 'unscoped-lookup', 'ssrf', 'sql-interpolation', 'mass-assignment', 'untyped-body', 'csv-export']) {
    assert.ok(hit.has(id), `expected ${id}`);
  }
});

test('does not mistake a regex .exec() for command execution', () => {
  assert.ok(!rulesHit('node').has('command-exec'));
});

test('flags the classic Python bugs', () => {
  const hit = rulesHit('python');
  for (const id of ['unscoped-lookup', 'sql-interpolation', 'command-exec']) assert.ok(hit.has(id), `expected ${id}`);
});

test('lists routes with their guards and marks unguarded ones public', () => {
  const list = routes(path.join(fixtures, 'node'));
  const find = (m, p) => list.find((r) => r.method === m && r.path === p);
  assert.equal(find('POST', '/crypto/webhook/:chain')?.public, true);
  assert.equal(find('POST', '/payments/:id/assign')?.public, false);
  assert.equal(find('POST', '/api/hook')?.public, true);
});

test('reads FastAPI dependencies as guards', () => {
  const list = routes(path.join(fixtures, 'python'));
  assert.equal(list.find((r) => r.path === '/me')?.public, false);
  assert.equal(list.find((r) => r.path === '/orders/{order_id}/refund')?.public, true);
});
