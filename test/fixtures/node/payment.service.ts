export async function pushTo(sub: { endpoint: string }) {
  await fetch(sub.endpoint, { method: 'POST' });
  const rows = await db.query(`SELECT * FROM users WHERE name = '${sub.endpoint}'`);
  Object.assign(team, data);
  return rows;
}
