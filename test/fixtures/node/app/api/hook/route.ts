export async function POST(req: Request) {
  return Response.json(await req.json());
}
