import { readOperatorSession } from '@/auth';

type Context = { params: Promise<{ path: string[] }> };

function error(status: number, detail: string) {
  return Response.json({ detail }, { status, headers: { 'Cache-Control': 'no-store' } });
}

async function proxy(request: Request, context: Context) {
  const session = await readOperatorSession();
  if (!session?.user) return error(401, 'Sign in to Sapphire');

  const reads = request.method === 'GET' || request.method === 'HEAD';
  if (!reads && request.headers.get('origin') !== new URL(process.env.AUTH_URL!).origin) {
    return error(403, 'Request origin is not allowed');
  }

  const { path } = await context.params;
  if (path.some((part) => !part || part === '.' || part === '..' || /[/\\]/.test(part))) {
    return error(400, 'Invalid API path');
  }
  const upstream = new URL(
    path.map(encodeURIComponent).join('/'),
    process.env.SAPPHIRE_INTERNAL_API_URL ?? 'http://api:8000/',
  );
  upstream.search = new URL(request.url).search;

  const headers = new Headers();
  for (const key of ['accept', 'content-type']) {
    const value = request.headers.get(key);
    if (value) headers.set(key, value);
  }
  const aiReviewRoute =
    path[0] === 'assessments' &&
    ((path.length === 3 && path[2] === 'ai-code-review') ||
      ((path.length === 3 || path.length === 4) && path[2] === 'project-code-review'));
  if (aiReviewRoute) {
    const proxyToken = process.env.SAPPHIRE_AI_REVIEW_PROXY_TOKEN?.trim();
    if (!proxyToken) return error(503, 'AI Code Review is not configured on the server');
    headers.set('X-Sapphire-AI-Review-Proxy', proxyToken);
  }

  try {
    const init: RequestInit & { duplex?: 'half' } = {
      method: request.method,
      headers,
      redirect: 'error',
      cache: 'no-store',
      signal: request.signal,
    };
    if (!reads && request.body) {
      init.body = request.body;
      init.duplex = 'half';
    }
    const response = await fetch(upstream, init);
    const output = new Headers({
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    const contentType = response.headers.get('content-type');
    const disposition = response.headers.get('content-disposition');
    if (contentType) output.set('Content-Type', contentType);
    if (disposition) output.set('Content-Disposition', disposition);
    return new Response(response.body, { status: response.status, headers: output });
  } catch {
    return error(502, 'Sapphire API is unavailable');
  }
}

export { proxy as GET, proxy as HEAD, proxy as POST };
