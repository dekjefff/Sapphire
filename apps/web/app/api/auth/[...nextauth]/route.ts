import { authenticationConfigured, handlers } from '@/auth';

export const GET: typeof handlers.GET = async (request) =>
  authenticationConfigured() ? handlers.GET(request) : new Response(null, { status: 503 });

export const POST: typeof handlers.POST = async (request) =>
  authenticationConfigured() ? handlers.POST(request) : new Response(null, { status: 503 });
