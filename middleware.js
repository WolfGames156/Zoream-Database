// Vercel Edge Middleware (No Next.js dependencies)
// runs before all routes

const rateLimitMap = new Map();

// Global rate limit: 10 req per 60s per IP
const RATE_LIMIT = { limit: 15, window: 60000 };

function getClientIp(request) {
  const forwarded = request.headers.get('x-forwarded-for');
  const realIp = request.headers.get('x-real-ip');

  if (forwarded) return forwarded.split(',')[0].trim();
  if (realIp) return realIp;

  return 'unknown';
}

function checkRateLimit(ip) {
  const now = Date.now();

  let timestamps = rateLimitMap.get(ip) || [];
  timestamps = timestamps.filter(ts => now - ts < RATE_LIMIT.window);

  if (timestamps.length >= RATE_LIMIT.limit) {
    return {
      allowed: false,
      retryAfter: Math.ceil((timestamps[0] + RATE_LIMIT.window - now) / 1000)
    };
  }

  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);

  // Cleanup occasionally
  if (Math.random() < 0.01) cleanupOldEntries();

  return { allowed: true };
}

function cleanupOldEntries() {
  const now = Date.now();

  for (const [ip, timestamps] of rateLimitMap.entries()) {
    const filtered = timestamps.filter(ts => now - ts < RATE_LIMIT.window);
    if (filtered.length === 0) rateLimitMap.delete(ip);
    else rateLimitMap.set(ip, filtered);
  }
}

export default function middleware(request) {
  // Skip OPTIONS
  if (request.method === 'OPTIONS') return;

  const ip = getClientIp(request);
  const rateCheck = checkRateLimit(ip);

  if (!rateCheck.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: rateCheck.retryAfter
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(rateCheck.retryAfter)
        }
      }
    );
  }
}

export const config = {
  matcher: '/:path*'
};

