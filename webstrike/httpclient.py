from __future__ import annotations
import asyncio, time, httpx

class RateLimiter:
    def __init__(self, rate: float):
        self.rate = rate; self._next = 0.0; self._lock = asyncio.Lock()
    async def acquire(self):
        if self.rate <= 0: return
        async with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next - now)
            self._next = max(now, self._next) + 1.0 / self.rate
        if wait: await asyncio.sleep(wait)

class HttpClient:
    def __init__(self, opt):
        headers = {"User-Agent": opt.user_agent, **opt.headers}
        auth = None
        if opt.basic:
            u, _, p = opt.basic.partition(":")
            auth = (u, p)
        if opt.bearer:
            headers["Authorization"] = f"Bearer {opt.bearer}"
        proxy = (opt.proxy or "").strip() or None
        if proxy and "://" not in proxy:
            proxy = "http://" + proxy
        conc = max(1, int(opt.concurrency or 30))
        self._c = httpx.AsyncClient(
            headers=headers, cookies=opt.cookies, auth=auth,
            proxy=proxy, verify=opt.verify_tls, timeout=opt.timeout,
            follow_redirects=True, limits=httpx.Limits(max_connections=conc * 2),
        )
        self.limiter = RateLimiter(max(0.0, float(opt.rate or 0.0)))
        self.retries = max(0, int(opt.retries))
        self.sem = asyncio.Semaphore(conc)

    async def get(self, url, **kw):
        return await self.request("GET", url, **kw)

    async def request(self, method, url, **kw):
        async with self.sem:
            last = None
            for attempt in range(self.retries + 1):
                await self.limiter.acquire()
                try:
                    return await self._c.request(method, url, **kw)
                except (httpx.TimeoutException, httpx.TransportError) as e:
                    last = e
                    await asyncio.sleep(0.4 * (attempt + 1))
            raise last

    async def probe(self, url, method="GET", **kw):
        """Return response or None, never raises."""
        try:
            return await self.request(method, url, **kw)
        except Exception:
            return None

    async def aclose(self):
        await self._c.aclose()
