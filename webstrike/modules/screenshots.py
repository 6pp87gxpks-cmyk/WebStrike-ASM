from urllib.parse import urlparse

from ..models import Confidence, Finding, Severity
from ..registry import Phase, register
from .base import Module


@register
class Screenshots(Module):
    id = "screenshots"
    name = "Host Screenshots"
    phase = Phase.ENRICH
    profiles = {"balanced", "danger"}
    kinds = {"domain", "url", "ip"}
    LIMIT = 25
    WEB_PORTS = {80, 443, 3000, 8000, 8080, 8443, 8888}

    async def run(self, ctx):
        try:
            from playwright.async_api import async_playwright
        except Exception:
            yield Finding(
                self.id,
                "Playwright not installed",
                Severity.INFO,
                category="screens",
                evidence="pip install playwright && playwright install chromium",
            )
            return

        parsed_base = urlparse(ctx.base_url)
        target_netloc = parsed_base.netloc or ctx.domain
        base_port = parsed_base.port

        candidates = []
        if target_netloc:
            candidates.append(target_netloc)
        for h in sorted(ctx.state.get("hosts", set())):
            if h in candidates:
                continue
            if ":" in h:
                _, _, port_str = h.rpartition(":")
                if port_str.isdigit():
                    port_num = int(port_str)
                    if port_num not in self.WEB_PORTS and port_num != base_port:
                        continue
            candidates.append(h)

        hosts = candidates[: self.LIMIT]
        out = ctx.screens_dir
        out.mkdir(parents=True, exist_ok=True)
        try:
            async with async_playwright() as p:
                try:
                    browser = await p.chromium.launch(args=["--no-sandbox"])
                except Exception as exc:
                    yield Finding(
                        self.id,
                        "Playwright browser launch failed",
                        Severity.INFO,
                        category="screens",
                        evidence=str(exc)[:200],
                    )
                    return

                for host in hosts:
                    if host.count(":") > 1 and not host.startswith("["):
                        host_fmt = f"[{host}]"
                    else:
                        host_fmt = host
                    _, _, port_part = host_fmt.rpartition(":")
                    if port_part in ("80", "3000", "8000", "8080", "8888"):
                        schemes = ("http", "https")
                    else:
                        schemes = ("https", "http")

                    for scheme in schemes:
                        url = f"{scheme}://{host_fmt}"
                        context = None
                        try:
                            context = await browser.new_context(
                                viewport={"width": 1280, "height": 800},
                                ignore_https_errors=True,
                            )
                            page = await context.new_page()
                            resp = await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                            if resp is None:
                                await context.close()
                                continue
                            title = await page.title()
                            name = f"{host}.png".replace("/", "_").replace(":", "_")
                            await page.screenshot(path=str(out / name))
                            await context.close()
                            yield Finding(
                                self.id,
                                f"Screenshot: {host}",
                                Severity.INFO,
                                Confidence.CERTAIN,
                                category="screens",
                                url=url,
                                evidence=title or "(no title)",
                                meta={"file": name, "status": resp.status},
                            )
                            break
                        except Exception:
                            if context:
                                try:
                                    await context.close()
                                except Exception:
                                    pass
                            continue
                await browser.close()
        except Exception as exc:
            yield Finding(
                self.id,
                "Screenshot capture failed",
                Severity.INFO,
                category="screens",
                evidence=str(exc)[:200],
            )
