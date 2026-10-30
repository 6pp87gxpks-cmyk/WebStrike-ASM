from urllib.parse import urlparse
from ..registry import register, Phase
from ..models import Finding, Severity, Confidence
from .base import Module

@register
class Screenshots(Module):
    id = "screenshots"; name = "Host Screenshots"; phase = Phase.ENRICH
    profiles = {"balanced", "danger"}; kinds = {"domain", "url"}
    LIMIT = 25

    async def run(self, ctx):
        try:
            from playwright.async_api import async_playwright
        except Exception:
            yield Finding(self.id, "Playwright not installed", Severity.INFO, category="screens",
                          evidence="pip install playwright && playwright install chromium")
            return
        target_netloc = urlparse(ctx.base_url).netloc
        hosts = sorted(ctx.state.get("hosts", set()))
        if not hosts and target_netloc:
            hosts = [target_netloc]
        elif not hosts:
            hosts = [ctx.domain]
        hosts = hosts[:self.LIMIT]
        out = ctx.screens_dir
        out.mkdir(parents=True, exist_ok=True)
        try:
            async with async_playwright() as p:
                try:
                    browser = await p.chromium.launch(args=["--no-sandbox"])
                except Exception as e:
                    yield Finding(self.id, "Playwright browser launch failed", Severity.INFO, category="screens",
                                  evidence=str(e)[:200])
                    return
                for host in hosts:
                    for scheme in ("https", "http"):
                        url = f"{scheme}://{host}"
                        context = None
                        try:
                            context = await browser.new_context(
                                viewport={"width": 1280, "height": 800}, ignore_https_errors=True)
                            page = await context.new_page()
                            resp = await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                            if resp is None:
                                await context.close()
                                continue
                            title = await page.title()
                            name = f"{host}.png".replace("/", "_").replace(":", "_")
                            await page.screenshot(path=str(out / name))
                            await context.close()
                            yield Finding(self.id, f"Screenshot: {host}", Severity.INFO,
                                          Confidence.CERTAIN, category="screens", url=url,
                                          evidence=title or "(no title)",
                                          meta={"file": name, "status": resp.status})
                            break
                        except Exception:
                            if context:
                                try:
                                    await context.close()
                                except Exception:
                                    pass
                            continue
                await browser.close()
        except Exception as e:
            yield Finding(self.id, "Screenshot capture failed", Severity.INFO, category="screens",
                          evidence=str(e)[:200])
