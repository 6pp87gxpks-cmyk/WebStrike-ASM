from __future__ import annotations

from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from ..models import Confidence, Finding, Severity
from ..registry import Phase, register
from .base import Module


@register
class Crawler(Module):
    id = "crawler"
    name = "Web Spider & Forms"
    phase = Phase.DISCOVERY
    profiles = {"balanced", "danger"}
    kinds = {"domain", "url"}
    MAX_PAGES = 35

    async def run(self, ctx):
        base = ctx.base_url
        domain = ctx.domain.lower()
        queue = [base]
        visited = set()
        discovered_forms = set()
        form_count = 0

        while queue and len(visited) < self.MAX_PAGES:
            current_url = queue.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)

            r = await ctx.http.probe(current_url)
            if not r or r.status_code != 200:
                continue

            content_type = r.headers.get("content-type", "").lower()
            if not ("text/html" in content_type or "application/xhtml" in content_type):
                continue

            try:
                soup = BeautifulSoup(r.text, "html.parser")
            except Exception:
                continue

            for tag in soup.find_all("a", href=True):
                href = tag.get("href", "").strip()
                if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue
                full_url = urljoin(current_url, href)
                parsed = urlparse(full_url)
                if parsed.hostname and (
                    parsed.hostname.lower() == domain
                    or parsed.hostname.lower().endswith("." + domain)
                ):
                    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    full_with_query = f"{clean_url}?{parsed.query}" if parsed.query else clean_url
                    ctx.remember("urls", full_with_query)
                    ctx.remember("endpoints", parsed.path or "/")
                    if clean_url not in visited and len(visited) + len(queue) < self.MAX_PAGES:
                        queue.append(clean_url)

            for st in soup.find_all("script", src=True):
                src = (st.get("src") or "").strip()
                if not src or src.startswith(("data:", "javascript:")):
                    continue
                full_script = urljoin(current_url, src)
                sp = urlparse(full_script)
                if sp.hostname and (
                    sp.hostname.lower() == domain
                    or sp.hostname.lower().endswith("." + domain)
                ):
                    ctx.remember("urls", full_script)

            curr_path = urlparse(current_url).path or "/"
            for form in soup.find_all("form"):
                action = form.get("action", "") or curr_path
                method = form.get("method", "GET").upper()
                full_action = urljoin(current_url, action)

                inputs = []
                input_names = []
                has_password = False
                has_file_upload = False

                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name") or inp.get("id") or ""
                    itype = inp.get("type", "text").lower()
                    if itype == "password":
                        has_password = True
                    if itype == "file":
                        has_file_upload = True
                    if name:
                        inputs.append(f"{name}:{itype}")
                        input_names.append(name)

                form_sig = (method, full_action, tuple(sorted(inputs)))
                if form_sig in discovered_forms:
                    continue
                discovered_forms.add(form_sig)
                form_count += 1

                action_path = urlparse(full_action).path or "/"
                ctx.remember("endpoints", action_path)
                if method == "GET" and input_names:
                    qs_sample = "&".join(f"{n}=1" for n in input_names[:6])
                    sep = "&" if "?" in full_action else "?"
                    ctx.remember("urls", f"{full_action}{sep}{qs_sample}")
                inputs_desc = ", ".join(inputs[:10]) if inputs else "no named inputs"

                if has_file_upload:
                    yield Finding(
                        self.id,
                        f"File Upload Form: {action_path}",
                        Severity.MEDIUM,
                        Confidence.CERTAIN,
                        category="surface",
                        url=full_action,
                        evidence=f"Method: {method} | Inputs: {inputs_desc}",
                    )
                elif has_password:
                    sev = Severity.HIGH if full_action.startswith("http://") else Severity.LOW
                    yield Finding(
                        self.id,
                        f"Auth/Login Form: {action_path}",
                        sev,
                        Confidence.CERTAIN,
                        category="surface",
                        url=full_action,
                        evidence=f"Method: {method} | Password input present | Inputs: {inputs_desc}",
                    )
                elif form_count <= 8:
                    yield Finding(
                        self.id,
                        f"Form: {method} {action_path}",
                        Severity.INFO,
                        Confidence.CERTAIN,
                        category="surface",
                        url=full_action,
                        evidence=f"Inputs: {inputs_desc}",
                    )

        yield Finding(
            self.id,
            f"Spider completed: {len(visited)} pages crawled, {form_count} forms",
            Severity.INFO,
            category="surface",
            url=base,
            evidence=f"Visited {len(visited)} internal endpoints",
        )
