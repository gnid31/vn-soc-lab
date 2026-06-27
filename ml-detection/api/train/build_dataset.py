#!/usr/bin/env python3
"""Synthesize URL dataset: malicious (sqli/xss/lfi/probe) + benign."""
import csv, random, urllib.parse
from pathlib import Path

random.seed(42)
OUT = Path(__file__).parent.parent / "data" / "urls.csv"
OUT.parent.mkdir(parents=True, exist_ok=True)

MALICIOUS_PATTERNS = [
    "/login.php?id=1' OR '1'='1",
    "/login.php?id=1' UNION SELECT username,password FROM users--",
    "/search?q=1'; DROP TABLE users--",
    "/product?id=1 AND SLEEP(5)--",
    "/admin?user=' OR 1=1#",
    "/index.php?page=../../../../etc/passwd",
    "/?file=../../../etc/shadow",
    "/include.php?f=php://filter/convert.base64-encode/resource=index",
    "/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd",
    "/?path=....//....//etc/passwd",
    "/search?q=<script>alert(1)</script>",
    "/search?q=<img src=x onerror=alert(1)>",
    "/comment?body=<svg/onload=alert(document.cookie)>",
    "/profile?name=<iframe src=javascript:alert(1)>",
    "/feedback?msg=javascript:alert(String.fromCharCode(88,83,83))",
    "/cgi-bin/.%2e/.%2e/.%2e/etc/passwd",
    "/.git/config", "/.env", "/.aws/credentials", "/wp-config.php.bak",
    "/admin/.htpasswd", "/phpinfo.php", "/server-status",
    "/wp-admin/admin-ajax.php?action=duplicator_download",
    "/?cmd=cat+/etc/passwd", "/?exec=id;uname+-a",
    "/cgi-bin/test.cgi?name=;cat+/etc/passwd",
    "/upload.php?file=shell.php.jpg",
    "/api/users?id=1;ls",
    "/login?username=admin&password=' OR ''='",
    "/index.php?module=PostgreSQL&func=loadModule&filename=../../../etc/passwd",
    "/?redirect=http://evil.com/phish",
    "/?next=//attacker.com/login",
    "/?id=1%27%20OR%20%271%27=%271",
    "/?q=%3Cscript%3Ealert%281%29%3C/script%3E",
    "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/",
    "/HNAP1/", "/manager/html", "/jenkins/script",
    "/solr/admin/info/system?wt=json",
    "/api/v1/pods?fieldSelector=status.phase=Running",
    "/struts2-rest-showcase/orders/3/edit",
    "/cgi-bin/php?-d+allow_url_include=on+-d+auto_prepend_file=php://input",
]

BENIGN_PATTERNS = [
    "/", "/index.html", "/about", "/contact", "/faq",
    "/products", "/products/123", "/products/laptop-msi-gp76",
    "/category/electronics", "/category/books/fiction",
    "/search?q=laptop", "/search?q=python+tutorial",
    "/search?q=best+restaurants+hanoi",
    "/blog/2024/03/welcome", "/blog/posts/tag/security",
    "/api/users/me", "/api/v1/orders?status=pending",
    "/api/v1/products?page=2&limit=20",
    "/login", "/logout", "/signup", "/forgot-password",
    "/profile", "/profile/edit", "/settings/account",
    "/cart", "/checkout", "/orders/history",
    "/static/css/main.css", "/static/js/app.bundle.js",
    "/static/img/logo.png", "/favicon.ico",
    "/assets/fonts/inter.woff2",
    "/dashboard", "/dashboard/reports/monthly",
    "/docs", "/docs/getting-started", "/docs/api-reference",
    "/help/category/billing", "/support/tickets",
    "/news?date=2024-03-15",
    "/products?sort=price&order=asc",
    "/articles?tag=devops&page=3",
    "/health", "/healthz", "/api/health",
    "/robots.txt", "/sitemap.xml",
    "/blog/how-to-secure-web-apps",
    "/courses/intro-to-python",
    "/events?city=hanoi&month=4",
    "/forum/threads/welcome-newbies",
    "/wiki/Main_Page", "/wiki/Special:Random",
    "/users/john-doe", "/users/john-doe/posts",
    "/group/devops/discussions",
    "/api/v2/metrics?from=now-1h",
    "/store/checkout/confirm?orderId=ABC123",
    "/account/preferences/notifications",
    "/release-notes/v2.3.1",
]

def jitter(url, label):
    """Add small variations for diversity."""
    if random.random() < 0.3:
        url = url + ("&" if "?" in url else "?") + random.choice([
            "ref=google", "utm_source=newsletter", "lang=en",
            "session=abc123", "v=2",
        ])
    return url

rows = []
for u in MALICIOUS_PATTERNS:
    for _ in range(5):
        rows.append((jitter(u, 1), 1))
for u in BENIGN_PATTERNS:
    for _ in range(4):
        rows.append((jitter(u, 0), 0))

random.shuffle(rows)
with OUT.open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["url", "label"])
    w.writerows(rows)

print(f"Wrote {len(rows)} rows → {OUT}")
print(f"  malicious: {sum(1 for _,l in rows if l==1)}")
print(f"  benign   : {sum(1 for _,l in rows if l==0)}")
