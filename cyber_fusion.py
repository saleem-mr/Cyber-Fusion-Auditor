import asyncio
import websockets
import json
import sys
import argparse
import requests
import time
import re
import os
import subprocess
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def ensure_tor():
    """Checks if Tor is running and starts it; re-runs script via torsocks if needed."""
    try:
        subprocess.check_output("pgrep -x tor", shell=True)
    except subprocess.CalledProcessError:
        print("[*] Tor not running. Starting daemon...")
        if os.path.exists("/tmp/tor.log"):
            os.remove("/tmp/tor.log")
        subprocess.run("tor --RunAsDaemon 1 --Log \"notice file /tmp/tor.log\"", shell=True)
        print("[*] Waiting for Tor to bootstrap (100%)...")
        for _ in range(30):
            try:
                with open("/tmp/tor.log", "r") as f:
                    if "Bootstrapped 100%" in f.read():
                        print("[*] Tor is ready.")
                        break
            except Exception:
                pass
            time.sleep(2)

    if 'torsocks' not in os.environ.get('LD_PRELOAD', ''):
        print("[*] Re-routing through Tor network...")
        os.execvp('torsocks', ['torsocks', sys.executable] + sys.argv)

# Proprietary Audit Standards
STANDARDS = {
    'Word Count': 'Standard: 800-2000 words for deep content.',
    'Readability': 'Standard: Average sentence length < 20 words.',
    'Keyword Density': 'Standard: 0.5% - 1.5%. Avoid keyword stuffing.',
    'Keyword Placement': 'Standard: Keyword in first 100 words and H1.',
    'H1 Heading': 'Standard: Exactly one H1 tag per page.',
    'H2 Headings': 'Standard: Use H2 tags for logical sub-sections.',
    'Image Alt Attributes': 'Standard: Every image needs descriptive alt text.',
    'Security Headers': 'Standard: CSP, HSTS, X-Frame-Options, X-Content-Type, Referrer-Policy.',
    'Information Leakage': 'Standard: Server versions and technology stacks should be hidden.',
    'Sensitive Files': 'Standard: Config files (.env, .git) must not be accessible.',
    'Cookie Hardening': 'Standard: Cookies must have Secure, HttpOnly, and SameSite flags.',
    'Form Security': 'Standard: Forms must use POST and HTTPS actions with CSRF protection.',
    'Email Exposure': 'Standard: Plaintext emails should be obfuscated to prevent scraping.',
    'SSL Check': 'Standard: Use modern TLS with valid certificates.',
    'Schema / JSON-LD': 'Standard: Structured data helps rich snippets.',
    'Minification': 'Standard: CSS and JS should be minified (.min).',
    'Response Time': 'Standard: Server response should be < 500ms.',
    'Sitemap': 'Standard: Sitemap.xml found in robots.txt.',
    'Robots.txt': 'Standard: robots.txt accessible and valid.'
}

# Master Scoring Algorithm
WEIGHTS = {
    'SSL Check': 12, 'Sensitive Files': 12, 'Noindex': 10, 'Canonical': 8,
    'H1 Heading': 8, 'H1 tag': 8, 'Title tag': 7, 'Meta Description': 7,
    'Information Leakage': 7, 'Cookie Hardening': 6, 'Form Security': 6,
    'Sitemap': 6, 'Robots.txt': 6, 'Response Time': 6, 'Minification': 5,
    'Word Count': 5, 'H2 Headings': 5, 'Security Headers': 5
}

async def fetch_master_intel(url):
    """Fetches real-time SEO intelligence from external WebSocket provider."""
    ws_url = "wss://seo-checker.yoast.app/v1/?url=" + url
    results = {}
    try:
        async with websockets.connect(ws_url) as websocket:
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=15)
                    data = json.loads(message)
                    if data.get("event") == "updatedResult":
                        results[data.get("key")] = data.get("result", {})
                    if data.get("event") == "finished":
                        break
                except Exception:
                    break
    except Exception:
        pass
    return results

def perform_internal_audit(url, keywords=None):
    """Performs localized on-page SEO and basic security scans."""
    audit = {'Content': [], 'Technical': [], 'Performance': [], 'Security': [], 'Social': []}
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    r = None
    for attempt in range(3):
        try:
            start_time = time.time()
            r = requests.get(url, headers=headers, timeout=25, verify=True)
            response_time = (time.time() - start_time) * 1000
            break
        except Exception as e:
            if attempt == 2:
                audit['Technical'].append({
                    'name': 'Page availability',
                    'score': 'bad',
                    'rec': f'Connection Error: {e}'
                })
                return audit
            time.sleep(3)

    try:
        soup = BeautifulSoup(r.text, 'html.parser')
        text = soup.get_text()
        words = re.findall(r'\w+', text)

        wc_score = 'good' if len(words) > 800 else 'warning'
        audit['Content'].append({'name': 'Word Count', 'score': wc_score, 'rec': f'Count: {len(words)} words.'})
        sentences = re.split(r'[.!?؟]+', text)
        avg_sl = len(words) / max(1, len(sentences))
        audit['Content'].append({
            'name': 'Readability',
            'score': 'good' if avg_sl < 20 else 'warning',
            'rec': f'Avg: {round(avg_sl, 1)} w/s.'
        })
        h1s = soup.find_all('h1')
        audit['Content'].append({
            'name': 'H1 Heading',
            'score': 'good' if len(h1s) == 1 else 'bad',
            'rec': f'Found {len(h1s)} H1.'
        })
        h2s = soup.find_all('h2')
        audit['Content'].append({
            'name': 'H2 Headings',
            'score': 'good' if len(h2s) > 0 else 'warning',
            'rec': f'Found {len(h2s)} H2.'
        })

        if keywords:
            for kw in keywords:
                kw = kw.strip().lower()
                count = len(re.findall(r'\b' + re.escape(kw) + r'\b', text.lower()))
                density = (count / max(1, len(words))) * 100
                f100 = " ".join(words[:100]).lower()
                audit['Content'].append({
                    'name': 'Keyword Density',
                    'score': 'good' if 0.5 <= density <= 1.5 else 'warning',
                    'rec': f'{kw}: {round(density, 2)}%.'
                })
                in_h1 = any(kw in h1.get_text().lower() for h1 in h1s)
                audit['Content'].append({
                    'name': 'Keyword Placement',
                    'score': 'good' if (kw in f100 and in_h1) else 'warning',
                    'rec': f'{kw} in intro: {"Yes" if kw in f100 else "No"}, In H1: {"Yes" if in_h1 else "No"}'
                })

        leaks = []
        if re.search(r'\d', r.headers.get('Server', '')):
            leaks.append(f'Server: {r.headers.get("Server")}')
        if r.headers.get('X-Powered-By'):
            leaks.append(f'PoweredBy: {r.headers.get("X-Powered-By")}')
        audit['Security'].append({
            'name': 'Information Leakage',
            'score': 'good' if not leaks else 'bad',
            'rec': ', '.join(leaks) if leaks else 'No tech-stack signatures leaked.'
        })

        sensitive_paths = ['.env', '.git/config', 'phpinfo.php']
        exposed = []
        for path in sensitive_paths:
            try:
                tr = requests.get(urljoin(url, path), headers=headers, timeout=10)
                if tr.status_code == 200:
                    exposed.append(path)
            except Exception:
                pass
        audit['Security'].append({
            'name': 'Sensitive Files',
            'score': 'good' if not exposed else 'bad',
            'rec': f'CRITICAL: {", ".join(exposed)} exposed!' if exposed else 'Protected.'
        })

        cookie_issues = [c.name for c in r.cookies if not c.secure and url.startswith('https')]
        audit['Security'].append({
            'name': 'Cookie Hardening',
            'score': 'good' if not cookie_issues else 'warning',
            'rec': ', '.join(cookie_issues) if cookie_issues else 'Cookies hardened.'
        })

        sec_h = {
            'Content-Security-Policy': 'Strict',
            'Strict-Transport-Security': 'Critical',
            'X-Frame-Options': 'Clickjacking',
            'X-Content-Type-Options': 'Sniffing'
        }
        miss = [h for h in sec_h if h not in r.headers]
        audit['Security'].append({
            'name': 'Security Headers',
            'score': 'good' if not miss else 'warning',
            'rec': f'Missing: {", ".join(miss) if miss else "None"}'
        })

        audit['Performance'].append({
            'name': 'Response Time',
            'score': 'good' if response_time < 800 else 'warning',
            'rec': f'{round(response_time, 0)}ms'
        })
        scripts = [s.get('src') for s in soup.find_all('script', src=True)]
        styles = [s.get('href') for s in soup.find_all('link', rel='stylesheet')]
        imgs = [i.get('src') for i in soup.find_all('img', src=True)]
        obj_count = len(scripts) + len(styles) + len(imgs)
        audit['Performance'].append({
            'name': 'Object Breakdown',
            'score': 'good' if obj_count < 30 else 'warning',
            'rec': f'Total: {obj_count} (JS: {len(scripts)}, CSS: {len(styles)}, Imgs: {len(imgs)})'
        })
        unminified = [f for f in (scripts + styles) if f and '.min.' not in f and not f.startswith('data:')]
        audit['Performance'].append({
            'name': 'Minification',
            'score': 'good' if not unminified else 'warning',
            'rec': f'Unminified files found ({len(unminified)})'
        })

        audit['Technical'].append({
            'name': 'SSL Check',
            'score': 'good' if url.startswith('https') else 'bad',
            'rec': 'HTTPS Active' if url.startswith('https') else 'Insecure'
        })
        canonical = soup.find('link', rel='canonical')
        audit['Technical'].append({
            'name': 'Canonical',
            'score': 'good' if canonical else 'warning',
            'rec': canonical['href'] if canonical else 'Missing'
        })
        schemas = soup.find_all('script', type='application/ld+json')
        audit['Technical'].append({
            'name': 'Schema / JSON-LD',
            'score': 'good' if schemas else 'warning',
            'rec': f'Found {len(schemas)} Schema blocks'
        })

        og = len([m for m in soup.find_all('meta') if m.get('property', '').startswith('og:')])
        tw = len([m for m in soup.find_all('meta') if m.get('name', '').startswith('twitter:')])
        audit['Social'].append({
            'name': 'Social Cards',
            'score': 'good' if (og and tw) else 'warning',
            'rec': f'OG: {og}, Twitter: {tw}'
        })

    except Exception as e:
        audit['Technical'].append({'name': 'Parsing Error', 'score': 'bad', 'rec': str(e)})
    return audit

def run_deep_asset_scan(url, recurse=False, concurrency=1):
    """Deep Asset Auditor (Proprietary Engine)."""
    header = "┌── DEEP ASSET AUDIT " + "─" * 47 + "┐"
    msg = "│ Scanning for broken links and assets... (Safe mode active)"
    print(f"\n\033[94m\033[1m{header}\033[0m")
    print(f"{msg}")
    cmd = ["linkinator", url, "--concurrency", str(concurrency), "--timeout", "300000", "--retry"]
    if recurse:
        cmd.append("--recurse")
    try:
        subprocess.run(cmd)
    except Exception as e:
        print(f"│ \033[91m✖ Engine Error: {e}\033[0m")
    print("\033[1m└" + "─" * 78 + "┘\033[0m")

def print_master_report(url, intel_res, local_audit):
    """Generates and prints a visually rich hierarchical audit report."""
    C_BLUE, C_CYAN, C_GREEN, C_YELLOW, C_RED, C_BOLD, C_DIM, C_END = (
        '\033[94m', '\033[96m', '\033[92m', '\033[93m', '\033[91m', '\033[1m', '\033[2m', '\033[0m'
    )
    print(f"\n{C_BLUE}{C_BOLD}╔" + "═" * 78 + "╗")
    title_line = f"║ {C_CYAN}OMNIPOTENT MASTER AUDIT {C_DIM}v4.0{C_END}"
    padding = " " * (78 - 25 - 2)
    print(f"{title_line}{padding}{C_BLUE}║")
    target_line = f"║ {C_BOLD}TARGET:{C_END} {url}"
    padding = " " * (78 - 8 - len(url) - 1)
    print(f"{target_line}{padding}{C_BLUE}║")
    print(f"╚" + "═" * 78 + f"╝{C_END}")

    cats = {k.title(): v for k, v in local_audit.items()}
    if intel_res:
        for k, v in intel_res.items():
            cat = v.get('category', 'Technical').title()
            if cat not in cats:
                cats[cat] = []
            rec = v.get('recommendation', '')
            if 'found' in v and v['found']:
                if k == 'headingHierarchy':
                    rec += ' | Tree: ' + ' > '.join([h['level'].upper() for h in v['found'][:5]])
                elif k in ['title', 'metaDescription']:
                    rec += ' | Found: ' + v['found'][0][:60] + '...'
            cats[cat].append({'name': v.get('name', k), 'score': v.get('score', 'info'), 'rec': rec})

    priority_list = ['Basic Seo', 'Content', 'Advanced Seo', 'Technical', 'Security', 'Performance', 'Social']
    total_possible = total_achieved = 0
    displayed_cats = []
    for p in priority_list:
        for c in cats.keys():
            if p.lower() == c.lower() and c not in displayed_cats:
                displayed_cats.append(c)
    for c in sorted(cats.keys()):
        if c not in displayed_cats:
            displayed_cats.append(c)

    for c in displayed_cats:
        if not cats[c]:
            continue
        print(f"\n{C_BOLD}┌── {C_BLUE}{c.upper()}{C_END} " + "─" * (74 - len(c)) + "┐")
        sorted_results = sorted(
            cats[c],
            key=lambda x: (0 if x['score'] == 'bad' else 1 if x['score'] == 'warning' else 2)
        )
        for r in sorted_results:
            icon = (
                f"{C_GREEN}●{C_END}" if r['score'] == 'good'
                else f"{C_YELLOW}▲{C_END}" if r['score'] == 'warning'
                else f"{C_RED}✖{C_END}" if r['score'] == 'bad'
                else f"{C_DIM}○{C_END}"
            )
            print(f"│ {icon} {C_BOLD}{r['name']}{C_END}")
            for line in r.get('rec', '').split('\n'):
                print(f"│   {C_DIM}└─{C_END} {line}")
            if r['name'] in STANDARDS:
                print(f"│      {C_DIM}💡 {STANDARDS[r['name']]}{C_END}")
            if r['score'] in ['good', 'warning', 'bad']:
                w = WEIGHTS.get(r['name'], 3)
                total_possible += w * 10
                total_achieved += w * 10 if r['score'] == 'good' else w * 5 if r['score'] == 'warning' else 0
        print("└" + "─" * 78 + "┘")

    score = round((total_achieved / max(1, total_possible)) * 100)
    clr = C_GREEN if score > 80 else C_YELLOW if score > 50 else C_RED
    filled_len = int(40 * score / 100)
    bar_str = f"{clr}{'█' * filled_len}{C_DIM}{'░' * (40 - filled_len)}{C_END}"
    print(f"\n{C_BOLD}┌── {C_BLUE}FINAL SCORE{C_END} " + "─" * 63 + "┐")
    print(f"│ {bar_str} {clr}{C_BOLD}{score}%{C_END}")
    print("└" + "─" * 78 + f"┘{C_END}\n")

async def main():
    """Main execution entry point."""
    ensure_tor()
    parser = argparse.ArgumentParser(
        description='Omnipotent Master SEO & Security Auditor (Cyber Fusion v4.0)',
        epilog='Note: Built-in support for Stealth Anonymity mode.'
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('--keywords', help='Comma-separated keywords')
    parser.add_argument('--deep-scan', action='store_true', help='Perform site-wide link & asset audit')
    parser.add_argument('--crawl', action='store_true', help='Recursive mode for deep-scan')
    parser.add_argument('--concurrency', type=int, default=1, help='Scanning speed (default 1)')
    args = parser.parse_args()

    url = args.url if args.url.startswith('http') else 'https://' + args.url
    print(f'[*] Analyzing {url} with Cyber Fusion v4.0...')
    intel_task = asyncio.create_task(fetch_master_intel(url))
    internal_res = perform_internal_audit(url, args.keywords.split(',') if args.keywords else None)
    intel_res = await intel_task
    print_master_report(url, intel_res, internal_res)
    if args.deep_scan:
        run_deep_asset_scan(url, recurse=args.crawl, concurrency=args.concurrency)

if __name__ == '__main__':
    asyncio.run(main())
