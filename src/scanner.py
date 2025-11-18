#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import re
import shutil
import subprocess
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

# ===========================
# IMPORTS (conforme sua árvore src/utils/http.py)
# Rode com: python -m src.scanner
# ===========================
from src.utils import http as httpmod
from src.utils.http import (
    get, build_url_with_params,
    likely_sqli_error, looks_like_passwd,
    contains_reflected_payload, has_csrf_token
)

# ----------------------------
# Configs / payloads
# ----------------------------

DEFAULT_PARAMS = ["q", "search", "id", "page", "name", "user", "email"]
DEFAULT_HEADERS_CHECK = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
]

# Soluções por header – enriquecido
HEADER_SOLUTIONS = {
    "strict-transport-security": (
        "Enable HSTS (e.g., max-age>=15552000; includeSubDomains; preload). "
        "Force HTTPS at the edge/load balancer and remove HTTP endpoints."
    ),
    "content-security-policy": (
        "Define a restrictive CSP (e.g., default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'). "
        "Avoid inline scripts or use nonces/hashes; audit third-party domains."
    ),
    "x-frame-options": (
        "Set X-Frame-Options to DENY or SAMEORIGIN (or use CSP frame-ancestors) to prevent clickjacking."
    ),
    "x-content-type-options": (
        "Set X-Content-Type-Options: nosniff to prevent MIME sniffing on script/style responses."
    ),
    "referrer-policy": (
        "Adopt a strict Referrer-Policy (e.g., no-referrer or strict-origin-when-cross-origin) to minimize data leakage."
    ),
    "permissions-policy": (
        "Use Permissions-Policy to disable unused browser features (e.g., geolocation=(), camera=(), microphone=())."
    ),
}

# Soluções genéricas – enriquecido
SOLUTIONS = {
    "SQL Injection (possível)": (
        "Use parameterized queries/ORM bindings; validate inputs with allowlists; "
        "centralize DB access; enforce least-privilege DB accounts; "
        "suppress stack traces/DB errors; add WAF rules for typical patterns."
    ),
    "XSS refletido": (
        "Encode/escape outputs (HTML/attr/JS context aware); sanitize inputs server-side; "
        "adotar CSP rígida; cookies HttpOnly+Secure+SameSite; evitar innerHTML sem sanitização; "
        "bibliotecas de templating que auto-escapam."
    ),
    "Directory Traversal / LFI": (
        "Normalize canonical paths; enforce allowlists de diretórios/nomes; "
        "nunca concatenar caminhos com input; rodar app com permissões mínimas; "
        "bloquear respostas de erro detalhadas."
    ),
    "Exposição de arquivos/diretórios": (
        "Remover artefatos (.git, .env, backups); negar listagem de diretórios; "
        "separar segredos do repositório; revisar regras do servidor/cdn; "
        "validar políticas de cache/CDN (private, no-store)."
    ),
    "Diretório sensível acessível (restrito)": (
        "Requerer autenticação forte/ACL; mascarar a existência; "
        "desabilitar directory listing; mover gestão para painel isolado."
    ),
    "CSRF (token ausente - suspeita)": (
        "Implementar anti-CSRF tokens (rotativos, por sessão); exigir SameSite=Lax/Strict; "
        "validar Origin/Referer; métodos idempotentes para GET; considerar double-submit cookie."
    ),
    "Security Headers ausentes": (
        "Configurar HSTS, CSP, XFO, X-Content-Type-Options, Referrer-Policy e Permissions-Policy; "
        "automatizar via middleware/reverse-proxy e testes em CI."
    ),
    "Nikto finding": (
        "Revisar a recomendação do Nikto; ajustar configs do servidor/proxy; "
        "desabilitar listagens; restringir endpoints; aplicar patches."
    ),
    "Nmap finding": (
        "Rever serviços/portas expostos; desabilitar o desnecessário; aplicar TLS forte; "
        "segmentação/regras de firewall; monitorar serviços externos."
    ),
    "Command Injection (possível)": (
        "Nunca concatenar comandos; usar APIs que não invocam shell; sanitizar/validar com allowlists; "
        "executar com contas sem privilégio; isolar chamadas com timeouts e quotas; "
        "desabilitar funcionalidades não utilizadas."
    ),
    "Erro de request": "Checar conectividade, DNS e formato de URL; repetir o teste com maior request-timeout."
}

# OWASP (descrições curtas em inglês)
OWASP_DESCRIPTIONS = {
    "A01": "Broken Access Control: violations of policy allow users to act outside their intended permissions.",
    "A02": "Cryptographic Failures: data in transit/at rest exposed due to weak or missing cryptography.",
    "A03": "Injection: untrusted data is interpreted as commands or queries (SQLi, OS command, LDAP, XSS, etc.).",
    "A04": "Insecure Design: missing or ineffective security controls by design.",
    "A05": "Security Misconfiguration: insecure default configs, open buckets, missing headers, verbose errors.",
    "A06": "Vulnerable and Outdated Components: known-vuln libs, frameworks, or platforms.",
    "A07": "Identification and Authentication Failures: broken auth or session management.",
    "A08": "Software and Data Integrity Failures: CI/CD integrity, unsafe deserialization, update trust issues.",
    "A09": "Security Logging and Monitoring Failures: poor logging/alerting/IR visibility.",
    "A10": "Server-Side Request Forgery (SSRF): server fetches remote resources based on untrusted input."
}

def _owasp_desc_from_tag(tag: str) -> str:
    if not tag:
        return ""
    parts = []
    for m in re.findall(r"\bA(\d{2})\b", tag):
        parts.append(f"A{m}")
    if not parts:
        if "Injection" in tag:
            return OWASP_DESCRIPTIONS.get("A03", "")
        return ""
    descs = [OWASP_DESCRIPTIONS.get(p, "") for p in parts if OWASP_DESCRIPTIONS.get(p)]
    return " | ".join(descs)

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1 --",
    "\" OR 1=1 --",
    "1 OR 1=1",
    "' OR '1'='1' /*",
    "'; WAITFOR DELAY '0:0:2'--",
    "' OR SLEEP(2)--",
    "'; SELECT pg_sleep(2)--",
]

CMDI_CONTENT_PAYLOADS = [";id", "&& id", "| id", "`id`"]
CMDI_TIME_PAYLOADS   = ["; sleep 2", "&& sleep 2", "| sleep 2", "& timeout /T 2 >NUL"]

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/config.php", "/backup.zip",
    "/admin/", "/_admin/", "/.vscode/", "/.idea/"
]

# ---------- orçamento global exposto aos detectores ----------
_within_budget = lambda: True  # substituído em runtime pelo main()

# ----------------------------
# Helpers
# ----------------------------

def add_finding(bag, _type, severity, url=None, param=None, evidence=None, owasp=None, tool=None, solution=None):
    owasp_desc = _owasp_desc_from_tag(owasp or "")
    bag.append({
        "time": datetime.utcnow().isoformat() + "Z",
        "type": _type,
        "severity": severity,
        "url": url or "",
        "param": param or "",
        "evidence": evidence or "",
        "owasp": owasp or "",
        "owasp_desc": owasp_desc,
        "tool": tool or "core",
        "solution": solution or SOLUTIONS.get(_type, "")
    })

def normalize_target(t):
    p = urlparse(t)
    if not p.scheme:
        t = "http://" + t
    return t

def same_origin(a, b):
    return urlparse(a).netloc == urlparse(b).netloc

def collect_params(seed):
    """
    Descobre nomes de parâmetros a partir de inputs de formulários da página inicial,
    somando com o conjunto DEFAULT_PARAMS (sem sobrescrever).
    """
    params = set(DEFAULT_PARAMS)
    try:
        r = get(seed)
        soup = BeautifulSoup(r.text, "html.parser")
        for i in soup.find_all("input"):
            name = i.get("name")
            if name:
                params.add(name)
    except Exception:
        pass
    return sorted(params)

# ----------------------------
# Detecções (core)
# ----------------------------

def check_security_headers(target, findings):
    try:
        r = get(target)
    except Exception as e:
        add_finding(findings, "Erro de request", "low", target, None, str(e), None, "core")
        return
    headers = {k.lower(): v for k, v in r.headers.items()}
    missing = []
    for h in DEFAULT_HEADERS_CHECK:
        if h not in headers:
            missing.append(h)
    if missing:
        add_finding(findings, "Security Headers ausentes", "medium", target, None,
                    ", ".join(missing), "A05", "core",
                    "; ".join(HEADER_SOLUTIONS.get(m, "") for m in missing if m in HEADER_SOLUTIONS))

def check_sensitive_files(target, findings):
    for p in SENSITIVE_PATHS:
        if not _within_budget():
            return
        url = urljoin(target, p)
        try:
            r = get(url, allow_redirects=True)
            if r.status_code == 200 and len((r.text or "")) > 0:
                sev = "high" if p in ("/.git/HEAD", "/.env", "/config.php", "/backup.zip") else "medium"
                add_finding(findings, "Exposição de arquivos/diretórios", sev, url, None, f"{r.status_code}", "A05", "core")
        except Exception as e:
            add_finding(findings, "Erro de request", "low", url, None, str(e), None, "core")

def check_directory_traversal(target, findings):
    test_paths = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]
    for p in test_paths:
        if not _within_budget():
            return
        url = build_url_with_params(target, {"file": p})
        try:
            r = get(url)
            if r.status_code == 200 and looks_like_passwd(r.text):
                add_finding(findings, "Directory Traversal / LFI", "high", url, "file", "etc/passwd content", "A05/A03", "core")
        except Exception as e:
            add_finding(findings, "Erro de request", "low", url, "file", str(e), None, "core")

def check_xss(target, findings, params):
    for name in params:
        if not _within_budget():
            return
        for payload in XSS_PAYLOADS:
            if not _within_budget():
                return
            url = build_url_with_params(target, {name: payload})
            try:
                r = get(url, allow_redirects=True)
                if contains_reflected_payload(r.text, payload):
                    add_finding(findings, "XSS refletido", "medium", url, name, payload, "A03", "core")
            except Exception as e:
                add_finding(findings, "Erro de request", "low", url, name, str(e), None, "core")

def check_sqli(target, findings, params):
    for name in params:
        if not _within_budget():
            return
        for payload in SQLI_PAYLOADS:
            if not _within_budget():
                return
            url = build_url_with_params(target, {name: payload})
            try:
                r = get(url, allow_redirects=True)
            except Exception as e:
                add_finding(findings, "Erro de request", "low", url, name, str(e), None, "core"); continue
            body = r.text or ""
            if r.status_code >= 500 or likely_sqli_error(body):
                add_finding(findings, "SQL Injection (possível)", "high", url, name, "error/500 or SQL trace", "A03", "core")

def check_cmd_injection(target, findings, params):
    try:
        rt = float(getattr(httpmod, "DEFAULT_TIMEOUT", 8) or 8)
    except Exception:
        rt = 8.0
    threshold = max(1.5, min(2.0, rt - 0.5))

    for name in params:
        if not _within_budget():
            return
        # conteúdo
        for payload in CMDI_CONTENT_PAYLOADS:
            if not _within_budget():
                return
            url = build_url_with_params(target, {name: payload})
            try:
                r = get(url)
                if ("uid=" in (r.text or "")) or ("gid=" in (r.text or "")):
                    add_finding(findings, "Command Injection (possível)", "high", url, name, "uid/gid in response", "A03", "core")
            except Exception as e:
                add_finding(findings, "Erro de request", "low", url, name, str(e), None, "core")
        # time-based
        for payload in CMDI_TIME_PAYLOADS:
            if not _within_budget():
                return
            t0 = time.time()
            url = build_url_with_params(target, {name: payload})
            try:
                _ = get(url)
            except Exception:
                pass
            if (time.time() - t0) >= threshold:
                add_finding(findings, "Command Injection (possível)", "high", url, name, f"time delay ~{threshold:.1f}s", "A03", "core")

def check_csrf_suspect(target, findings):
    try:
        r = get(target)
    except Exception as e:
        add_finding(findings, "Erro de request", "low", target, None, str(e), None, "core"); return
    soup = BeautifulSoup(r.text, "html.parser")
    for form in soup.find_all("form"):
        if not _within_budget():
            return
        method = (form.get("method") or "").lower()
        if method == "post":
            inputs = form.find_all("input")
            if not has_csrf_token([{"name": i.get("name",""), "id": i.get("id","")} for i in inputs]):
                add_finding(findings, "CSRF (token ausente - suspeita)", "medium", target, None, "form POST without token-like input", "A01/A07", "core")

def crawl_light(seed, max_depth=0, max_pages=20):
    seen = set([seed])
    q = deque([(seed, 0)])
    urls = [seed]
    while q and len(urls) < max_pages:
        if not _within_budget():
            break
        url, d = q.popleft()
        if d >= max_depth:
            continue
        try:
            r = get(url, allow_redirects=True)
        except Exception:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a"):
            if not _within_budget():
                break
            href = a.get("href")
            if not href:
                continue
            u = urljoin(url, href)
            if same_origin(seed, u) and u not in seen:
                seen.add(u)
                urls.append(u)
                q.append((u, d + 1))
        for f in soup.find_all("form"):
            if not _within_budget():
                break
            action = f.get("action") or url
            u = urljoin(url, action)
            if same_origin(seed, u) and u not in seen:
                seen.add(u)
                urls.append(u)
                q.append((u, d + 1))
    return urls

# ----------------------------
# Integrações (streaming c/ relógio fluido)
# ----------------------------

def _run_external_stream(name, cmd, out_path: Path, maxtime_sec: int, findings, parser_fn, within_budget, console: Console, progress: Progress, task_id):
    """
    Executa ferramenta externa com Popen + polling para:
      - respeitar orçamento global,
      - interromper ao atingir maxtime da ferramenta,
      - manter o relógio fluido na UI.
    """
    if progress and task_id is not None:
        progress.update(task_id, description=f"{name} (running)")

    if not within_budget():
        return False

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        out_path.write_text(str(e), encoding="utf-8")
        return False

    start = time.time()
    # loop de polling com UI fluida
    while True:
        if proc.poll() is not None:
            break
        elapsed = time.time() - start
        # orçamentos
        if maxtime_sec and elapsed >= maxtime_sec:
            try:
                proc.terminate()
            except Exception:
                pass
            break
        if not within_budget():
            try:
                proc.terminate()
            except Exception:
                pass
            break
        # tick de UI
        if progress and task_id is not None:
            progress.refresh()
        time.sleep(0.2)

    try:
        out, err = proc.communicate(timeout=5)
    except Exception:
        try:
            proc.kill()
            out, err = proc.communicate(timeout=2)
        except Exception:
            out, err = "", ""

    # grava log
    out_path.write_text((out or "") + ("\n" + err if err else ""), encoding="utf-8")

    # parseia findings do stdout
    if out:
        parser_fn(out, findings)

    return True

def _parse_nikto(stdout_text: str, findings):
    for line in stdout_text.splitlines():
        s = line.strip()
        if not s:
            continue
        # Evita metadados ‘+ Target IP/Hostname/Port’ etc.
        if s.startswith("+"):
            if any(key in s.lower() for key in ["target ip", "target hostname", "target port", "start time", "end time"]):
                continue
            if "OSVDB" in s:
                continue
            add_finding(findings, "Nikto finding", "medium", None, None, s, "A05", "nikto")

def _parse_nmap(stdout_text: str, findings, target_host: str):
    for line in stdout_text.splitlines():
        s = line.strip()
        if not s:
            continue
        if "http-" in s or "/tcp" in s or "open" in s:
            add_finding(findings, "Nmap finding", "medium", f"http://{target_host}", None, s, "A05", "nmap")

def run_nikto_stream(target, findings, out_dir, maxtime_sec, within_budget, console, progress, task_id):
    if not shutil.which("nikto"):
        return False
    out = Path(out_dir) / "nikto.txt"
    cmd = ["nikto", "-host", target, "-ask", "no", "-maxtime", f"{maxtime_sec}s"]
    return _run_external_stream("Nikto", cmd, out, maxtime_sec, findings, _parse_nikto, within_budget, console, progress, task_id)

def run_nmap_stream(target, findings, out_dir, maxtime_sec, within_budget, console, progress, task_id):
    if not shutil.which("nmap"):
        return False
    host = urlparse(target).netloc.split("@")[-1].split(":")[0]
    out = Path(out_dir) / "nmap.txt"
    # Nmap não tem ‘maxtime’ nativo simples → usamos orçamento via polling e matamos o proc ao passar o tempo
    cmd = ["nmap", "-Pn", "-p", "80,443", "--script", "http-enum,http-config-backup", host]
    parser = lambda txt, fset: _parse_nmap(txt, fset, host)
    return _run_external_stream("Nmap", cmd, out, maxtime_sec, findings, parser, within_budget, console, progress, task_id)

# ----------------------------
# Main (CLI)
# ----------------------------

def main():
    ap = argparse.ArgumentParser(description="Web Security Scanner (conceito B) — 3min budget + relógio fluido")
    ap.add_argument("-t", "--target", required=True, help="URL alvo (ex: http://testphp.vulnweb.com)")
    ap.add_argument("--params", nargs="*", help="Nomes de parâmetros para fuzz (padrão interno)")
    ap.add_argument("--crawl-depth", type=int, default=0, help="Profundidade de crawl (0=off)")
    ap.add_argument("--max-pages", type=int, default=30, help="Máximo de páginas no crawl")
    ap.add_argument("--nikto", action="store_true", help="Rodar Nikto e agregar achados")
    ap.add_argument("--nmap", action="store_true", help="Rodar Nmap e agregar achados")
    # defaults pensados para caber em ~3min somando tudo
    ap.add_argument("--max-scan-seconds", type=int, default=180, help="Tempo máximo total da varredura (0=ilimitado).")
    ap.add_argument("--request-timeout", type=int, default=None, help="Timeout de cada requisição HTTP (segundos).")
    ap.add_argument("--nikto-maxtime", type=int, default=80, help="Tempo máximo do Nikto (segundos).")
    ap.add_argument("--nmap-maxtime", type=int, default=60, help="Tempo máximo do Nmap (segundos) — controlado externamente.")
    ap.add_argument("--fancy-progress", action="store_true", help="Mostra barra/spinner de progresso com Rich.")
    ap.add_argument("-o", "--out", default="out", help="Diretório de saída (reports)")
    ap.add_argument("--json-stdout", action="store_true", help="Imprimir JSON no stdout (além de salvar arquivo)")
    ap.add_argument("--no-progress", action="store_true", help="Desativa logs de progresso no terminal")
    args = ap.parse_args()

    console = Console(stderr=True)

    def log(tag, msg, style="cyan"):
        if not args.no_progress:
            console.print(f"[bold {style}][{tag}][/bold {style}] {msg}")

    # timeout por requisição
    try:
        if args.request_timeout:
            httpmod.DEFAULT_TIMEOUT = args.request_timeout
    except Exception:
        pass

    start_ts = time.time()
    def within_budget():
        if not args.max_scan_seconds or args.max_scan_seconds <= 0:
            return True
        return (time.time() - start_ts) < args.max_scan_seconds

    # expõe checker aos detectores
    global _within_budget
    _within_budget = within_budget

    # UI de progresso com relógio fluido
    progress = None
    task = None
    if (not args.no_progress) and args.fancy_progress:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),   # relógio flui porque não bloqueamos etapas externas
            transient=True,
            console=console
        )
        progress.start()
        task = progress.add_task("Scan workflow", total=7)

    target = normalize_target(args.target)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    log("core", f"Alvo: {target}")
    if progress: progress.advance(task)

    # 1) Coleta de parâmetros (seed)
    param_list = sorted(set(args.params or []) | set(collect_params(target) or []))
    if not param_list:
        param_list = DEFAULT_PARAMS
    log("core", f"Parâmetros em uso: {', '.join(param_list)}")

    # 2) Crawl leve
    targets = [target]
    if args.crawl_depth > 0 and within_budget():
        log("core", f"Crawl leve (depth={args.crawl_depth}, max_pages={args.max_pages})…")
        targets = crawl_light(target, max_depth=args.crawl_depth, max_pages=args.max_pages)
    log("core", f"{len(targets)} URL(s) para testar.")
    if progress: progress.advance(task)

    findings = []

    # 3) Etapas core
    steps = [
        ("core", "Checando security headers…", check_security_headers),
        ("core", "Buscando arquivos/diretórios sensíveis…", check_sensitive_files),
        ("core", "Testando Directory Traversal / LFI…", check_directory_traversal),
        ("core", "Testando XSS refletido…", check_xss),
        ("core", "Testando SQL Injection…", check_sqli),
        ("core", "Inspecionando CSRF (token ausente – suspeita)…", check_csrf_suspect),
        ("core", "Testando Command Injection…", check_cmd_injection),
    ]

    for url in targets:
        for tag, desc, fn in steps:
            if not within_budget():
                log("core", "Tempo máximo atingido — gerando relatórios.", style="yellow")
                break
            n0 = len(findings)
            log(tag, f"{desc} [{url}]" if len(targets) > 1 else desc)
            if fn in (check_xss, check_sqli, check_cmd_injection):
                fn(url, findings, param_list)
            else:
                fn(url, findings)
            added = len(findings) - n0
            log(tag, f"{desc.split('…')[0]} ✓ (+{added})", style="green")
            if progress: progress.advance(task)

    # 4) Integrações com tempo fatiado + relógio fluido
    if args.nikto and within_budget():
        if shutil.which("nikto"):
            log("nikto", f"Executando (maxtime {args.nikto_maxtime}s)…", style="magenta")
            run_nikto_stream(target, findings, out_dir, args.nikto_maxtime, within_budget, console, progress, task)
            log("nikto", "Finalizado.", style="green")
        else:
            log("nikto", "Não encontrado no PATH — pulando", style="yellow")
        if progress: progress.advance(task)

    if args.nmap and within_budget():
        if shutil.which("nmap"):
            log("nmap", f"Executando (maxtime {args.nmap_maxtime}s)…", style="magenta")
            run_nmap_stream(target, findings, out_dir, args.nmap_maxtime, within_budget, console, progress, task)
            log("nmap", "Finalizado.", style="green")
        else:
            log("nmap", "Não encontrado no PATH — pulando", style="yellow")
        if progress: progress.advance(task)

    # 5) Relatórios
    from src import report_generator as rg
    (out_dir / "report.json").write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    rg.write_markdown(findings, out_dir / "report.md")
    rg.write_csv(findings, out_dir / "report.csv")

    if args.json_stdout:
        print(json.dumps(findings, indent=2, ensure_ascii=False))

    log("core", f"Finalizado. Relatórios em: {out_dir}/report.(json|md|csv)", style="green")

    if progress:
        progress.stop()

    if any(f["severity"] == "high" for f in findings):
        exit(2)
    elif any(f["severity"] == "medium" for f in findings):
        exit(1)
    else:
        exit(0)

if __name__ == "__main__":
    main()
