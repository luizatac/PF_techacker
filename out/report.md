# Web Security Scan Report

_Generated at: 2025-11-17T17:36:04.995998Z_

## Resumo por severidade

- **high**: 4
- **medium**: 5

**Ferramentas**: `core`

## Achados

### Security Headers ausentes
- Severidade: **medium**
- Ferramenta: `core`
- URL: https://demo.owasp-juice.shop
- OWASP: `A05`
- OWASP (desc): Security Misconfiguration: insecure default configs, open buckets, missing headers, verbose errors.
- Evidência: `strict-transport-security, content-security-policy, referrer-policy, permissions-policy`
- **Solução sugerida:** Enable HSTS (e.g., max-age>=15552000; includeSubDomains; preload). Force HTTPS at the edge/load balancer and remove HTTP endpoints.; Define a restrictive CSP (e.g., default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'). Avoid inline scripts or use nonces/hashes; audit third-party domains.; Adopt a strict Referrer-Policy (e.g., no-referrer or strict-origin-when-cross-origin) to minimize data leakage.; Use Permissions-Policy to disable unused browser features (e.g., geolocation=(), camera=(), microphone=()).

### Exposição de arquivos/diretórios
- Severidade: **high**
- Ferramenta: `core`
- URL: https://demo.owasp-juice.shop/.git/HEAD
- OWASP: `A05`
- OWASP (desc): Security Misconfiguration: insecure default configs, open buckets, missing headers, verbose errors.
- Evidência: `200`
- **Solução sugerida:** Remover artefatos (.git, .env, backups); negar listagem de diretórios; separar segredos do repositório; revisar regras do servidor/cdn; validar políticas de cache/CDN (private, no-store).

### Exposição de arquivos/diretórios
- Severidade: **high**
- Ferramenta: `core`
- URL: https://demo.owasp-juice.shop/.env
- OWASP: `A05`
- OWASP (desc): Security Misconfiguration: insecure default configs, open buckets, missing headers, verbose errors.
- Evidência: `200`
- **Solução sugerida:** Remover artefatos (.git, .env, backups); negar listagem de diretórios; separar segredos do repositório; revisar regras do servidor/cdn; validar políticas de cache/CDN (private, no-store).

### Exposição de arquivos/diretórios
- Severidade: **high**
- Ferramenta: `core`
- URL: https://demo.owasp-juice.shop/config.php
- OWASP: `A05`
- OWASP (desc): Security Misconfiguration: insecure default configs, open buckets, missing headers, verbose errors.
- Evidência: `200`
- **Solução sugerida:** Remover artefatos (.git, .env, backups); negar listagem de diretórios; separar segredos do repositório; revisar regras do servidor/cdn; validar políticas de cache/CDN (private, no-store).

### Exposição de arquivos/diretórios
- Severidade: **high**
- Ferramenta: `core`
- URL: https://demo.owasp-juice.shop/backup.zip
- OWASP: `A05`
- OWASP (desc): Security Misconfiguration: insecure default configs, open buckets, missing headers, verbose errors.
- Evidência: `200`
- **Solução sugerida:** Remover artefatos (.git, .env, backups); negar listagem de diretórios; separar segredos do repositório; revisar regras do servidor/cdn; validar políticas de cache/CDN (private, no-store).

### Exposição de arquivos/diretórios
- Severidade: **medium**
- Ferramenta: `core`
- URL: https://demo.owasp-juice.shop/admin/
- OWASP: `A05`
- OWASP (desc): Security Misconfiguration: insecure default configs, open buckets, missing headers, verbose errors.
- Evidência: `200`
- **Solução sugerida:** Remover artefatos (.git, .env, backups); negar listagem de diretórios; separar segredos do repositório; revisar regras do servidor/cdn; validar políticas de cache/CDN (private, no-store).

### Exposição de arquivos/diretórios
- Severidade: **medium**
- Ferramenta: `core`
- URL: https://demo.owasp-juice.shop/_admin/
- OWASP: `A05`
- OWASP (desc): Security Misconfiguration: insecure default configs, open buckets, missing headers, verbose errors.
- Evidência: `200`
- **Solução sugerida:** Remover artefatos (.git, .env, backups); negar listagem de diretórios; separar segredos do repositório; revisar regras do servidor/cdn; validar políticas de cache/CDN (private, no-store).

### Exposição de arquivos/diretórios
- Severidade: **medium**
- Ferramenta: `core`
- URL: https://demo.owasp-juice.shop/.vscode/
- OWASP: `A05`
- OWASP (desc): Security Misconfiguration: insecure default configs, open buckets, missing headers, verbose errors.
- Evidência: `200`
- **Solução sugerida:** Remover artefatos (.git, .env, backups); negar listagem de diretórios; separar segredos do repositório; revisar regras do servidor/cdn; validar políticas de cache/CDN (private, no-store).

### Exposição de arquivos/diretórios
- Severidade: **medium**
- Ferramenta: `core`
- URL: https://demo.owasp-juice.shop/.idea/
- OWASP: `A05`
- OWASP (desc): Security Misconfiguration: insecure default configs, open buckets, missing headers, verbose errors.
- Evidência: `200`
- **Solução sugerida:** Remover artefatos (.git, .env, backups); negar listagem de diretórios; separar segredos do repositório; revisar regras do servidor/cdn; validar políticas de cache/CDN (private, no-store).
