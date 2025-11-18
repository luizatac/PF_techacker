#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import csv
from collections import Counter
from datetime import datetime
from pathlib import Path

SEV_ORDER = ["high", "medium", "low", "info"]

def _sev_sorted_items(counter: Counter):
    # retorna pares (sev, count) ordenados por criticidade
    return sorted(counter.items(), key=lambda kv: SEV_ORDER.index(kv[0]) if kv[0] in SEV_ORDER else 999)

def write_json(findings, out_path):
    """
    Salva os achados em JSON (idêntico ao que o scanner imprime em --json-stdout).
    """
    Path(out_path).write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")

def write_markdown(findings, out_path):
    """
    Gera um relatório Markdown legível, com resumo por severidade e listagem dos achados.
    Inclui OWASP code e descrição curta (owasp_desc) quando presente.
    """
    lines = []
    lines.append("# Web Security Scan Report\n")
    lines.append(f"_Generated at: {datetime.utcnow().isoformat()}Z_\n")

    if not findings:
        lines.append("> Nenhuma vulnerabilidade encontrada.\n")
        Path(out_path).write_text("\n".join(lines), encoding="utf-8")
        return

    # Resumo por severidade
    sev_counts = Counter([f.get("severity","info") for f in findings])
    lines.append("## Resumo por severidade\n")
    for sev, n in _sev_sorted_items(sev_counts):
        lines.append(f"- **{sev}**: {n}")
    lines.append("")

    # Ferramentas utilizadas (quando presentes)
    tools = sorted({f.get("tool","core") for f in findings})
    if tools:
        lines.append("**Ferramentas**: " + ", ".join(f"`{t}`" for t in tools) + "\n")

    # Lista de achados
    lines.append("## Achados\n")
    for f in findings:
        lines.append(f"### {f.get('type','')}")
        lines.append(f"- Severidade: **{f.get('severity','')}**")
        if f.get("tool"):       lines.append(f"- Ferramenta: `{f['tool']}`")
        if f.get("url"):        lines.append(f"- URL: {f['url']}")
        if f.get("param"):      lines.append(f"- Parâmetro: `{f['param']}`")
        if f.get("owasp"):      lines.append(f"- OWASP: `{f['owasp']}`")
        if f.get("owasp_desc"): lines.append(f"- OWASP (desc): {f['owasp_desc']}")
        if f.get("evidence"):
            ev = str(f.get("evidence",""))
            ev_short = ev if len(ev) <= 240 else ev[:240] + "…"
            lines.append(f"- Evidência: `{ev_short}`")
        if f.get("solution"):
            lines.append(f"- **Solução sugerida:** {f['solution']}")
        lines.append("")
    Path(out_path).write_text("\n".join(lines), encoding="utf-8")

def write_csv(findings, out_path):
    """
    Exporta CSV com colunas úteis para análise rápida e planilhas.
    """
    if not findings:
        Path(out_path).write_text("", encoding="utf-8")
        return

    keys = ["time","type","severity","url","param","owasp","owasp_desc","tool","evidence","solution"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for x in findings:
            row = {k: x.get(k,"") for k in keys}
            # encurta evidência para não “explodir” planilhas; ajuste se preferir
            if row.get("evidence") and len(row["evidence"]) > 512:
                row["evidence"] = row["evidence"][:512] + "…"
            w.writerow(row)
