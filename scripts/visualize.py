#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OCI Public Perimeter Visualizer
================================

Genera visualizzazioni da un CSV prodotto da oci_public_perimeter_scan.py.

Output:
  - Diagramma Mermaid (.mmd) della topologia esposizioni
  - PNG: esposizioni per compartment (bar chart)
  - PNG: heatmap categoria x region
  - PNG: distribuzione per tipo risorsa (pie/donut)
  - HTML: dashboard navigabile con tabella filtrabile

Uso:
  python3 oci_perimeter_viz.py reports/oci_perimeter_20260512T103000Z.csv
  python3 oci_perimeter_viz.py reports/*.csv --output-dir ./viz
  python3 oci_perimeter_viz.py latest --auto    # prende l'ultimo csv in ./reports
"""

import argparse
import csv
import glob
import html
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import matplotlib
    matplotlib.use("Agg")  # backend non interattivo
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("ERROR: matplotlib non installato. Esegui: pip install matplotlib", file=sys.stderr)
    sys.exit(2)


# ----------------------------------------------------------------------------
# Caricamento CSV
# ----------------------------------------------------------------------------

def load_records(csv_path: Path) -> List[Dict[str, str]]:
    with open(csv_path, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        return list(reader)


def find_latest_csv(directory: Path, prefix: str = "oci_perimeter") -> Path:
    candidates = sorted(directory.glob(f"{prefix}_*.csv"))
    if not candidates:
        raise FileNotFoundError(f"Nessun CSV {prefix}_*.csv trovato in {directory}")
    return candidates[-1]


# ----------------------------------------------------------------------------
# Mermaid topology diagram
# ----------------------------------------------------------------------------

def sanitize_id(s: str, maxlen: int = 40) -> str:
    """Rende una stringa sicura come ID Mermaid."""
    out = "".join(c if c.isalnum() else "_" for c in (s or "x"))
    return out[:maxlen] or "x"


def build_mermaid(records: List[Dict[str, str]], max_leaves_per_group: int = 8) -> str:
    """
    Topologia: Tenant > Region > Compartment > ResourceType > {Risorsa+IP}.
    Se un gruppo ha > max_leaves_per_group foglie, le aggrega in "N more...".
    """
    tree: Dict[str, Dict[str, Dict[str, List[Dict[str, str]]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(list))
    )
    for r in records:
        region = r.get("Region") or "unknown-region"
        comp = r.get("CompartmentName") or "unknown-comp"
        rtype = r.get("ResourceType") or "UNKNOWN"
        tree[region][comp][rtype].append(r)

    lines = ["graph LR", "    TENANT[OCI Tenant]"]
    seen = set()

    for region, comps in sorted(tree.items()):
        rid = "R_" + sanitize_id(region)
        lines.append(f'    {rid}["{html.escape(region)}"]')
        lines.append(f"    TENANT --> {rid}")
        for comp, rtypes in sorted(comps.items()):
            cid = f"{rid}_C_" + sanitize_id(comp)
            if cid not in seen:
                # numero totale esposizioni nel compartment
                total = sum(len(v) for v in rtypes.values())
                lines.append(f'    {cid}["{html.escape(comp)}<br/>({total} item)"]')
                lines.append(f"    {rid} --> {cid}")
                seen.add(cid)
            for rtype, items in sorted(rtypes.items()):
                tid = f"{cid}_T_" + sanitize_id(rtype)
                lines.append(f'    {tid}["{html.escape(rtype)}<br/>x{len(items)}"]')
                lines.append(f"    {cid} --> {tid}")

                # foglie: IP o nome risorsa
                shown = items[:max_leaves_per_group]
                for i, it in enumerate(shown):
                    label = it.get("PublicIP") or it.get("Endpoint") or it.get("ResourceName") or "n/a"
                    label = label[:50]
                    lid = f"{tid}_L{i}"
                    # colora i nodi con Cloud Guard finding
                    cg = it.get("CloudGuardRiskLevel", "")
                    if cg:
                        lines.append(f'    {lid}(("{html.escape(label)}<br/>CG:{html.escape(cg)}"))')
                        lines.append(f"    class {lid} cgRisk")
                    else:
                        lines.append(f'    {lid}["{html.escape(label)}"]')
                    lines.append(f"    {tid} --> {lid}")
                if len(items) > max_leaves_per_group:
                    extra = len(items) - max_leaves_per_group
                    mid = f"{tid}_more"
                    lines.append(f'    {mid}["...+{extra} altri"]')
                    lines.append(f"    {tid} --> {mid}")

    lines.append("    classDef cgRisk fill:#ffcccc,stroke:#cc0000,stroke-width:2px;")
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# Bar chart: esposizioni per compartment
# ----------------------------------------------------------------------------

def chart_by_compartment(records: List[Dict[str, str]], out_path: Path, top_n: int = 20) -> None:
    counter = Counter(r.get("CompartmentName") or "unknown" for r in records)
    items = counter.most_common(top_n)
    if not items:
        return
    labels, counts = zip(*items)
    fig, ax = plt.subplots(figsize=(11, max(4, len(labels) * 0.35)))
    bars = ax.barh(labels, counts, color="#2E86AB", edgecolor="#1B4965")
    ax.invert_yaxis()
    ax.set_xlabel("Numero esposizioni rilevate")
    ax.set_title(f"Esposizioni pubbliche per compartment (top {len(items)})")
    ax.grid(axis="x", alpha=0.3)
    for bar, c in zip(bars, counts):
        ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
                str(c), va="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(out_path, dpi=140, bbox_inches="tight")
    plt.close(fig)


# ----------------------------------------------------------------------------
# Heatmap categoria x region
# ----------------------------------------------------------------------------

def chart_heatmap(records: List[Dict[str, str]], out_path: Path) -> None:
    regions = sorted({r.get("Region") or "?" for r in records})
    categories = sorted({r.get("ExposureCategory") or "?" for r in records})
    if not regions or not categories:
        return
    matrix = np.zeros((len(categories), len(regions)), dtype=int)
    cat_idx = {c: i for i, c in enumerate(categories)}
    reg_idx = {r: i for i, r in enumerate(regions)}
    for r in records:
        ci = cat_idx[r.get("ExposureCategory") or "?"]
        ri = reg_idx[r.get("Region") or "?"]
        matrix[ci, ri] += 1

    fig, ax = plt.subplots(figsize=(max(6, len(regions) * 1.4), max(4, len(categories) * 0.5)))
    im = ax.imshow(matrix, cmap="YlOrRd", aspect="auto")
    ax.set_xticks(range(len(regions)))
    ax.set_xticklabels(regions, rotation=30, ha="right")
    ax.set_yticks(range(len(categories)))
    ax.set_yticklabels(categories, fontsize=9)
    for i in range(len(categories)):
        for j in range(len(regions)):
            v = matrix[i, j]
            if v > 0:
                ax.text(j, i, str(v), ha="center", va="center",
                        color="white" if v > matrix.max() / 2 else "black", fontsize=9)
    ax.set_title("Esposizioni: categoria × region")
    fig.colorbar(im, ax=ax, label="count")
    plt.tight_layout()
    plt.savefig(out_path, dpi=140, bbox_inches="tight")
    plt.close(fig)


# ----------------------------------------------------------------------------
# Donut: distribuzione per tipo risorsa
# ----------------------------------------------------------------------------

def chart_resource_donut(records: List[Dict[str, str]], out_path: Path) -> None:
    counter = Counter(r.get("ResourceType") or "UNKNOWN" for r in records)
    if not counter:
        return
    items = counter.most_common(10)
    other = sum(v for _, v in counter.most_common()[10:])
    if other:
        items.append(("ALTRI", other))
    labels, sizes = zip(*items)
    fig, ax = plt.subplots(figsize=(9, 7))
    colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct="%1.1f%%",
        startangle=90, pctdistance=0.78,
        wedgeprops=dict(width=0.42, edgecolor="white"),
    )
    for t in autotexts:
        t.set_fontsize(9)
        t.set_color("#222")
    ax.set_title(f"Distribuzione esposizioni per tipo risorsa (totale: {sum(counter.values())})")
    plt.tight_layout()
    plt.savefig(out_path, dpi=140, bbox_inches="tight")
    plt.close(fig)


# ----------------------------------------------------------------------------
# HTML dashboard
# ----------------------------------------------------------------------------

def build_dashboard(records, mermaid_text, png_paths, out_path: Path, tenant_label="OCI Tenant"):
    total = len(records)
    unique_ips = len({r["PublicIP"] for r in records if r.get("PublicIP")})
    cg_correlated = sum(1 for r in records if r.get("CloudGuardRiskLevel"))
    regions = sorted({r.get("Region", "") for r in records if r.get("Region")})

    # tabella JSON-embed per filtri client-side
    visible_fields = ["Region", "CompartmentName", "ExposureCategory", "PublicIP",
                      "Endpoint", "ResourceType", "ResourceName", "CloudGuardRiskLevel"]
    rows_json = [{k: r.get(k, "") for k in visible_fields} for r in records]

    import json
    rows_b64 = json.dumps(rows_json, ensure_ascii=False)

    html_doc = f"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<title>OCI Perimeter Dashboard — {html.escape(tenant_label)}</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<style>
  body {{ font-family: -apple-system, Arial, sans-serif; margin: 0; padding: 20px; background: #f5f6fa; color: #222; }}
  h1 {{ margin-top: 0; }}
  .kpis {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 20px 0; }}
  .kpi {{ background: white; padding: 16px 24px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .kpi .v {{ font-size: 28px; font-weight: bold; color: #2E86AB; }}
  .kpi .l {{ font-size: 12px; color: #666; text-transform: uppercase; }}
  .section {{ background: white; padding: 20px; border-radius: 8px; margin: 16px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .charts img {{ width: 100%; border-radius: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 8px 10px; text-align: left; border-bottom: 1px solid #eee; }}
  th {{ background: #343a40; color: white; position: sticky; top: 0; cursor: pointer; }}
  tr:hover {{ background: #f8f9fa; }}
  .cg {{ background: #ffe5e5; }}
  input[type=text] {{ padding: 8px; width: 320px; border: 1px solid #ccc; border-radius: 4px; }}
  .filter-row {{ margin-bottom: 12px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
  select {{ padding: 8px; border: 1px solid #ccc; border-radius: 4px; }}
  .mermaid {{ background: white; padding: 20px; border-radius: 4px; overflow-x: auto; }}
</style>
</head>
<body>
<h1>OCI Public Perimeter — {html.escape(tenant_label)}</h1>
<p style="color:#666;">Generato il {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} · regions: {html.escape(', '.join(regions))}</p>

<div class="kpis">
  <div class="kpi"><div class="v">{total}</div><div class="l">esposizioni totali</div></div>
  <div class="kpi"><div class="v">{unique_ips}</div><div class="l">IP pubblici univoci</div></div>
  <div class="kpi"><div class="v">{cg_correlated}</div><div class="l">finding Cloud Guard</div></div>
  <div class="kpi"><div class="v">{len(regions)}</div><div class="l">region attive</div></div>
</div>

<div class="section">
  <h2>Grafici</h2>
  <div class="charts">
"""
    for label, p in png_paths:
        if p and p.exists():
            html_doc += f'    <div><h3>{html.escape(label)}</h3><img src="{p.name}" alt="{html.escape(label)}"></div>\n'
    html_doc += """  </div>
</div>

<div class="section">
  <h2>Topologia (Mermaid)</h2>
  <div class="mermaid">
""" + mermaid_text + """
  </div>
</div>

<div class="section">
  <h2>Tabella esposizioni</h2>
  <div class="filter-row">
    <input type="text" id="filter" placeholder="filtra (IP, compartment, risorsa...)" oninput="applyFilter()">
    <select id="catFilter" onchange="applyFilter()"><option value="">Tutte le categorie</option></select>
    <select id="regFilter" onchange="applyFilter()"><option value="">Tutte le region</option></select>
    <span id="count" style="color:#666;"></span>
  </div>
  <div style="max-height: 600px; overflow-y: auto;">
    <table id="dataTable">
      <thead><tr>""" + "".join(f"<th>{html.escape(f)}</th>" for f in visible_fields) + """</tr></thead>
      <tbody></tbody>
    </table>
  </div>
</div>

<script>
  mermaid.initialize({ startOnLoad: true, theme: 'default', securityLevel: 'loose' });
  const DATA = """ + rows_b64 + """;
  const FIELDS = """ + json.dumps(visible_fields) + """;

  function populateFilters() {
    const cats = [...new Set(DATA.map(r => r.ExposureCategory))].filter(Boolean).sort();
    const regs = [...new Set(DATA.map(r => r.Region))].filter(Boolean).sort();
    const cf = document.getElementById('catFilter');
    cats.forEach(c => { const o = document.createElement('option'); o.value = c; o.textContent = c; cf.appendChild(o); });
    const rf = document.getElementById('regFilter');
    regs.forEach(c => { const o = document.createElement('option'); o.value = c; o.textContent = c; rf.appendChild(o); });
  }

  function render(rows) {
    const tb = document.querySelector('#dataTable tbody');
    tb.innerHTML = rows.map(r => {
      const cls = r.CloudGuardRiskLevel ? 'cg' : '';
      return `<tr class="${cls}">` + FIELDS.map(f => `<td>${escapeHtml(r[f] || '')}</td>`).join('') + '</tr>';
    }).join('');
    document.getElementById('count').textContent = `${rows.length} righe`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function applyFilter() {
    const q = document.getElementById('filter').value.toLowerCase();
    const cat = document.getElementById('catFilter').value;
    const reg = document.getElementById('regFilter').value;
    const filtered = DATA.filter(r => {
      if (cat && r.ExposureCategory !== cat) return false;
      if (reg && r.Region !== reg) return false;
      if (!q) return true;
      return FIELDS.some(f => String(r[f] || '').toLowerCase().includes(q));
    });
    render(filtered);
  }

  populateFilters();
  render(DATA);
</script>
</body>
</html>
"""
    out_path.write_text(html_doc, encoding="utf-8")


# ----------------------------------------------------------------------------
# Anomalie / highlights
# ----------------------------------------------------------------------------

def find_anomalies(records: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    out: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for r in records:
        if r.get("ResourceType") == "UNASSIGNED" and r.get("PublicIP"):
            out["public_ip_orphaned"].append(r)
        if r.get("ExposureCategory") == "OBJECT_STORAGE_PUBLIC_BUCKET":
            out["public_buckets"].append(r)
        if r.get("ExposureCategory") == "OBJECT_STORAGE_PRE_AUTHENTICATED_REQUEST":
            if r.get("ExposureStatus") == "ACTIVE":
                out["active_pars"].append(r)
        if r.get("CloudGuardRiskLevel"):
            out["cloud_guard"].append(r)
    return out


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="Visualizzatore output scanner OCI perimetro pubblico")
    ap.add_argument("csv", nargs="?", help="Path al CSV (oppure 'latest' per autodetect)")
    ap.add_argument("--input-dir", default="./reports", help="Dir dove cercare 'latest' (default: ./reports)")
    ap.add_argument("--output-dir", default="./reports", help="Dir di output per grafici (default: ./reports)")
    ap.add_argument("--tenant-label", default="OCI Tenant")
    ap.add_argument("--max-leaves", type=int, default=8, help="Max foglie per nodo nel diagramma Mermaid")
    return ap.parse_args()


def main():
    args = parse_args()

    if not args.csv or args.csv == "latest":
        csv_path = find_latest_csv(Path(args.input_dir))
    else:
        csv_path = Path(args.csv)
        if not csv_path.exists():
            print(f"ERROR: file non trovato: {csv_path}", file=sys.stderr)
            return 1

    records = load_records(csv_path)
    print(f"Caricati {len(records)} record da {csv_path}", file=sys.stderr)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # Mermaid
    mermaid_text = build_mermaid(records, max_leaves_per_group=args.max_leaves)
    mmd_path = out_dir / f"topology_{stamp}.mmd"
    mmd_path.write_text(mermaid_text, encoding="utf-8")
    print(f"  → {mmd_path}", file=sys.stderr)

    # Bar chart compartment
    bar_path = out_dir / f"by_compartment_{stamp}.png"
    chart_by_compartment(records, bar_path)
    print(f"  → {bar_path}", file=sys.stderr)

    # Heatmap
    heat_path = out_dir / f"heatmap_{stamp}.png"
    chart_heatmap(records, heat_path)
    print(f"  → {heat_path}", file=sys.stderr)

    # Donut
    donut_path = out_dir / f"by_resource_type_{stamp}.png"
    chart_resource_donut(records, donut_path)
    print(f"  → {donut_path}", file=sys.stderr)

    # Dashboard HTML
    dash_path = out_dir / f"dashboard_{stamp}.html"
    build_dashboard(
        records, mermaid_text,
        [("Esposizioni per compartment", bar_path),
         ("Categoria × Region", heat_path),
         ("Distribuzione per tipo risorsa", donut_path)],
        dash_path, tenant_label=args.tenant_label,
    )
    print(f"  → {dash_path}", file=sys.stderr)

    # Anomalie su stdout
    anomalies = find_anomalies(records)
    print("\n=== ANOMALIE ===")
    print(f"IP pubblici orfani (assegnati ma UNASSIGNED): {len(anomalies['public_ip_orphaned'])}")
    print(f"Bucket Object Storage pubblici: {len(anomalies['public_buckets'])}")
    print(f"Pre-Authenticated Request attive: {len(anomalies['active_pars'])}")
    print(f"Record correlati Cloud Guard: {len(anomalies['cloud_guard'])}")

    print(f"\nDashboard: file://{dash_path.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

