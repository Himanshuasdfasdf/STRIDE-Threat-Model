#!/usr/bin/env python3
"""
STRIDE Threat Model Analyzer
============================
Parses an OWASP Threat Dragon (v2) JSON threat model, then:

  1. Flattens every threat into a table (CSV export)
  2. Runs a STRIDE-per-element coverage check (finds categories nobody analysed)
  3. Scores and ranks risk (severity x status -> residual risk)
  4. Generates charts, a rendered Data Flow Diagram (DFD) and a Markdown summary

Usage:
    python stride_analyzer.py --model threat_model/ecommerce_threat_model.json --out output
"""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # headless backend, no display needed
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyBboxPatch
import pandas as pd

STRIDE = [
    "Spoofing", "Tampering", "Repudiation",
    "Information disclosure", "Denial of service", "Elevation of privilege",
]

# STRIDE-per-element: which categories apply to which DFD element type
APPLICABLE = {
    "tm.Actor":   {"Spoofing", "Repudiation"},
    "tm.Process": set(STRIDE),
    "tm.Store":   {"Tampering", "Repudiation", "Information disclosure", "Denial of service"},
    "tm.Flow":    {"Tampering", "Information disclosure", "Denial of service"},
}
TYPE_LABEL = {"tm.Actor": "External Entity", "tm.Process": "Process",
              "tm.Store": "Data Store", "tm.Flow": "Data Flow"}

SEVERITY_WEIGHT = {"High": 9, "Medium": 5, "Low": 2}
# Mitigated threats still carry some residual risk
STATUS_FACTOR = {"Open": 1.0, "Mitigated": 0.2}

COLORS = {"High": "#d64545", "Medium": "#f0a030", "Low": "#4a9b5a"}


# --------------------------------------------------------------------------- #
# Loading & flattening
# --------------------------------------------------------------------------- #
def load_model(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def iter_cells(model):
    for diagram in model["detail"]["diagrams"]:
        for cell in diagram.get("cells", []):
            yield cell


def build_dataframe(model):
    """Return (threat_df, elements_df)."""
    cells = {c["id"]: c for c in iter_cells(model)}
    threat_rows, element_rows = [], []

    for cid, cell in cells.items():
        data = cell.get("data", {})
        etype = data.get("type")
        if etype not in APPLICABLE:  # skip trust boundaries
            continue
        name = data.get("name", "unnamed")
        if etype == "tm.Flow":
            src = cells[cell["source"]["cell"]]["data"]["name"]
            dst = cells[cell["target"]["cell"]]["data"]["name"]
            name = f"{name} ({src} -> {dst})"
        element_rows.append({"id": cid, "element": name, "type": etype,
                             "type_label": TYPE_LABEL[etype],
                             "threat_count": len(data.get("threats", []))})
        for t in data.get("threats", []):
            sev, status = t.get("severity", "Medium"), t.get("status", "Open")
            inherent = SEVERITY_WEIGHT.get(sev, 5)
            threat_rows.append({
                "id": t["number"], "element": name, "element_type": TYPE_LABEL[etype],
                "stride": t["type"], "title": t["title"], "severity": sev, "status": status,
                "inherent_score": inherent,
                "residual_score": round(inherent * STATUS_FACTOR.get(status, 1.0), 1),
                "description": t.get("description", ""), "mitigation": t.get("mitigation", ""),
            })
    return pd.DataFrame(threat_rows), pd.DataFrame(element_rows), cells


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def coverage_gaps(model, threats):
    """STRIDE-per-element: applicable categories with zero identified threats."""
    gaps = []
    for cell in iter_cells(model):
        data = cell.get("data", {})
        etype = data.get("type")
        if etype not in APPLICABLE:
            continue
        found = {t["type"] for t in data.get("threats", [])}
        missing = sorted(APPLICABLE[etype] - found)
        if missing:
            gaps.append({"element": data["name"], "type": TYPE_LABEL[etype],
                         "missing_categories": ", ".join(missing)})
    return pd.DataFrame(gaps)


def summarise(threats):
    return {
        "total": len(threats),
        "open": int((threats.status == "Open").sum()),
        "mitigated": int((threats.status == "Mitigated").sum()),
        "high_open": int(((threats.severity == "High") & (threats.status == "Open")).sum()),
        "inherent_risk": float(threats.inherent_score.sum()),
        "residual_risk": float(threats.residual_score.sum()),
    }


# --------------------------------------------------------------------------- #
# Visuals
# --------------------------------------------------------------------------- #
def chart_stride_distribution(threats, out):
    pivot = (threats.pivot_table(index="stride", columns="severity", values="id",
                                 aggfunc="count", fill_value=0)
             .reindex(STRIDE).fillna(0))
    for col in ["High", "Medium", "Low"]:
        if col not in pivot:
            pivot[col] = 0
    ax = pivot[["High", "Medium", "Low"]].plot(kind="bar", stacked=True, figsize=(9, 5),
                                               color=[COLORS[c] for c in ["High", "Medium", "Low"]])
    ax.set_ylim(0, pivot.sum(axis=1).max() + 2)
    ax.set_title("Threats per STRIDE category (by severity)")
    ax.set_xlabel("")
    ax.set_ylabel("Number of threats")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(out / "stride_distribution.png", dpi=150)
    plt.close()


def chart_status(threats, out):
    fig, axes = plt.subplots(1, 2, figsize=(9, 4))
    status = threats.status.value_counts()
    axes[0].pie(status, labels=status.index, autopct="%1.0f%%",
                colors=["#d64545", "#4a9b5a"][:len(status)], startangle=90)
    axes[0].set_title("Mitigation status")
    sev = threats.severity.value_counts().reindex(["High", "Medium", "Low"]).fillna(0)
    axes[1].bar(sev.index, sev.values, color=[COLORS[s] for s in sev.index])
    axes[1].set_title("Severity distribution")
    axes[1].set_ylabel("Threats")
    plt.tight_layout()
    plt.savefig(out / "status_severity.png", dpi=150)
    plt.close()


def chart_heatmap(threats, out):
    pivot = threats.pivot_table(index="element", columns="stride", values="residual_score",
                                aggfunc="sum", fill_value=0).reindex(columns=STRIDE, fill_value=0)
    pivot = pivot.loc[pivot.sum(axis=1).sort_values(ascending=True).index]
    fig, ax = plt.subplots(figsize=(11, max(5, 0.38 * len(pivot))))
    im = ax.imshow(pivot.values, cmap="YlOrRd", aspect="auto")
    ax.set_xticks(range(len(STRIDE)))
    ax.set_xticklabels([s.replace(" ", "\n") for s in STRIDE], fontsize=8)
    ax.set_yticks(range(len(pivot)))
    ax.set_yticklabels([e[:42] for e in pivot.index], fontsize=7)
    for i in range(pivot.shape[0]):
        for j in range(pivot.shape[1]):
            v = pivot.values[i, j]
            if v:
                ax.text(j, i, f"{v:g}", ha="center", va="center", fontsize=7)
    ax.set_title("Residual risk heatmap (element x STRIDE category)")
    fig.colorbar(im, ax=ax, shrink=0.6, label="Residual risk score")
    plt.tight_layout()
    plt.savefig(out / "risk_heatmap.png", dpi=150)
    plt.close()


def render_dfd(cells, out):
    """Draw the Data Flow Diagram using positions stored in the Threat Dragon file."""
    fig, ax = plt.subplots(figsize=(12, 7.5))
    centers = {}
    for cid, c in cells.items():
        if c["shape"] == "trust-boundary-box":
            p, s = c["position"], c["size"]
            ax.add_patch(Rectangle((p["x"], p["y"]), s["width"], s["height"], fill=False,
                                   linestyle="--", edgecolor="#b02020", linewidth=1.6))
            ax.text(p["x"] + 8, p["y"] + s["height"] - 12, c["data"]["name"], color="#b02020",
                    fontsize=9, fontweight="bold", va="top")
    for cid, c in cells.items():
        shape = c["shape"]
        if shape in ("actor", "process", "store"):
            p, s = c["position"], c["size"]
            x, y, w, h = p["x"], p["y"], s["width"], s["height"]
            centers[cid] = (x + w / 2, y + h / 2)
            n_open = sum(t["status"] == "Open" for t in c["data"]["threats"])
            if shape == "actor":
                ax.add_patch(Rectangle((x, y), w, h, facecolor="#e8eefc", edgecolor="#2d4a99", lw=1.5))
            elif shape == "process":
                ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=30",
                                            facecolor="#e6f4ea", edgecolor="#2d7a3e", lw=1.5))
            else:
                ax.plot([x, x + w], [y, y], color="#7a5b00", lw=2)
                ax.plot([x, x + w], [y + h, y + h], color="#7a5b00", lw=2)
                ax.add_patch(Rectangle((x, y), w, h, facecolor="#fff6dc", edgecolor="none"))
            ax.text(x + w / 2, y + h / 2, c["data"]["name"].replace(" (", "\n("), ha="center",
                    va="center", fontsize=7.5, fontweight="bold")
            ax.text(x + w - 3, y + 3, f"{n_open} open", ha="right", va="bottom", fontsize=6.5,
                    color="#b02020")
    for cid, c in cells.items():
        if c["shape"] == "flow":
            a, b = centers[c["source"]["cell"]], centers[c["target"]["cell"]]
            ax.annotate("", xy=b, xytext=a,
                        arrowprops=dict(arrowstyle="->", color="#444", lw=1.3, shrinkA=38, shrinkB=38))
            ax.text((a[0] + b[0]) / 2, (a[1] + b[1]) / 2, c["data"]["name"], fontsize=6.5,
                    color="#333", ha="center", bbox=dict(fc="white", ec="none", alpha=0.85, pad=0.8))
    ax.set_xlim(-10, 1070)
    ax.set_ylim(540, -10)  # y axis downwards like the Threat Dragon canvas
    ax.set_aspect("equal")
    ax.axis("off")
    ax.set_title("Data Flow Diagram - E-Commerce Microservices", fontsize=12, fontweight="bold")
    plt.tight_layout()
    plt.savefig(out / "dfd.png", dpi=150)
    plt.close()


# --------------------------------------------------------------------------- #
# Markdown summary
# --------------------------------------------------------------------------- #
def write_markdown(model, threats, gaps, stats, out):
    top = threats[threats.status == "Open"].sort_values(
        ["residual_score", "element"], ascending=[False, True]).head(10)
    lines = [f"# {model['summary']['title']} - Analysis Summary", "",
             "## Key numbers", "",
             f"- Total threats identified: **{stats['total']}**",
             f"- Open: **{stats['open']}**, Mitigated: **{stats['mitigated']}**",
             f"- High-severity threats still open: **{stats['high_open']}**",
             f"- Inherent risk score: **{stats['inherent_risk']:.0f}** -> "
             f"residual: **{stats['residual_risk']:.1f}** "
             f"({100 * (1 - stats['residual_risk'] / stats['inherent_risk']):.0f}% reduction)", "",
             "## Top 10 open threats", "",
             "| # | Element | STRIDE | Threat | Severity |", "|---|---|---|---|---|"]
    for _, r in top.iterrows():
        lines.append(f"| {r['id']} | {r['element']} | {r['stride']} | {r['title']} | {r['severity']} |")
    lines += ["", "## Coverage gaps (STRIDE-per-element)", ""]
    if gaps.empty:
        lines.append("No gaps: every applicable STRIDE category has at least one threat.")
    else:
        lines += ["| Element | Type | Missing categories |", "|---|---|---|"]
        lines += [f"| {r.element} | {r.type} | {r.missing_categories} |" for r in gaps.itertuples()]
    (out / "analysis_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="STRIDE analyzer for OWASP Threat Dragon models")
    ap.add_argument("--model", default="threat_model/ecommerce_threat_model.json",
                    help="Path to Threat Dragon JSON file")
    ap.add_argument("--out", default="output", help="Output directory")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    model = load_model(args.model)
    threats, elements, cells = build_dataframe(model)
    gaps = coverage_gaps(model, threats)
    stats = summarise(threats)

    threats.sort_values("residual_score", ascending=False).to_csv(out / "threats.csv", index=False)
    gaps.to_csv(out / "coverage_gaps.csv", index=False)
    chart_stride_distribution(threats, out)
    chart_status(threats, out)
    chart_heatmap(threats, out)
    render_dfd(cells, out)
    write_markdown(model, threats, gaps, stats, out)

    print("=== STRIDE ANALYSIS ===")
    print(f"Elements analysed : {len(elements)}")
    for k, v in stats.items():
        print(f"{k:<18}: {v}")
    print(f"Coverage gaps     : {len(gaps)} element(s)")
    print(f"Outputs written to: {out.resolve()}")


if __name__ == "__main__":
    main()
