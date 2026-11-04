#!/usr/bin/env python3
"""Validate data/threats.yaml and (re)generate the tables, risk register, traceability and ATT&CK Navigator layers.

  python3 scripts/build.py          validate + write generated files
  python3 scripts/build.py --check  validate + fail if committed generated files are stale (for CI)

Validation failures exit 1. Warnings (e.g. a level>=5 detection rule that no threat references) print but do not fail.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
STATUSES = {"mitigated", "partial", "open", "accepted"}


def load():
    model = yaml.safe_load((ROOT / "data/threats.yaml").read_text())
    xml = ET.fromstring("<root>" + (ROOT / "detections/payloop_rules.xml").read_text() + "</root>")
    rules = {}
    for r in xml.iter("rule"):
        rules[int(r.get("id"))] = {
            "level": int(r.get("level", 0)),
            "desc": (r.findtext("description") or "").strip(),
            "mitre": [i.text.strip() for i in r.iter("id")],
        }
    return model, rules


def score(t):
    return t["likelihood"] * t["impact"]


def band(model, s):
    b = model["risk_bands"]
    return "Critical" if s >= b["critical"] else "High" if s >= b["high"] else "Medium" if s >= b["medium"] else "Low"


def validate(model, rules):
    errs, warns = [], []
    elems = {e["id"] for e in model["elements"]}
    techs = model["attack_techniques"]
    seen = set()
    for t in model["threats"]:
        p = t.get("id", "?")
        if p in seen:
            errs.append(f"{p}: duplicate id")
        seen.add(p)
        if t["element"] not in elems:
            errs.append(f"{p}: unknown element {t['element']}")
        if t["stride"] not in model["stride"]:
            errs.append(f"{p}: bad STRIDE letter {t['stride']}")
        for k in ("likelihood", "impact"):
            if not (isinstance(t[k], int) and 1 <= t[k] <= 5):
                errs.append(f"{p}: {k} must be an integer 1..5")
        if t["status"] not in STATUSES:
            errs.append(f"{p}: status must be one of {sorted(STATUSES)}")
        if not t.get("controls") and t["status"] != "open":
            errs.append(f"{p}: needs controls (or status open)")
        if not t.get("residual"):
            errs.append(f"{p}: needs a residual-risk statement")
        for a in t["attack"]:
            if not TECH_RE.match(a):
                errs.append(f"{p}: malformed ATT&CK id {a}")
            elif a not in techs:
                errs.append(f"{p}: technique {a} missing from attack_techniques (add its name)")
        for d in t["detections"]:
            if isinstance(d, str):
                if not d.startswith("stock:"):
                    errs.append(f"{p}: string detections must look like 'stock:<id>', got {d}")
            elif d not in rules:
                errs.append(f"{p}: detection rule {d} not found in detections/payloop_rules.xml")
        if not t["detections"]:
            if band(model, score(t)) in ("Critical", "High") and not t.get("detection_note"):
                errs.append(f"{p}: {band(model, score(t))} risk with no detection and no detection_note explaining why")
            elif not t.get("detection_note"):
                warns.append(f"{p}: no detections and no detection_note")
        if "finding" in t and not re.fullmatch(r"F\d+", str(t["finding"])):
            errs.append(f"{p}: finding must look like F7")
    covered = {e["element"] for e in model["threats"]}
    for e in model["elements"]:
        if e["id"] not in covered:
            warns.append(f"element {e['id']} ({e['name']}) has no threats")
    referenced = {d for t in model["threats"] for d in t["detections"] if isinstance(d, int)}
    for rid, r in sorted(rules.items()):
        if r["level"] >= 5 and rid not in referenced:
            warns.append(f"detection rule {rid} (level {r['level']}) is not referenced by any threat")
        for m in r["mitre"]:
            if m not in techs:
                warns.append(f"rule {rid} tags {m} which no threat maps to")
    return errs, warns


# ------------------------------------------------------------------ renderers
def elem_name(model, eid):
    return next(e["name"] for e in model["elements"] if e["id"] == eid)


def fmt_det(t):
    return ", ".join(str(d) for d in t["detections"]) or "none"


def render_stride(model):
    out = ["# STRIDE analysis", "", "_Generated from `data/threats.yaml`. Do not edit by hand._", "",
           "STRIDE: " + ", ".join(f"**{k}** {v}" for k, v in model["stride"].items()), ""]
    grid = defaultdict(int)
    for t in model["threats"]:
        grid[(t["element"], t["stride"])] += 1
    out += ["## Coverage matrix (threat count per element and category)", "",
            "| Element | " + " | ".join(model["stride"]) + " |", "|---|" + "---|" * len(model["stride"])]
    for e in model["elements"]:
        out.append(f"| {e['id']} {e['name']} | " + " | ".join(str(grid[(e['id'], k)] or "·") for k in model["stride"]) + " |")
    out += ["", "A dot means no threat was identified for that category on that element. For externals and stores some categories "
            "do not apply under classic STRIDE-per-element rules; the matrix is a prompt to ask, not a quota.", ""]
    for e in model["elements"]:
        ts = [t for t in model["threats"] if t["element"] == e["id"]]
        if not ts:
            continue
        out += [f"## {e['id']}: {e['name']}", "", f"Type: {e['type']}  |  Trust boundary: {e['boundary']}", "",
                "| Threat | STRIDE | Scenario | Risk | Status | Detections |", "|---|---|---|---|---|---|"]
        for t in ts:
            out.append(f"| {t['id']} {t['title']} | {t['stride']} | {t['scenario']} | {band(model, score(t))} ({score(t)}) | {t['status']} | {fmt_det(t)} |")
        out.append("")
    return "\n".join(out)


def render_attack(model):
    by = defaultdict(list)
    for t in model["threats"]:
        for a in t["attack"]:
            by[a].append(t)
    out = ["# MITRE ATT&CK mapping", "", "_Generated from `data/threats.yaml`. Do not edit by hand._", "",
           f"Mapped against ATT&CK Enterprise v{model['meta']['attack_version']}. Import `attack-navigator-layer.json` "
           "into ATT&CK Navigator to see the heat map.", "",
           "| Technique | Name | Threats | Highest risk | Detection rules |", "|---|---|---|---|---|"]
    for tid in sorted(by):
        ts = by[tid]
        dets = sorted({d for t in ts for d in t["detections"]}, key=str)
        out.append(f"| {tid} | {model['attack_techniques'][tid]} | {', '.join(t['id'] for t in ts)} | "
                   f"{band(model, max(score(t) for t in ts))} | {', '.join(map(str, dets)) or 'none'} |")
    no_map = [t for t in model["threats"] if not t["attack"]]
    if no_map:
        out += ["", "Threats with no ATT&CK technique (design or accountability gaps rather than adversary behaviour): "
                + ", ".join(t["id"] for t in no_map) + "."]
    return "\n".join(out) + "\n"


def render_risk(model):
    ts = sorted(model["threats"], key=lambda t: (-score(t), t["id"]))
    out = ["# Risk register", "", "_Generated from `data/threats.yaml`. Do not edit by hand._", "",
           f"Score = likelihood x impact (1-5 each). Bands: Critical >= {model['risk_bands']['critical']}, "
           f"High >= {model['risk_bands']['high']}, Medium >= {model['risk_bands']['medium']}, otherwise Low.", "",
           "| Threat | Title | L | I | Score | Band | Status | Residual risk |", "|---|---|---|---|---|---|---|---|"]
    for t in ts:
        out.append(f"| {t['id']} | {t['title']} | {t['likelihood']} | {t['impact']} | {score(t)} | {band(model, score(t))} | {t['status']} | {t['residual']} |")
    out += ["", "## Heat map (inherent risk, threat numbers)", "", "| Impact \\ Likelihood | 1 | 2 | 3 | 4 | 5 |", "|---|---|---|---|---|---|"]
    for imp in range(5, 0, -1):
        cells = []
        for lik in range(1, 6):
            ids = [t["id"].split("-")[1] for t in model["threats"] if t["likelihood"] == lik and t["impact"] == imp]
            cells.append(", ".join(ids) or "·")
        out.append(f"| **{imp}** | " + " | ".join(cells) + " |")
    by_status = defaultdict(list)
    for t in model["threats"]:
        by_status[t["status"]].append(t["id"])
    out += ["", "## Status summary", ""] + [f"- **{s}** ({len(v)}): {', '.join(v)}" for s, v in sorted(by_status.items())]
    out += ["", "Scores are inherent (before the listed controls). Residual risk is described in words rather than re-scored, "
            "because re-scoring without evidence invites optimism."]
    return "\n".join(out) + "\n"


def render_trace(model, rules):
    out = ["# Threat to detection traceability", "", "_Generated from `data/threats.yaml` and `detections/payloop_rules.xml`. Do not edit by hand._", ""]
    det = [t for t in model["threats"] if t["detections"]]
    out += [f"**{len(det)} of {len(model['threats'])}** threats have at least one detection. "
            f"Every referenced custom rule id was verified to exist in the ruleset on each build.", "",
            "## Threat to rules", "", "| Threat | Risk | Rules (level) | If it fails |", "|---|---|---|---|"]
    for t in sorted(model["threats"], key=lambda t: (-score(t), t["id"])):
        if t["detections"]:
            rs = ", ".join(f"{d} (L{rules[d]['level']})" if isinstance(d, int) else str(d) for d in t["detections"])
            out.append(f"| {t['id']} {t['title']} | {band(model, score(t))} | {rs} | {t['residual']} |")
    out += ["", "## Threats without a detection, and why", "", "| Threat | Risk | Reason |", "|---|---|---|"]
    for t in sorted([t for t in model["threats"] if not t["detections"]], key=lambda t: (-score(t), t["id"])):
        out.append(f"| {t['id']} {t['title']} | {band(model, score(t))} | {t.get('detection_note', 'not stated')} |")
    ref = defaultdict(list)
    for t in model["threats"]:
        for d in t["detections"]:
            if isinstance(d, int):
                ref[d].append(t["id"])
    out += ["", "## Rule to threats", "", "| Rule | Level | What it detects | Threats |", "|---|---|---|---|"]
    for rid in sorted(rules):
        if rid in ref:
            out.append(f"| {rid} | {rules[rid]['level']} | {rules[rid]['desc'].split(':', 1)[-1].strip()} | {', '.join(ref[rid])} |")
    unref = [rid for rid in sorted(rules) if rid not in ref]
    out += ["", f"Rules not tied to a threat ({len(unref)}): " + (", ".join(map(str, unref)) or "none") +
            ". These are infrastructure rules (event parents or informational), kept below level 5.", ""]
    return "\n".join(out)


def render_layers(model):
    by = defaultdict(list)
    for t in model["threats"]:
        for a in t["attack"]:
            by[a].append(t)
    v = {"attack": model["meta"]["attack_version"], "navigator": "5.1.0", "layer": "4.5"}
    risk = {"name": "PayLoop threat model: inherent risk", "versions": v, "domain": "enterprise-attack",
            "description": "Score = max likelihood x impact of mapped threats. Generated by scripts/build.py.",
            "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": 25},
            "techniques": [{"techniqueID": k, "score": max(score(t) for t in ts),
                            "comment": "; ".join(f"{t['id']} {t['title']}" for t in ts)} for k, ts in sorted(by.items())]}
    cov = {"name": "PayLoop threat model: detection coverage", "versions": v, "domain": "enterprise-attack",
           "description": "2 = at least one detection rule maps to a threat using this technique, 1 = mapped threats but no detection. Generated by scripts/build.py.",
           "gradient": {"colors": ["#ff6666", "#8ec843"], "minValue": 1, "maxValue": 2},
           "techniques": [{"techniqueID": k, "score": 2 if any(t["detections"] for t in ts) else 1,
                           "comment": "rules: " + (", ".join(sorted({str(d) for t in ts for d in t["detections"]})) or "none")} for k, ts in sorted(by.items())]}
    return {"attack-navigator-layer.json": json.dumps(risk, indent=2) + "\n",
            "attack-navigator-detection-layer.json": json.dumps(cov, indent=2) + "\n"}


def outputs(model, rules):
    files = {"docs/03-stride-analysis.md": render_stride(model), "docs/04-attack-mapping.md": render_attack(model),
             "docs/05-risk-register.md": render_risk(model), "docs/06-detection-traceability.md": render_trace(model, rules)}
    files.update(render_layers(model))
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    model, rules = load()
    errs, warns = validate(model, rules)
    for w in warns:
        print("warning:", w)
    for e in errs:
        print("ERROR:", e)
    if errs:
        return 1
    files = outputs(model, rules)
    if a.check:
        stale = [p for p, c in files.items() if not (ROOT / p).exists() or (ROOT / p).read_text() != c]
        if stale:
            print("stale generated files (run python3 scripts/build.py):", ", ".join(stale))
            return 1
        print(f"ok: {len(model['threats'])} threats valid, generated files up to date")
        return 0
    for p, c in files.items():
        (ROOT / p).write_text(c)
    det = sum(1 for t in model["threats"] if t["detections"])
    print(f"ok: {len(model['threats'])} threats, {det} with detections, wrote {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
