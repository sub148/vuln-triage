KEV_LIKELIHOOD_FLOOR = 0.75
NO_FIX_PENALTY = 0.5
DEFAULT_CVSS = 5.0


def likelihood(finding):
    """Probability this gets exploited, 0-1."""
    epss = finding.get("epss")
    if epss is None:
        epss = 0.00045

    if finding.get("in_kev"):
        return max(epss, KEV_LIKELIHOOD_FLOOR)

    return epss


def impact(finding):
    """How bad if exploited, normalized to 0-1."""
    cvss = finding.get("cvss")
    if cvss is None:
        cvss = DEFAULT_CVSS
    return cvss / 10.0


def actionability(finding):
    """Can we fix it today? 0-1."""
    if finding.get("fixed_version"):
        return 1.0
    return NO_FIX_PENALTY


def score(finding):
    """Attach a 0-100 risk score plus the reasoning behind it."""
    l = likelihood(finding)
    i = impact(finding)
    a = actionability(finding)

    finding["risk_score"] = round(l * i * a * 100, 2)
    finding["rationale"] = {
        "likelihood": round(l, 5),
        "impact": round(i, 3),
        "actionability": a,
        "in_kev": finding.get("in_kev", False),
        "has_fix": bool(finding.get("fixed_version")),
    }
    return finding["risk_score"]

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "src")
    from triage.parser import parse_file
    from triage.enrich import enrich

    findings = []
    for path in ["data/raw/python39.json", "data/raw/node14.json"]:
        findings.extend(parse_file(path))

    enrich(findings)

    for f in findings:
        score(f)

    findings.sort(key=lambda f: f["risk_score"], reverse=True)

    print(f"\nScored {len(findings)} findings\n")
    print(f"{'#':>3} {'score':>6} {'cvss':>5} {'epss':>8} {'kev':>4} {'fix':>4}  package")
    print("-" * 70)

    for i, f in enumerate(findings[:20], 1):
        print(f"{i:>3} {f['risk_score']:>6.2f} "
              f"{str(f['cvss'] or '-'):>5} "
              f"{f['epss']:>8.5f} "
              f"{'yes' if f['in_kev'] else '-':>4} "
              f"{'yes' if f['fixed_version'] else 'NO':>4}  "
              f"{f['package']}")