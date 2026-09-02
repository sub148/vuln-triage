def cvss_ranked(findings):
    """Baseline: rank by CVSS alone, which is what most teams do."""
    return sorted(
        findings,
        key=lambda f: f["cvss"] if f["cvss"] is not None else 0,
        reverse=True,
    )


def risk_ranked(findings):
    """Our ranking: contextual risk score."""
    return sorted(findings, key=lambda f: f["risk_score"], reverse=True)


def finding_key(f):
    """Identify a finding so the same one can be matched across both lists."""
    return (f["cve"], f["package"], f["target"])


def compare(findings, top_n=50):
    """Measure how much the two rankings disagree in their top N."""
    by_cvss = cvss_ranked(findings)[:top_n]
    by_risk = risk_ranked(findings)[:top_n]

    cvss_set = {finding_key(f) for f in by_cvss}
    risk_set = {finding_key(f) for f in by_risk}

    promoted = risk_set - cvss_set
    demoted = cvss_set - risk_set

    return {
        "top_n": top_n,
        "churn": len(promoted),
        "churn_pct": round(100 * len(promoted) / top_n, 1),
        "promoted": [f for f in by_risk if finding_key(f) in promoted],
        "demoted": [f for f in by_cvss if finding_key(f) in demoted],
    }

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "src")
    from triage.parser import parse_file
    from triage.enrich import enrich
    from triage.score import score

    findings = []
    for path in ["data/raw/python39.json", "data/raw/node14.json"]:
        findings.extend(parse_file(path))

    enrich(findings)
    for f in findings:
        score(f)

    result = compare(findings, top_n=50)

    print(f"\nComparing top {result['top_n']} of each ranking")
    print(f"Rank churn: {result['churn']} findings ({result['churn_pct']}%)\n")

    print("PROMOTED by contextual scoring (CVSS-only ranking missed these):")
    for f in result["promoted"][:8]:
        print(f"  {f['cve']:<18} cvss={str(f['cvss'] or '-'):>4} "
              f"epss={f['epss']:.5f} kev={'yes' if f['in_kev'] else '-':<3} "
              f"risk={f['risk_score']:.1f}  {f['package']}")

    print("\nDEMOTED by contextual scoring (CVSS-only over-prioritized these):")
    for f in result["demoted"][:8]:
        fix = "yes" if f["fixed_version"] else "NO FIX"
        print(f"  {f['cve']:<18} cvss={str(f['cvss'] or '-'):>4} "
              f"epss={f['epss']:.5f} fix={fix:<7} "
              f"risk={f['risk_score']:.1f}  {f['package']}")