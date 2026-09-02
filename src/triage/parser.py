def get_cvss(vuln):
    """extract a single CVSS score, preferring NVD as a neutral baseline."""
    cvss = vuln.get("CVSS" , {})

    nvd = cvss.get("nvd", {})
    if "V3Score" in nvd:
        return nvd["V3Score"]
    if "V2Score" in nvd:
        return nvd["V2Score"]

    for name, block in cvss.items():
        if "V3Score" in block:
            return block["V3Score"]

    return None


def parse_file(path):
    """Read a Trivy JSON file and return a flat list of findings."""
    import json

    data = json.load(open(path))
    findings = []

    for section in data.get("Results", []):
        target = section.get("Target", "unknown")

        for vuln in section.get("Vulnerabilities", []):
            findings.append({
                "cve": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "severity": vuln.get("Severity"),
                "cvss": get_cvss(vuln),
                "title": vuln.get("Title"),
                "target": target,
            })

    return findings





if __name__ == "__main__":
    files = [
        "data/raw/python39.json",
        "data/raw/node14.json",
    ]

    all_findings = []
    for path in files:
        found = parse_file(path)
        print(f"{path}: {len(found)} findings")
        all_findings.extend(found)

    print(f"\nTotal: {len(all_findings)}")

    no_fix = [f for f in all_findings if f["fixed_version"] is None]
    print(f"No fix available: {len(no_fix)} ({100*len(no_fix)//len(all_findings)}%)")

    with_cve = [f for f in all_findings if f["cve"] and f["cve"].startswith("CVE-")]
    print(f"Have a real CVE ID: {len(with_cve)}")