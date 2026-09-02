import json
import os
import time

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR = "data/enrichment"
CACHE_MAX_AGE = 24 * 60 * 60


def _is_fresh(path):
    """True if the file exists and is less than a day old."""
    if not os.path.exists(path):
        return False
    age = time.time() - os.path.getmtime(path)
    return age < CACHE_MAX_AGE


def load_kev():
    """Return the set of CVE IDs that CISA has confirmed as exploited."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache = os.path.join(CACHE_DIR, "kev.json")

    if _is_fresh(cache):
        print("KEV: using cached copy")
        return set(json.load(open(cache)))

    print("KEV: downloading from CISA...")
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    data = response.json()

    cve_ids = [v["cveID"] for v in data["vulnerabilities"]]
    json.dump(cve_ids, open(cache, "w"))

    return set(cve_ids)


import csv
import gzip
import io

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_MEDIAN = 0.00045


def load_epss():
    """Return {cve_id: probability of exploitation in the next 30 days}."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache = os.path.join(CACHE_DIR, "epss.json")

    if _is_fresh(cache):
        print("EPSS: using cached copy")
        return json.load(open(cache))

    print("EPSS: downloading (this one is big)...")
    response = requests.get(EPSS_URL, timeout=60)
    response.raise_for_status()

    text = gzip.decompress(response.content).decode("utf-8")
    lines = [line for line in text.splitlines() if not line.startswith("#")]

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    scores = {row["cve"]: float(row["epss"]) for row in reader}

    json.dump(scores, open(cache, "w"))
    return scores



def enrich(findings):
    """Attach EPSS score and KEV membership to each finding."""
    kev = load_kev()
    epss = load_epss()

    stats = {"in_kev": 0, "epss_found": 0, "no_cve": 0}

    for f in findings:
        cve = f.get("cve")

        if not cve or not cve.startswith("CVE-"):
            f["epss"] = None
            f["in_kev"] = False
            stats["no_cve"] += 1
            continue

        f["in_kev"] = cve in kev
        if f["in_kev"]:
            stats["in_kev"] += 1

        if cve in epss:
            f["epss"] = epss[cve]
            stats["epss_found"] += 1
        else:
            f["epss"] = EPSS_MEDIAN

    return stats


if __name__ == "__main__":
    import sys
    sys.path.insert(0, "src")
    from triage.parser import parse_file

    findings = []
    for path in ["data/raw/python39.json", "data/raw/node14.json"]:
        findings.extend(parse_file(path))

    print(f"\nLoaded {len(findings)} findings")

    stats = enrich(findings)
    print(f"  in CISA KEV:     {stats['in_kev']}")
    print(f"  EPSS score found: {stats['epss_found']}")
    print(f"  no usable CVE:    {stats['no_cve']}")

    kev_findings = [f for f in findings if f["in_kev"]]
    kev_findings.sort(key=lambda f: f["epss"], reverse=True)

    print(f"\nTop KEV findings by EPSS:")
    for f in kev_findings[:10]:
        fix = f["fixed_version"] or "NO FIX"
        print(f"  {f['cve']:<18} epss={f['epss']:.5f} cvss={f['cvss']} {f['package']} -> {fix}")