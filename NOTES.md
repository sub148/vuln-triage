# Build Notes

## Session 1 — Sept 1

### What I built
- Parser for Trivy JSON output (src/triage/parser.py)
- Enrichment against CISA KEV + EPSS (src/triage/enrich.py)

### Numbers from this run
- Scanned: python:3.9-slim (367 findings), node:14 (1,451 findings)
- Total: 1,818 findings
- No fix available: 463 (25%)
- Findings with a real CVE ID: 1,804 (14 were Debian TEMP- placeholders)
- Confirmed exploited (CISA KEV): 9
- EPSS covers 366,848 CVEs; KEV lists only 1,687

### The example that makes the argument
CVE-2023-44487 (HTTP/2 Rapid Reset)
- CVSS 7.5 — sorts BELOW dozens of 9.8s in my data
- EPSS 0.99999 — highest exploitation probability in the whole set
- Confirmed in CISA KEV, and a fix exists
Sorting by CVSS buries the one thing that's actively being attacked.

### Decisions I made and why

**CVSS source: prefer NVD.**
Trivy reports scores from 4 sources (nvd, redhat, bitnami, julia) and they
disagree. Picked NVD because it's the neutral government baseline rather than
a vendor's view of their own product. Fallback order: NVD V3 -> NVD V2 ->
any other source's V3 -> None.

**Missing CVSS returns None, not 0.**
Zero means "harmless," which would sort genuinely unrated flaws to the bottom.
None means "unknown," which is the truth.

**Unknown EPSS gets the median (0.00045), not 0.**
Same reasoning. EPSS having no opinion isn't the same as "will never be
exploited." Median treats it as ordinary rather than safe.

**Cache the feeds for 24h.**
KEV and EPSS change slowly. Hitting free public APIs on every run is rude
and slow.

**Return KEV as a set, not a list.**
Checking membership across ~1,800 findings; set lookup is constant time,
list lookup scans everything.

### Things I hit
- Trivy omits fields entirely rather than sending empty ones — no
  FixedVersion key means no patch exists, and a section with no
  vulnerabilities has no Vulnerabilities key at all. Used .get() with
  defaults everywhere.
- node:14 (full image) had 4x the findings of python:3.9-slim. Smaller
  base image = smaller attack surface.
- CVE-2023-4863 appears 4x — four packages bundle the same vulnerable
  libwebp code. One fix covers all four. Dedup would collapse these.

### Next session
- Scoring engine: likelihood x impact x actionability
- Compare against a CVSS-only baseline and measure rank churn
- Then it's resume-ready