# vuln-triage

Reranks vulnerability findings in containers by **exploitation
probability** and measures how much it changes the queue.

## The problem

Scanning two container images found **1,818** vulnerabilities. Sorted by CVSS,
which is the default for most organizations, the top of the list looks like
this:

CVE-2005-2541 CVSS 10.0 EPSS 0.04 no patch available


This flaw got a perfect 10.0 score, so it comes first. It is also from 2005,
is expected to be exploited in the next 30 days with a probability of 4%, and
there is **no patch available**, i.e. no action an engineer can take right now.

This is the core issue. CVSS rates a flaw in isolation, assigning
a score once and without updates based on how people use and attack real-life
systems.

## Approach

This project combines three factors, normalized to 0–1 range, into a product:

| Factor | Question | Source |
|---|---|---|
| **Likelihood** | Will this be exploited? | EPSS probability, CISA KEV |
| **Impact** | If exploited, how bad? | CVSS base score |
| **Actionability** | Can we fix it today? | Is a patched version available? |

The idea behind multiplication over addition is that a near-zero factor should
bring the final score down. For instance, CVSS 9.8 that is never exploited
should be lower.

Every score gets annotated with a `rationale` detailing the contribution of
each factor. Scores that cannot be explained to the analyst fixing something
are irrelevant.

## Results

| Metric | Value |
|---|---|
| Findings scanned (2 images) | 1,818 |
| No fix available | 463 (25%) |
| Exploited (CISA KEV) | 9 |
| **Top 50 rank churn compared to CVSS baseline** | **70%** |

**70% rank churn** means out of 50 findings in a CVSS-sorted queue shown
first to the analyst, 35 are the wrong ones: either unactionable findings,
or actively-exploited vulnerabilities that never make the list.

### Vulnerabilities missed by CVSS ranking

CVE-2023-44487 CVSS 7.5 EPSS 0.99999 in KEV fix available


HTTP/2 Rapid Reset used in the largest DDoS attacks on record. CVSS gives it
a 7.5 score which is way worse than several 9.8 vulnerabilities never
exploited in this dataset.

CVE-2023-50387 CVSS 7.5 EPSS 0.99995 not in KEV


With a 99.995% exploitation probability and no CISA listing. Filtering on KEV
alone would drop this vulnerability; EPSS works on 366,848 CVEs while KEV has
only 1,687.

### Vulnerabilities overprioritized by CVSS ranking

CVE-2005-2541 CVSS 10.0 EPSS 0.04 no fix -> risk score 2.0
CVE-2019-1010022 CVSS 9.8 EPSS 0.032 no fix -> risk score 1.6


## Running

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install requests

# Scan some images
trivy image --format json -o data/raw/python39.json python:3.9-slim
trivy image --format json -o data/raw/node14.json node:14

# Enrich findings with EPSS and KEV
python3 src/triage/enrich.py

# Score and rank
python3 src/triage/score.py

# Compare to CVSS baseline
python3 src/triage/analyze.py
```

EPSS and CISA KEV are fetched live and cached for 24 hours.

## Structure

src/triage/
parser.py parses Trivy JSON into normalized findings
enrich.py adds EPSS probability and KEV membership
score.py three-factor scoring logic
analyze.py compares to CVSS baseline and calculates rank churn


## Design decisions

**CVSS source: prefer NVD.** There are four sources of CVSS scores in Trivy:
(nvd, redhat, bitnami, julia) that might differ. NVD is a government
baseline without a commercial stake unlike vendor score for its own products.
Fallback: NVD V3 → NVD V2 → any other source's V3 → None.

**Missing score = `None`, not `0`.** Score of `0` means "harmless" and will
sort truly unrated flaws to the bottom. Missing score (`None`) is unknown.

**Unknown EPSS = median (0.00045).** EPSS having no opinion is not the same as
"will never be exploited". Median value treats it as an ordinary probability
rather than a safe one.

**KEV makes likelihood floor 0.75.** CISA confirms exploitation, so even
if the probability prediction is off, it should be higher anyway.
`max()` keeps higher EPSS values.

**No fix available = multiply by 0.5.** This is important to track and
possibly fix with a compensating control, but shouldn't outrank actionable
findings.

## Limitations

- **No asset context yet.** Impact uses CVSS alone now. The same vulnerability
  on a sandboxed host and an internet-facing database scores identically, but
  that's incorrect. Environment and exposure weighing is the highest-value
  next step.
- **Scores are subjective.** KEV likelihood floor of 0.75 and the no-fix
  penalty of 0.5 result in a reasonable ranking, but "reasonable" is
  not "validated".
- **No deduplication.** CVE-2023-4863 appears four times because four
  packages have the same vulnerable code libwebp. One upgrade is sufficient.
- **EPSS is a prediction.** Better than CVSS, but still just an algorithm
  output.
- **Only container images for now.** No cloud config scanning.

## Next steps

- Environment/exposure weighing
- Deduplication based on shared vulnerable components
- AWS config scanning with Prowler
- Mapping to NIST CSF and MITRE ATT&CK frameworks