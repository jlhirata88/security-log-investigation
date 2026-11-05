# Security Log Investigation — Microsoft Entra / KQL

**Portfolio project | Tier 1 cloud security / SOC investigation**

An analyst-style walkthrough of investigating suspicious Microsoft Entra sign-in events: identify repeated failures, correlate the source IP across accounts, check whether a sign-in succeeded after failures, and document an evidence-based Tier 2 handoff.

> **Training scope:** All 15 sign-in events are **simulated**. This project uses a CSV file, not live Microsoft Entra or Microsoft Sentinel telemetry. KQL examples were **written for** the Microsoft Sentinel / Log Analytics `SigninLogs` table but **were not executed** against a live workspace. The expected findings were derived by reviewing the CSV, not measured Sentinel query outputs.

## Investigation at a glance

| Item | Training result |
| --- | --- |
| Dataset | 15 synthetic sign-in events on 2026-11-03 (UTC) |
| Suspected source | `203.0.113.45` (reserved documentation IP) |
| Failed sign-ins from that source | 9 |
| Accounts involved | `john@contoso.example`, `admin@contoso.example` |
| Key event | Admin: 3 failures, then success at 08:07:33 UTC, then another failure at 13:12:07 UTC |
| Analyst assessment | Possible credential guessing / password spraying; **not confirmed** |
| Recommended follow-up | Verify admin sign-in and context; escalate per playbook if unauthorized or unexplained |

## Files

| Path | Description |
| --- | --- |
| [`data/sample_signin_logs.csv`](data/sample_signin_logs.csv) | The synthetic Microsoft Entra-style authentication events |
| [`queries/investigation_queries.kql`](queries/investigation_queries.kql) | Four documented KQL investigation examples with interpretation |
| [`docs/INVESTIGATION_REPORT.md`](docs/INVESTIGATION_REPORT.md) | Findings, supporting event IDs, limitations, and example Tier 2 handoff |

## Investigation workflow

1. **Review failed sign-ins:** summarize failed attempts by account and source IP.
2. **Correlate source addresses:** find IPs with failed sign-ins to multiple users.
3. **Check failures followed by success:** flag accounts warranting a detailed review.
4. **Examine the timeline:** confirm the sequence of individual events before drawing conclusions.
5. **Document and escalate:** record evidence, caveats, unknowns, and recommended next checks.

### Example KQL — failed sign-ins by user and IP

```kql
SigninLogs
| where TimeGenerated >= datetime(2026-11-03T00:00:00Z)
    and TimeGenerated < datetime(2026-11-04T00:00:00Z)
| where ResultType != "0"
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| sort by FailedAttempts desc
```

**Expected from the synthetic CSV:** John: 5 failures from `203.0.113.45`; Admin: 4 from the same IP; Sarah: 1 from `198.51.100.22`.

[Explore all four KQL queries](queries/investigation_queries.kql).

## How to study or reproduce the exercise

**Offline (no Azure account):**
1. Open [the CSV](data/sample_signin_logs.csv).
2. Filter the `ResultType` column: `0` means success, and nonzero values mean failure for these examples.
3. Group the failed sign-ins by `UserPrincipalName` and `IPAddress`; compare your counts with the investigation report.
4. Read each KQL example and explain what it would query in a connected `SigninLogs` environment.

**In a real Microsoft Sentinel workspace:** With the required permissions and a populated `SigninLogs` table, open Logs and run **individual KQL queries**, modifying the date/time window and account/IP filters to match the available records. **The CSV is not ingested automatically** and these exact sample events will not appear in Sentinel unless loaded into a compatible table and the queries adapted accordingly.

## Analyst decisions and limitations

- Multiple failed sign-ins can result from user error, legitimate shared networks, or malicious attempts.
- A successful login after failures is **not proof** of account takeover.
- An analyst would seek MFA results, Conditional Access decisions, user confirmation, device data, IP reputation, and related privileged actions before deciding containment.
- This project demonstrates initial triage and a written handoff. It does **not** claim live detection, threat-intelligence enrichment, automated alerting, or a confirmed incident.
- Synthetic IP addresses are from reserved documentation networks.

## Skills demonstrated

KQL concepts (`where`, `summarize`, `count`, `dcount`, `join`, `project`), authentication log triage, timeline analysis, evidence documentation, false-positive awareness, and escalation communication.

## Interview-ready summary

> “I built a simulated Microsoft Entra sign-in investigation to practice a Tier 1 security analyst workflow. I created a set of KQL queries for Microsoft Sentinel to review failed logins, identify a single IP targeting multiple accounts, and spot successes following failures. I then analyzed 15 sample events and documented nine failed attempts from one IP across two accounts, including an admin login that succeeded after several failures. I wrote an investigation report with supporting timestamps and a proposed Tier 2 handoff. This was an offline exercise, not a live Sentinel deployment.”

---
**Note:** `.example` email addresses and the IP addresses in the dataset are placeholders, not real employees or public threat indicators.
