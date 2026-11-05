# Security Log Investigation Report

**Case:** SIM-2026-11-03-001  
**Status:** Training exercise — investigation completed; no live incident created  
**Environment:** Simulated Microsoft Entra sign-in events (CSV)  
**Period reviewed:** 2026-11-03 00:00–23:59 UTC  
**Analyst level:** Tier 1 / initial triage  
**Data source:** [sample_signin_logs.csv](../data/sample_signin_logs.csv)  
**Queries:** [investigation_queries.kql](../queries/investigation_queries.kql)

> **Scope disclaimer:** All users, applications, and sign-in events are synthetic. The IP addresses are reserved documentation ranges, not real threat indicators. Counts and observations below are derived from the CSV, **not actual Microsoft Sentinel executions**. This report makes no claim of confirmed compromise.

## 1. Executive summary

Review of 15 simulated sign-in events identified a potentially suspicious authentication pattern from the same IP address, `203.0.113.45`, against two accounts. Across both accounts, that IP generated **nine failed sign-ins**. Three failed sign-ins against `admin@contoso.example` were followed by a **successful sign-in at 08:07:33 UTC**, and a further failed sign-in occurred at 13:12:07 UTC.

**Assessment:** Possible password spraying or credential guessing with a successful administrative sign-in. This is a **hypothesis requiring verification**, not proof of an attack.

**Recommended disposition:** **Escalate for Tier 2 review** if this pattern appears in live telemetry and the administrative sign-in cannot be quickly verified as legitimate. Follow the organization's playbook for potential privileged-account compromise.

## 2. Observations and findings

| Finding | Evidence in synthetic data | Initial priority | Analyst interpretation |
| --- | --- | --- | --- |
| Multiple accounts with failures from one IP | `203.0.113.45`: John 5 failures; Admin 4 failures | Medium | Could reflect password spraying or legitimate shared-network activity |
| Admin sign-in succeeds after failures | Admin: failures at 08:03:44, 08:04:15, 08:05:01 UTC; success 08:07:33 UTC | High if unexpected | Possible successful authentication after credential guessing |
| Another admin failure later | Admin failure at 13:12:07 UTC from the same IP | Medium | Confirms that the unusual sign-in activity was not limited to one short burst |
| Single failure followed by success for Sarah | Failure 09:05:00; success 09:05:22 UTC from `198.51.100.22` | Low without additional context | May be ordinary password-entry error |

Priority labels represent **training triage judgments**, not product-generated severities.

### Key evidence

- `evt-001`–`evt-005`: John, five failed sign-ins from `203.0.113.45` between 08:01:12 and 08:03:11 UTC.
- `evt-006`–`evt-008`: Admin, three failures from that IP between 08:03:44 and 08:05:01 UTC.
- `evt-009`: Admin, successful Azure Portal sign-in from the same IP at 08:07:33 UTC.
- `evt-015`: Admin, another failed Azure Portal sign-in from that IP at 13:12:07 UTC.
- `evt-010`–`evt-011`: Sarah, one failed and then one successful sign-in from another IP.

`ResultType == "0"` is treated as success in this dataset; `50126` is used for failed username/password validation.

## 3. Tier 1 investigation workflow

1. **Detect:** Run the failed-sign-in summary (Query 1) to identify users and IPs with repeated failures.
2. **Correlate:** Run the multiple-account IP summary (Query 2) to identify potential password-spraying patterns.
3. **Prioritize:** Run the success-after-failure query (Query 3) to surface accounts needing closer attention. Its counts may include failures *after* the success, so do not treat the count as a precise pre-success number.
4. **Validate chronology:** Run the account/IP timeline query (Query 4) to inspect the sequence of sign-in outcomes.
5. **Enrich:** In a real tenant, review Conditional Access, MFA outcomes, device context, user confirmation, IP reputation and subsequent account actions.
6. **Document and escalate:** Record timestamps, affected identities, evidence, unknowns and recommended containment for authorized responders.

## 4. Escalation recommendation

**Escalate urgently according to the organization's playbook if** the successful Admin sign-in is unexpected, the source cannot be explained, or related privileged actions are observed. A Tier 1 analyst should avoid declaring compromise based solely on this dataset.

### Suggested Tier 2 handoff

**Subject:** Review requested — admin success after repeated sign-in failures

**Summary:** On 2026-11-03 (UTC), source `203.0.113.45` produced nine failed logins across `john@contoso.example` and `admin@contoso.example`. The Admin account had failures at 08:03:44, 08:04:15 and 08:05:01, followed by a successful Azure Portal sign-in at 08:07:33. Another failed Admin attempt occurred at 13:12:07.

**Why escalate:** Potential credential-guessing or password-spraying pattern involving an administrative account, with a subsequent success.

**Requested Tier 2 actions:** Confirm sign-in legitimacy; inspect authentication details and MFA; review related Azure and Entra audit activity; decide whether session revocation, credential reset, account restriction or additional containment is warranted according to approved procedures.

## 5. Limits and unanswered questions

- No real threat-intelligence, IP-geolocation or user-verification data was collected.
- No MFA, device, Conditional Access or token/session details appear in the CSV.
- A successful authentication event does **not** confirm malicious access.
- Counts reflect 15 illustrative events only, not a complete identity environment.
- IP addresses `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` are reserved for documentation.
- The KQL examples target the Microsoft Sentinel `SigninLogs` table; the CSV must be ingested into a compatible environment (or adapted to a custom table) before those queries can operate on it.

## 6. Skills demonstrated

Basic authentication log triage, KQL query design, multi-user IP correlation, event timeline analysis, false-positive awareness, incident documentation, and Tier 1-to-Tier 2 handoff.
