# Operation Overreach — Flag Answers and Queries

**Case GF-INC-2026-0806 · Greenfield Logistics · 50 flags**

> **Two conventions used throughout.**
>
> **Time.** The Sentinel portal and CSV exports render `TimeGenerated` in the browser's local timezone (CDT, UTC−5). Every answer here is UTC. Where a timestamp is the answer, the query uses `format_datetime(...,'HH:mm:ss.fff')`, which always emits UTC and sidesteps the display conversion entirely.
>
> **Scope.** Both workspaces are shared and contaminated — `lognpacific.com` hashed accounts, `deadreckoning.local`, `cgm-*` hosts and the `GF FP Study` alert family belong to other estates or are deliberate false-positive material. Every query binds to the incident window and scopes to the identities under investigation.
>
> Queries marked **[run]** were executed against the workspaces during this investigation. Queries marked **[reconstructed]** produce the recorded answer but were not the exact form used at the time.

---

## Key identifiers

| Thing | Value |
|---|---|
| Cloud identity | `m.smith@lognpacific.org` (note **`.org`**, not `.com` — the `.com` accounts are contamination) |
| Cloud object ID | `fa5020a1-0d42-4839-bbfe-22db0861ced5` |
| On-prem identity | `GREENFIELD\m.smith`, SID `S-1-5-21-2130493337-2304943033-647427612-1111` |
| Escalation target | `GREENFIELD\t.harris`, RID `1107` |
| Agent service account | `GREENFIELD\svc_helpbot` |
| Attacker cloud egress | `159.26.115.80` (SG, `pv-sl-hosted-singapore-network`) |
| Attacker on-prem source | `10.1.0.120`, workstation `KALI` |
| Incident | `INC-161166` |

---

# Stage 01 — Triage

## T1 — The Entry Alert · 125

**Q.** Ten alerts, one incident, most noise about where the sign-in came from. One is from the identity product and names *how* the session is held. Which alert?

**A.** `Possible use of a stolen session cookie`

Sort the ten into symptom and cause. Anonymous IP ×3, Unfamiliar sign-in properties, Atypical travel and Potential user account compromise all describe *where from* — each is equally consistent with a VPN or a holiday. The identity product's High names the **mechanism**: the session is held, not authenticated. That one alert sets the containment order for the whole case (see IR1).

```kql
// [run] All alerts correlated into INC-161166, sorted by severity then time
SecurityAlert
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| extend IncidentId = tostring(parse_json(ExtendedProperties).IncidentId)
| where IncidentId == "161166"
| project TimeGenerated, AlertName, AlertSeverity, ProductName, Entities
| sort by AlertSeverity asc, TimeGenerated asc
```

---

## T2 — The Second High · 125

**Q.** Later the same evening, same product, another High at 20:08:56 — about what the account is *doing*, not how it signed in. Which phase?

**A.** `Discovery`

Not sign-in risk. The product observed the account enumerating the environment.

```kql
// [run] Highs on this identity after the stolen-cookie alert
SecurityAlert
| where TimeGenerated between (datetime(2026-08-05 19:00) .. datetime(2026-08-06))
| where AlertSeverity == "High"
| project TimeGenerated, AlertName, AlertSeverity, Description, Tactics
| sort by TimeGenerated asc
```

---

## T3 — The False Positive · 150

**Q.** Two Highs fired on-prem. One lines up with the attack, one fires as the DC is coming up. Which is the false positive?

**A.** `GF Pipe - Post-Exploitation Framework Named Pipe`

Its `StartTime` **predates** the reset at 11:53:55 and coincides with DC startup. Nothing ties it to a beat of the attack. Closing it early is what makes the other on-prem High — replication rights by a non-machine account — legible. It also means this alert cannot be used to corroborate the BloodHound inference in O1.

```kql
// [run] On-prem Highs, StartTime compared against the 11:53:55 reset
SecurityAlert
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-08))
| where AlertSeverity == "High"
| where AlertName !has "FP Study" and AlertName !has "lognpacific"
| extend Reset = datetime(2026-08-06 11:53:55)
| extend Position = iff(StartTime < Reset, "BEFORE reset", "AFTER reset")
| project StartTime, EndTime, AlertName, Position, Description
| sort by StartTime asc
```

---

## T4 — The Unactioned Window · 114

**Q.** How long between the cloud incident going High and the first on-prem action?

**A.** `15h37m`

Measured to the **VPN authentication in `LinuxAuth_CL`**, not to the first account-management event. Longer than a working day, and it contains every subsequent stage of the intrusion.

```kql
// [reconstructed] Escalation time vs first successful VPN authentication
let Escalation =
    SecurityIncident
    | where IncidentNumber == 161166
    | summarize min(CreatedTime);
let FirstVPN =
    LinuxAuth_CL
    | where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
    | where Result =~ "success" or EventOriginalMessage has "session opened"
    | summarize min(TimeGenerated);
print Gap = toscalar(FirstVPN) - toscalar(Escalation)
```

---

# Stage 02 — Cloud phase

## C1 — First Contact · 150

**Q.** The identity's own first move, to the millisecond.

**A.** `18:44:47.748`

`SigninLogs` is not the earliest witness — `IdentityLogonEvents` is. The first hostile event is a `LogonFailed` against Microsoft Azure with FailureReason *Strong Authentication is required* from `159.26.115.80`. The GB events earlier that day (`80.2.2.12`, ISP *baguley*) are the legitimate user and are baseline, not intrusion.

```kql
// [run] Earliest witness. format_datetime emits UTC regardless of portal display.
IdentityLogonEvents
| where Timestamp between (datetime(2026-08-05) .. datetime(2026-08-07))
| where AccountObjectId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
   or AccountUpn has "m.smith"
| sort by Timestamp asc
| extend T = format_datetime(Timestamp, 'HH:mm:ss.fff')
| project T, ActionType, Application, LogonType, FailureReason, IPAddress, Location, ISP
```

> **Two traps.** Submitting with a trailing `Z` fails — the format is `HH:MM:SS.mmm` only. And the UPN is `.org`; filtering on `.com` returns the contaminating tenant and no results for this identity.

---

## C2 — The Other Identity · 134

**Q.** Who else is on the attacker's address, and what does that do to scoping?

**A.** `mohammed_admin@lognpacific.com` — **scope by identity (UserPrincipalName), not by IP address**

Scoping on the address would drag an uninvolved administrator into the incident and could get them contained. This decision also drives IR2.

```kql
// [run] Every identity seen on the attacker address in the window
SigninLogs
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| where IPAddress == "159.26.115.80"
| summarize Signins = count(), First = min(TimeGenerated), Last = max(TimeGenerated)
        by UserPrincipalName, AppDisplayName
| sort by First asc
```

---

## C3 — The Pivot Record · 150

**Q.** The session works the mailbox, then acts on a file, with no search between. Which record carries it across?

**A.** `Invoice_Reconciliation_Q3.xlsx`

`UrlClickEvents` records the pivot from mail to file. No search operation sits between the click and the file action, so the attacker did not hunt for it — something they read pointed them at it.

```kql
// [run] Mail-to-file pivot
UrlClickEvents
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| where AccountUpn has "m.smith"
| project TimeGenerated, Url, ActionType, NetworkMessageId, IPAddress
| sort by TimeGenerated asc
```
```kql
// [run] File activity immediately following the click
CloudAppEvents
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| where AccountDisplayName has "m.smith" or RawEventData has "m.smith"
| project TimeGenerated, ActionType, ObjectName, Application, IPAddress
| sort by TimeGenerated asc
```

---

## C4 — The Restored Vault · 150

**Q.** In the file burst nearly everything is a take. One action goes the other way. Which vault, which action?

**A.** `Personal.kdbx`, action = `FileRestored`

A restore is a retrieval. The likeliest reading is that the vault had been deleted and the attacker wanted it back — they valued the contents enough to recover a file the owner had discarded.

```kql
// [run] Direction of travel across the file burst
CloudAppEvents
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| where RawEventData has "m.smith"
| summarize Count = count(), Files = make_set(ObjectName, 20) by ActionType
| sort by Count desc
```

---

## C5 — The Bridge File · 134

**Q.** Most of what they took are password stores. One is not, and it makes on-prem possible. Which file?

**A.** `VPN-Access-Credentials.txt`

Every other item is a credential *store* requiring further work to open. This one is directly actionable, and the VPN authentication in B1 is its consequence.

```kql
// [run] Inventory of the collection burst, non-vault extensions
CloudAppEvents
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| where RawEventData has "m.smith"
| where isnotempty(ObjectName)
| extend Ext = tostring(split(ObjectName, ".")[-1])
| summarize Files = make_set(ObjectName, 30) by Ext
```

---

## C6 — The Hidden Forward · 134

**Q.** Mail is leaving a mailbox the user never set a forward on. What operation set it?

**A.** `Set-Mailbox`

A mailbox **property**, not an inbox rule — which is why it never appears in the user's rules list, and why the obvious hunt in IR7 returns empty.

```kql
// [run] Mailbox-level configuration changes
OfficeActivity
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| where UserId has "m.smith"
| where Operation in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule",
                      "Set-TransportRule", "Add-MailboxPermission")
| project TimeGenerated, Operation, UserId, Parameters, ClientIP
| sort by TimeGenerated asc
```

---

## C7 — The Deleted Bounces · 125

**Q.** The forward bounced and the notifications are gone. What removed them?

**A.** `SoftDelete`

Anti-forensic housekeeping, and a tell about tempo — the attacker was watching the mailbox closely enough to notice bounces and clear them, so the session was interactive at that point.

```kql
// [run] Deletion operations against the mailbox, with subjects
OfficeActivity
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| where UserId has "m.smith"
| where Operation has_any ("SoftDelete", "HardDelete", "MoveToDeletedItems")
| project TimeGenerated, Operation, UserId, Folder, Item, ClientIP
| sort by TimeGenerated asc
```

---

## C8 — The Auto-Dismissal · 150

**Q.** Two risk detections were cleared while the session was live. What cleared them, and what reason was recorded?

**A.** `aiConfirmedSigninSafe`

Automation, not an analyst. The platform's own risk assessment concluded the sign-in was safe and suppressed its own detections mid-intrusion — the cloud-side twin of the agent failure in O4.

```kql
// [run] Risk detections and their dismissal state
AADUserRiskEvents
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| where UserPrincipalName has "m.smith"
| project TimeGenerated, RiskEventType, RiskLevel, RiskState, RiskDetail,
          DetectionTimingType, Activity, IpAddress
| sort by TimeGenerated asc
```

---

## C9 — The Automated Burst · 144

**Q.** A one-minute burst of directory calls. Give a measure from the call pattern itself that a person could not produce.

**A.** `21 repeated calls`

Client app is an attacker-controlled string and swappable. Call rate is a property of the automation. 21 calls in one minute is not human-producible, so a detection built on rate survives the attacker changing tooling and one built on client name does not.

```kql
// [run] Calls per minute, and repetition within the peak minute
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| where UserId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
| summarize Calls = count(), URIs = dcount(RequestUri), Apps = make_set(AppId, 5)
        by bin(TimeGenerated, 1m)
| sort by Calls desc
```

---

## C10 — The Refused Reads · 150

**Q.** One class of read came back refused every time. What code, and what did it cost them?

**A.** `403` and **privilege escalation**

The enumeration succeeded broadly but was blocked on exactly the reads that would have supported escalation in the cloud. The tenant held — which is why the escalation happened on-prem instead.

```kql
// [run] Response codes across the burst, and what the 403s were reaching for
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| where UserId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
| summarize Calls = count(), Sample = make_set(RequestUri, 10) by ResponseStatusCode
| sort by Calls desc
```

---

## C11 — The Single Record · 162

**Q.** Exactly one directory-audit record exists for the identity. What is it, and what does that prove?

**A.** `Settings_GetSettingsAsync` — proves the attacker **only read settings and did not establish persistence**

Actor intelligence says they try to secure cloud re-entry. One read and no write of any kind proves they did not manage it here: no MFA method registered, no consent granted, no credential added. The negative is only meaningful because the sweep was complete.

```kql
// [run] Complete directory-audit sweep for the identity — no operation filter
AuditLogs
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-08))
| where tostring(InitiatedBy) has "m.smith"
   or tostring(TargetResources) has "m.smith"
| project TimeGenerated, OperationName, Category, Result, InitiatedBy, TargetResources
| sort by TimeGenerated asc
```

---

## C12 — The Walled-Off Collector · 160

**Q.** The same client keeps coming back for forty minutes against something with no calls behind it. Client, refusal code, resource refused?

**A.** `AzureHound`, `50076`, `Azure Resource Manager`

The sign-in log's client name is a first-party name the tool rides on; the Graph activity log's `UserAgent` carries the real identity. The easy read — they mapped the tenant and moved on — misses that a second target was being pursued the whole time and that only an MFA requirement stopped them taking the Azure control plane. A resource with no calls behind it is not absence of interest; here it is sustained, blocked interest.

```kql
// [run] Real client identity from the Graph UserAgent
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| where UserId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
| summarize Calls = count() by UserAgent, AppId
| sort by Calls desc
```
```kql
// [run] The forty-minute retry loop and what refused it
SigninLogs
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-06))
| where UserPrincipalName has "m.smith"
| summarize Attempts = count(), First = min(TimeGenerated), Last = max(TimeGenerated)
        by ResourceDisplayName, ResultType, tostring(ResultDescription), AppDisplayName
| extend Span = Last - First
| sort by Attempts desc
```

---

# Bridge phase

## B1 — The Stolen Seed · 153

**Q.** The identity walks onto the estate VPN first try, both factors satisfied, no failures. What second component did the service record, and how did they already hold it?

**A.** `pam_google_authenticator` and **the Google Authenticator seed**

A TOTP code lives thirty seconds, so a first-try success with zero failures rules out relay or interception and leaves only possession of the **seed**. A seed is a file, and the credential files had already been taken. This is why re-enrolling TOTP is not the answer in IR8.

```kql
// [run] VPN PAM grantors and TOTP outcomes — note the absence of failures
LinuxAuth_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| project TimeGenerated, DvcHostname, User, PamModule, Result, SrcIpAddr, EventOriginalMessage
| sort by TimeGenerated asc
```

---

## B2 — The Internal Sweep · 162

**Q.** The internal reconnaissance is not in the on-prem SIEM at all. What destination port sequence shows the whole attack in one table?

**A.** `53, 80, 88, 135, 139, 389, 443, 445, 636, 3268, 49668`

The external address is absent on-prem because the gateway translates it. The sweep is witnessed only by `NTANetAnalytics` in the **cloud** workspace. The sequence is itself a fingerprint: DNS, HTTP, Kerberos, RPC endpoint mapper, NetBIOS, LDAP, HTTPS, SMB, LDAPS, Global Catalog and a dynamic RPC port in a single pass is a full AD recon tool, not a person.

```kql
// [run] Ports touched on the DC by the translated internal address
NTANetAnalytics
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| where SrcIp == "<translated internal address>"
| where DestIp == "<domain controller>"
| summarize Flows = count(), First = min(TimeGenerated) by DestPort
| sort by DestPort asc
```

---

# Stage 02 — On-prem phase

## O1 — The Mapping Tool · 150

**Q.** A tight named-pipe burst over `IPC$`, then an artifact drops. Which tool, and what am I inferring rather than seeing?

**A.** `BloodHound` and **the tool identity**

The *pattern* is observed; the *identity* is inferred. The attacker host is not onboarded, so no process, binary or hash exists — anything producing the same pipe sequence would look identical. Note that the named-pipe alert cannot corroborate this, because it is a false positive (T3).

```kql
// [run] Named-pipe access over IPC$ from non-machine sources
SecurityEvent
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| where EventID in (5140, 5145)
| where ShareName has "IPC$"
| where Account !endswith "$"
| project TimeGenerated, Account, RelativeTargetName, IpAddress, WorkstationName
| sort by TimeGenerated asc
```

---

## O2 — The Reset Actor · 125

**Q.** An account reset ran on the DC and the thing that performed it is not a person. Which identity?

**A.** `svc_helpbot`

Two resets ran in the window. Comparing who performed each and against whom separates them: the benign one is performed by `GF-DC01$` against a standard user; this one is `svc_helpbot` against a privileged account.

```kql
// [run] All resets in the window, actor against target
WindowsAccountMgmt_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-08))
| where EventID in (4724, 4738)
| where DvcHostname has "greenfield"
| project TimeGenerated, EventID, Operation, TargetUsername, ActorUsername, DvcHostname
| sort by TimeGenerated asc
```

---

## O3 — The Injected Block · 166

**Q.** Under a genuine printer fault is a block that did not come from the person who raised it. What tag presents it as an automated security notice?

**A.** `[GF-SEC-REMEDIATION]`

```kql
// [run] The agent turn and the content it read
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| project TimeGenerated, session_id, actor, user_input, retrieved_content,
          tool_name, tool_args, gate_decision, gate_reason, gate_marker_type, gate_marker_text
| sort by TimeGenerated asc
```

---

## O4 — The Gate Marker · 166

**Q.** The gate let this through because a marker was present, not because it was checked. Which reference?

**A.** `GF-IR-4488`

`gate_reason = authorisation_marker_present`. Present, not verified — the distinction the whole incident turns on.

```kql
// [run] Gate decisions and the markers they accepted
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| project TimeGenerated, session_id, gate_decision, gate_reason,
          gate_marker_type, gate_marker_text
| sort by TimeGenerated asc
```

---

## O5 — The Tool Call · 125

**Q.** Between the agent deciding and the write landing in AD, what did the tool layer invoke?

**A.** `reset_account_password`

Three witnesses — agent log, tool layer, AD — for one action, inside 40 ms.

```kql
// [run] Tool-layer invocations
MCPToolCalls_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| project TimeGenerated, mcp_server, tool, arguments, result, caller, session
| sort by TimeGenerated asc
```

---

## O6 — The Password Source · 166

**Q.** Which field in the arguments separates this reset from every benign one?

**A.** `password_source = caller_supplied`

A legitimate reset generates its own password. This one used a value supplied by the requester — i.e. by the attacker, in the ticket text.

```kql
// [run] Password provenance across all tool calls
MCPToolCalls_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| extend PwdSource = tostring(parse_json(arguments).password_source)
| extend Target    = tostring(parse_json(arguments).username)
| project TimeGenerated, tool, Target, PwdSource, caller, session
| sort by TimeGenerated asc
```

---

## O7 — The Cross-Account Reset · 180

**Q.** Neither half is suspicious alone. Which pair of events, and which single field comparison is the signal?

**A.** `tool_args.username: t.harris` **vs.** `actor: Mark Smith`

An agent turn and a reset on the DC. The signal is that the requester does not own the account being reset. This comparison is also the detection rule in S2.

```kql
// [run] The comparison that exposes it
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| extend TargetUser = tostring(parse_json(tool_args).username)
| where isnotempty(TargetUser)
| extend RequesterOwnsTarget = actor has TargetUser
| project TimeGenerated, session_id, actor, TargetUser, RequesterOwnsTarget,
          tool_name, gate_decision
```

---

## O8 — The Coverage Gap · 166

**Q.** Sweep both workspaces for the reset, the group change and the agent tables. What comes back, and what is the nearest High?

**A.** **No alert fired for the reset or the group-add**, and the nearest High is `GF Pipe - Post-Exploitation Framework Named Pipe`

The two actions that took the intruder from standard user to domain-wide credential access generated no detection at all. The nearest High fired 36 seconds earlier on something else — and per T3 it is a false positive, so the nearest signal was noise.

```kql
// [run] Everything that fired around the escalation
SecurityAlert
| where TimeGenerated between (datetime(2026-08-06 11:00) .. datetime(2026-08-06 13:00))
| where AlertName !has "FP Study" and AlertName !has "lognpacific"
| extend DeltaFromReset = TimeGenerated - datetime(2026-08-06 11:53:55)
| project TimeGenerated, DeltaFromReset, AlertName, AlertSeverity, ProductName
| sort by TimeGenerated asc
```

---

## O9 — The Certificate · 150

**Q.** The reset account requests something and receives it sixty milliseconds later. What did it obtain?

**A.** `GF-PrivilegedAccessLogon`

4886 request and 4887 issuance, both in `WindowsCertServices_CL`. Serial `5e00000009dcf20b1a0b12911e000000000009`, issued 2026-08-06 12:02:54 UTC.

```kql
// [run] Certificate request and issuance pairs
WindowsCertServices_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| extend Requester = extract('Name="Requester">([^<]+)', 1, EventData)
| extend Serial    = extract('Name="SerialNumber">([^<]+)', 1, EventData)
| extend SAN       = extract('Name="SubjectAlternativeName">([^<]*)', 1, EventData)
| project TimeGenerated, EventOriginalType, CertificateTemplate, Requester, SAN, Serial
| sort by TimeGenerated asc
```

---

## O10 — The Binding Question · 180

**Q.** The DC enforces strong certificate binding and accepted this certificate. Give the SAN and the specific mechanism in the template that granted the privilege.

**A.** `t.harris@greenfield.local` and **the template's `msPKI-Enrollment-Flag` has `CT_FLAG_NO_SECURITY_EXTENSION` set — `GF-PrivilegedAccessLogon` is configured to omit the `szOID_NTDS_CA_SECURITY_EXT` SID extension from issued certificates**

Binding did not fail; it had nothing to work with. Strong binding compares the SID embedded in the certificate against the SID of the account presenting it. This template omits that extension, so there is no input to the comparison and the DC falls back to mapping implicitly from the UPN in the SAN. The privilege comes from an enrolment-flag setting that removes the only field capable of catching an identity mismatch — not from the EKU, the template name, or group membership. This is the AD CS **ESC9** pattern, and it is why revoking the certificate does not close the problem (IR5).

```kql
// [run] Issuance record — SAN present, and the template configuration to check
WindowsCertServices_CL
| where TimeGenerated between (datetime(2026-08-06) .. datetime(2026-08-07))
| where EventOriginalType == 4887
| extend SAN      = extract('Name="SubjectAlternativeName">([^<]*)', 1, EventData)
| extend Subject  = extract('Name="Subject">([^<]*)', 1, EventData)
| extend Serial   = extract('Name="SerialNumber">([^<]+)', 1, EventData)
| project TimeGenerated, CertificateTemplate, Subject, SAN, Serial
```
> The flag itself is a template attribute, not a log field — read `msPKI-Enrollment-Flag` on the `GF-PrivilegedAccessLogon` template object in the AD Configuration partition and test bit `0x00080000`.

---

## O11 — The Silent Group Add · 125

**Q.** Nobody added this account to a privileged group, yet minutes later it holds rights a standard user does not. Then it collects one thing so a new membership takes effect. Which group?

**A.** `GF-Tier0-Automation`

The 4728 exists — with the account as **its own actor**. No administrator authorised it and none appears in the log, because the certificate path supplied the authenticated context. The "one thing" collected afterwards is a fresh Kerberos ticket: group membership is baked into the ticket at issue, so an existing ticket would not carry it.

```kql
// [run] Group additions, actor against member
WindowsAccountMgmt_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-08))
| where EventID == 4728
| where DvcHostname has "greenfield"
| project TimeGenerated, GroupName, MemberName, ActorUsername, DvcHostname
| sort by TimeGenerated asc
```

---

## O12 — The Five-Second Extraction · 180

**Q.** Every account's secrets left the DC in under five seconds and nothing touched host memory. What technique, and which right?

**A.** `DCSync` and **Replicating Directory Changes All**

There is no memory trace because no memory was touched. DCSync asks the DC to hand over its secrets through the replication protocol, as a domain controller peer would — the credentials are served, not scraped. Proving it from the audited right is stronger than inferring it from a missing memory artefact, because absence has many causes and an audited right has one.

```kql
// [run] Replication rights exercised by non-machine accounts
SecurityEvent
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-08))
| where EventID == 4662
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   // Get-Changes-All
    or Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"   // Get-Changes
| project TimeGenerated, Account, ObjectName, ObjectType, Properties, Computer
| sort by TimeGenerated asc
```

---

## O13 — The Surviving ACE · 180

**Q.** Two writes to the same object, one changed nothing. Which entry is real, and why does a dangerous-permissions audit miss it?

**A.** `12:10:22 UTC — real write; 12:50:14 UTC is a no-op`

The added entry is `(A;OICI;CR;;;S-1-5-21-2130493337-2304943033-647427612-1107)` on the `nTSecurityDescriptor` of `DC=greenfield,DC=local`. The audit misses it because the mask is **`CR` (ControlAccess) with no object GUID** — a full-control-only filter never returns a bare control-access ACE, so the object reports clean while the DCSync grant persists.

Pair the writes by correlation ID and compare the descriptor content on each side, **not** the object's latest state — the latest write is the no-op, so baselining from it shows nothing.

```kql
// [run] Pair by correlation ID, hash each side. Equal hashes = the no-op.
WindowsDirChanges_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| where TargetObject == "DC=greenfield,DC=local"
| where AttributeLDAPDisplayName =~ "nTSecurityDescriptor"
| extend UTC    = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss.fff')
| extend Corr   = extract('Name="OpCorrelationID">.([0-9a-f-]+)', 1, EventData)
| extend Op     = extract('Name="OperationType">(%%[0-9]+)', 1, EventData)
| extend SD     = extract('Name="AttributeValue">(.*?)</Data>', 1, EventData)
| extend SDHash = hash_sha256(SD)
| project UTC, SubjectAccount, Corr, Op, SDHash
| sort by UTC asc
```

| UTC | Corr | Op | SDDL SHA256 |
|---|---|---|---|
| 12:10:22.873 | `554fa8d5-…` | `%%14675` deleted | `1c004054…d627c` |
| 12:10:22.874 | `554fa8d5-…` | `%%14674` added | `aa49dc10…b2dba` |
| 12:50:14.895 | `ed413c2c-…` | `%%14674` added | `aa49dc10…b2dba` |
| 12:50:14.895 | `ed413c2c-…` | `%%14675` deleted | `aa49dc10…b2dba` |

```kql
// [run] Extract both SDDL strings for the real write, then diff by ACE offline
WindowsDirChanges_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| where TargetObject == "DC=greenfield,DC=local"
  and AttributeLDAPDisplayName =~ "nTSecurityDescriptor"
| extend Corr = extract('Name="OpCorrelationID">.([0-9a-f-]+)', 1, EventData)
| where Corr == "554fa8d5-7771-4732-b426-3be6f2c13ca1"
| extend Op = extract('Name="OperationType">(%%[0-9]+)', 1, EventData)
| extend SD = extract('Name="AttributeValue">(.*?)</Data>', 1, EventData)
| project Op, SD
```
Tokenising on `\(([^()]*)\)` gives 62 ACEs before, 63 after, one added, zero removed.

```kql
// [run] Full-retention sweep proving no third write exists
WindowsDirChanges_CL
| where TimeGenerated between (datetime(2026-07-15) .. datetime(2026-08-14))
| where AttributeLDAPDisplayName =~ "nTSecurityDescriptor"
| extend UTC = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss.fff')
| summarize count() by UTC, TargetObject, SubjectAccount
| sort by UTC asc
```

> **Two traps.** The portal renders these as 07:10:22 and 07:50:14 local — read UTC. And the answer must carry both halves in one submission: the real write's time **and** the no-op judgement.

---

## O14 — The Benign Twin · 169

**Q.** The same replication ran 45 minutes earlier and nothing alerted. Was it hostile, and which principal ran it?

**A.** `GF-DC01$` — **not hostile**

A domain controller replicating is the operation working as designed. The rule excludes machine accounts deliberately. Before calling any silence a coverage gap, read the exclusion.

```kql
// [reconstructed] Both replication events side by side
SecurityEvent
| where TimeGenerated between (datetime(2026-08-06 11:00) .. datetime(2026-08-06 14:00))
| where EventID == 4662
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| extend IsMachine = Account endswith "$"
| project TimeGenerated, Account, IsMachine, ObjectName, Computer
| sort by TimeGenerated asc
```

---

## O15 — The Scheduling Gap · 150

**Q.** The rule was right. Compare when the replication happened against when the incident opened. What is the gap?

**A.** `36m 46s` — **scheduling**

The detection content was correct and it fired on the right event. What failed is how often it runs. Thirty-seven minutes is long enough for DCSync to complete, the collection sweep to finish and the operator to leave — which makes the fix a schedule change, not a logic change.

```kql
// [reconstructed] Operation time vs alert time
let Replication =
    SecurityEvent
    | where TimeGenerated between (datetime(2026-08-06) .. datetime(2026-08-07))
    | where EventID == 4662 and Account !endswith "$"
    | summarize min(TimeGenerated);
let Alert =
    SecurityAlert
    | where AlertName has "Replication Rights By Non-Machine Account"
    | summarize min(TimeGenerated);
print Gap = toscalar(Alert) - toscalar(Replication)
```

---

## O16 — The Published Key · 150

**Q.** The last file read is a policy file off a domain share, world-readable for years. What credential does it yield?

**A.** `GPPstillStandingStrong2k18`

GPP `cpassword` is encrypted with a key Microsoft published in 2012, so the protection is nominal. `AccessReason` on the read is `D:(A;;0x1200a9;;;WD)` — read and execute granted to **Everyone**.

```kql
// [run] The SYSVOL policy file read, with the access reason
WindowsObjectAccess_CL
| where TimeGenerated between (datetime(2026-08-06 12:55) .. datetime(2026-08-06 13:05))
| where RelativeTargetName has "Groups"
| project TimeGenerated, ActorUsername, ShareName, RelativeTargetName,
          AccessList, SrcIpAddr, EventOriginalMessage
```
> The credential is **not** in telemetry — `WindowsObjectAccess_CL` records that the file was read, not its contents. The value comes from the recovered file. Free-text searching for `cpassword` returns only the contaminating `cgm-*` estate.

---

## O17 — The Recovery Account · 125

**Q.** One file holds three credentials, and on a domain controller one matters far more. Which?

**A.** `DSRM_Gr33nfield!`

Three blast radii: FTP (`Ft9$xLm2024`) is host-scoped to `gf-web01`; `svc_backup` (`Greenfield2024`) is domain-scoped; **DSRM** is Directory Services Restore Mode — offline recovery access to the DC itself, usable outside normal domain authentication, unaffected by ordinary domain remediation, and the one most often forgotten in a rotation.

```kql
// [run] The credential file read
WindowsObjectAccess_CL
| where TimeGenerated between (datetime(2026-08-06) .. datetime(2026-08-07))
| where RelativeTargetName has "credentials"
| project TimeGenerated, ActorUsername, ShareName, RelativeTargetName, SrcIpAddr
```

---

## O18 — The Fallback · 169

**Q.** Two identities did the collection. Which actually read the files, and across how many shares? What do the logs not capture?

**A.** `m.smith` and **9** distinct shares

`IPC$`, `ADMIN$`, `C$`, `CertEnroll`, `Finance`, `NETLOGON`, `SYSVOL`, `IT`, `Public`. The other identity touched shares and stopped. **There is no denial event anywhere** — nothing refused them at any point. That absence is a finding, but only because the handover can be reconstructed from the share sequence, source address and timing that *are* present.

```kql
// [run] Distinct shares per identity
WindowsObjectAccess_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| where ActorUsername !endswith "$"
| summarize Shares = dcount(ShareName), ShareList = make_set(ShareName, 20),
            First = min(TimeGenerated), Last = max(TimeGenerated)
        by ActorUsername
| sort by Shares desc
```

---

## O19 — The Disclosure Threshold · 150

**Q.** One file taken is not a credential store at all and changes what kind of incident this is. Which file?

**A.** `employee_records.csv`

Personal data. This converts a security incident into a personal-data breach with a notification obligation and a clock that started at discovery, and it means people with no involvement in the compromise are now affected parties.

```kql
// [run] Non-credential files in the collection
WindowsObjectAccess_CL
| where TimeGenerated between (datetime(2026-08-06) .. datetime(2026-08-07))
| where ActorUsername !endswith "$"
| where isnotempty(RelativeTargetName) and RelativeTargetName has "."
| project TimeGenerated, ActorUsername, ShareName, RelativeTargetName
| sort by TimeGenerated asc
```

---

# Stage 04 — Strategic

## S1 — The Coverage Inversion · 169

**Q.** Ranking beats by evidence quality against detection coverage, one sits top for evidence and bottom for coverage. Which source?

**A.** `LLMAgentLogs_CL`

It holds the complete decision record — retrieved content, tool name, tool arguments, gate decision, gate reason, accepted marker text. No analytic rule in either workspace queries it. The agent turn is the **best-evidenced event in the entire intrusion** — better than the DCSync, better than the certificate — and the only one nobody was watching.

```kql
// [reconstructed] Tables holding evidence vs tables referenced by rules
union withsource=T *
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| summarize Events = count() by T
| sort by Events desc
// then compare against the analytic rule inventory in the Sentinel Analytics blade
```

---

## S2 — The Cross-Source Rule · 150

**Q.** The compromise is in one table and its consequence in another. Which two, and what rule?

**A.** `LLMAgentLogs_CL` and `WindowsAccountMgmt_CL` — **join on username / target identity within a tight time window**

Neither side alone is anomalous: the agent log shows a normal ticket resolution, the AD log shows a normal help-desk reset. The join is what exposes the mismatch between who asked and whose account changed.

```kql
// [reconstructed] Proposed detection
let window = 2m;
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| extend TargetUser = tostring(parse_json(tool_args).username)
| where isnotempty(TargetUser)
| project AgentTime = TimeGenerated, session_id, actor, tool_name, TargetUser,
          PwdSource = tostring(parse_json(tool_args).password_source)
| join kind=inner (
    WindowsAccountMgmt_CL
    | where EventID in (4724, 4738)
    | project ResetTime = TimeGenerated, TargetUsername, ActorUsername, EventID
  ) on $left.TargetUser == $right.TargetUsername
| where ResetTime between (AgentTime .. AgentTime + window)
| where PwdSource == "caller_supplied" or not(actor has TargetUser)
| project AgentTime, ResetTime, session_id, actor, TargetUser, PwdSource, ActorUsername
```

**Tuning caveats.** Legitimate self-service resets match the join and must be excluded on actor-owns-target. Bulk onboarding resets performed by `GF-DC01$` are the main false-positive source.

---

## S3 — The Response Failure · 169

**Q.** The techniques were all detected and correlated. So why is this a loss? What is it, and the single cheapest control?

**A.** **Triage / response failure**, and **auto-assignment / mandatory-acknowledgement SLA on High-severity incidents**

The interesting question was never what the tooling missed. Ten alerts across three products correlated correctly into one incident that escalated itself High — close to the best outcome a detection stack can produce. Then it sat New and unassigned for 15h37m while the VPN entry, internal sweep, agent abuse, certificate, ACE and DCSync all happened. Every technical recommendation in the report is worth doing, and none would have mattered if the incident that already existed had simply been opened.

```kql
// [run] The incident's own state history
SecurityIncident
| where IncidentNumber == 161166
| project CreatedTime, FirstActivityTime, LastActivityTime, Severity, Status,
          Owner, ClosedTime, IncidentNumber
```

---

# Stage 03 — Response

## IR1 — Session Containment · 169

**Q.** First containment action, and why is a reset alone not enough?

**A.** **Revoke the user's refresh tokens / sign-in sessions** (Entra ID "Revoke sessions"), before or at minimum alongside any credential change.

A password reset alone is not enough because **the attacker never had the password**. Entry was a replayed session cookie, so what they hold is an already-issued refresh/access token. Resetting the password changes the credential used to *obtain* new tokens; it does not invalidate tokens already issued. The stolen session stays valid until its own lifetime expires or it is explicitly revoked, so the attacker survives the reset and simply keeps refreshing.

**Order matters:** revoke sessions → reset password → re-register MFA and audit authentication methods. Reversing it leaves a window in which the live session can re-enrol MFA or observe the new state.

```kql
// [run] The evidence for "no password was ever used"
IdentityLogonEvents
| where Timestamp between (datetime(2026-08-05) .. datetime(2026-08-07))
| where AccountObjectId == "fa5020a1-0d42-4839-bbfe-22db0861ced5"
| summarize Count = count() by ActionType, LogonType, FailureReason
| sort by Count desc
```

---

## IR2 — The IP Blocking Question · 169

**Q.** Four attacker exit addresses. Block them at the edge?

**A.** **Reject** — of the four exit addresses, **at least one is a NAT gateway**.

Blocking is only right if the addresses are stable, unique to the attacker, and not shared with legitimate traffic. Here they fail all three tests: a NAT gateway carries other people's traffic, so blocking it takes out legitimate users while the attacker rotates to the next address. **Contain by identity and session instead** — which is the same conclusion C2 reached from the other direction.

```kql
// [run] Are these addresses shared with legitimate traffic?
SigninLogs
| where TimeGenerated between (datetime(2026-08-04) .. datetime(2026-08-08))
| where IPAddress in ("159.26.115.80", "<addr2>", "<addr3>", "<addr4>")
| summarize Users = dcount(UserPrincipalName), UserList = make_set(UserPrincipalName, 20),
            First = min(TimeGenerated), Last = max(TimeGenerated)
        by IPAddress
| sort by Users desc
```

---

## IR3 — The krbtgt Rotation · 169

**Q.** Action, count, interval condition.

**A.** **Reset (rotate) the krbtgt account password — twice, sequentially (count: 2), and the two resets must be separated by at least the maximum Kerberos ticket lifetime.**

One reset is not enough because AD deliberately retains the previous key version (N−1) so tickets in flight keep working — a forged ticket signed with the old key stays valid. Two resets back to back invalidate tickets still in legitimate use and break authentication estate-wide. The gap must exceed the maximum ticket lifetime so every legitimate ticket has naturally expired before the second reset lands.

**And this must follow the ACE removal (IR4).** Rotating krbtgt while the DCSync grant stands means the attacker simply replicates the new key.

---

## IR4 — Is It Contained · 187

**Q.** Account disabled, Tier 0 emptied, certificate revoked. Is the attacker evicted?

**A.** **No.**

The surviving mechanism is the ACE `(A;OICI;CR;;;S-1-5-21-2130493337-2304943033-647427612-1107)` on the `nTSecurityDescriptor` of `DC=greenfield,DC=local`, written 2026-08-06 12:10:22 UTC, granting all control-access rights — including DS-Replication-Get-Changes and DS-Replication-Get-Changes-All, i.e. DCSync — with container and object inheritance.

- **Disabling the account** changes `userAccountControl` on the user object. It does not touch the domain root's DACL. The ACE references the SID, and the SID still resolves; the entry remains whether the account is enabled, disabled or deleted. Any path back to that SID — re-enabling, a recycle-bin restore, or SID-History injection onto another principal — reactivates the grant.
- **Emptying Tier 0** removes rights held *by virtue of membership*. This right was granted directly to the SID on the object, so no membership change affects it.
- **Revoking the certificate** invalidates one authentication method. The ACE is an authorisation entry, not an authentication artefact.

All three actions are real containment and all three are aimed at the **account**. The persistence was placed somewhere that outlives the account — which is exactly why the permissions audit reported the object clean (O13).

```kql
// [run] Does the ACE depend on anything the three actions touched? No.
WindowsDirChanges_CL
| where TimeGenerated between (datetime(2026-07-15) .. datetime(2026-08-14))
| where TargetObject == "DC=greenfield,DC=local"
| extend UTC = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss.fff')
| project UTC, SubjectAccount, AttributeLDAPDisplayName
| sort by UTC asc
```

---

## IR5 — The Template Problem · 169

**Q.** Certificate revoked. Does that close the ADCS problem?

**A.** **No** — **fix the certificate template configuration itself, not just the individual certificate.**

Revocation addresses this instance. It does not change how the template issues the next one. While `CT_FLAG_NO_SECURITY_EXTENSION` remains set on `GF-PrivilegedAccessLogon`, every certificate it issues omits the SID extension and the same privilege path stays open to anyone who can enrol.

---

## IR6 — Detection vs Authorisation · 187

**Q.** Build a detection rule for those authorisation markers?

**A.** **Reject** — **fix the authorisation architecture, not the detection surface.**

A detection rule fires *after* the action. By the time it alerts, the Tier 0 password is already reset and the attacker is already authenticating. More fundamentally, the marker is attacker-authored text: a rule keyed on `GF-IR-4488` is defeated by typing `GF-IR-4489`. The class of failure is that authorisation was asserted inside untrusted content and accepted. That cannot be fixed after the fact — the gate must verify authorisation against the system of record, out of band, *before* the privileged call.

Detection still has a place (S2), but as a backstop, not as the fix.

---

## IR7 — The Forwarding Hunt · 150

**Q.** Why does hunting for a malicious inbox rule fail, and what do I do instead?

**A.** **The mail persistence was not set as an inbox rule at all.** Query `OfficeActivity` for `Operation == "Set-Mailbox"` where the Parameters contain `ForwardingSmtpAddress`, recover the destination address, clear the property and block the destination.

Forwarding configured as a **mailbox property** does not appear in the user's rules list and is invisible to any hunt that enumerates rules. That is precisely why the user never noticed it.

```kql
// [run] The correct hunt
OfficeActivity
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-08))
| where Operation == "Set-Mailbox"
| where Parameters has "ForwardingSmtpAddress"
| extend Destination = extract('ForwardingSmtpAddress[^,]*,"Value":"([^"]+)"', 1, Parameters)
| project TimeGenerated, UserId, Operation, Destination, ClientIP, Parameters
| sort by TimeGenerated asc
```

---

## IR8 — The MFA Failure · 169

**Q.** MFA was satisfied five times with no failures. Is re-enrolling TOTP the answer?

**A.** **No.** The `credentials.txt` file swept from the IT share (O17/O18) is the seed store — and the fix is to **move to FIDO2/WebAuthn hardware security keys.**

The attacker never intercepted a code in transit; they held the **seed**. Re-enrolling TOTP issues a new seed with exactly the same property: it is a file, it can be stored somewhere readable, and the extraction method that took the first one still works. Re-issuing the same class of factor changes nothing.

FIDO2/WebAuthn keys are hardware-bound and non-exportable — there is no seed to steal, which removes the class of failure rather than the instance.

```kql
// [run] Five authentications, zero failures — rules out interception
LinuxAuth_CL
| where TimeGenerated between (datetime(2026-08-05) .. datetime(2026-08-07))
| summarize Attempts = count() by Result, PamModule, User
| sort by Attempts desc
```

---

## IR9 — Rank the Interventions · 187

**Q.** Rank three interventions by impact reduction, with justification. Is the answer technology at all?

**A.**

1. **Timely triage of the incident — process, not technology.** INC-161166 was already escalated High before the on-prem phase began, and sat unassigned all night. Everything that followed happened inside a window in which the alert was open and unread. This is first because it costs nothing and it alone changes the outcome.
2. **Non-exportable, hardware-bound MFA plus removing plaintext credential files — technology.** The TOTP seed existed as a file on an open share, so even a contained cloud compromise still yielded a durable second factor and a route onto the estate.
3. **Fixing the MCP agent's authorisation trust boundary — architecture.** The escalation vector was the help-desk agent honouring an in-band, unverified authorisation marker to reset a privileged password.

The ranking is the point: the highest-leverage control here is not a product.

---

## IR10 — The Rotation List · 169

**Q.** Every credential, in order, and why that sequence.

**A.** Strip the sources first — rotating before these completes re-burns the credential immediately.

**Prerequisites:** remove the domain-root ACE · delete `Groups.xml` from SYSVOL · revoke certificate `5e00000009dcf20b1a0b12911e000000000009` and clear `CT_FLAG_NO_SECURITY_EXTENSION` on the template · remove `\\IT\credentials.txt` from the share.

Then rotate, widest blast radius first:

1. **krbtgt — twice, with replication convergence between resets.** DCSync (O12) took every hash; a forged TGT voids all rotation below. Remove the ACE (O13) first or it is re-harvested.
2. **DSRM — `DSRM_Gr33nfield!`** (O17). DC recovery credential, domain-wide radius, survives normal domain remediation.
3. **The GPP credential — `GPPstillStandingStrong2k18`** (O16). Delete `Groups.xml` first, or the GPO republishes the new password to a world-readable share. Applies to every machine the policy targeted.
4. **svc_backup — `Greenfield2024`** (O17). Holds Replicating Directory Changes All on the domain root.
5. **t.harris — `Greenfield#Temp2026`.** Revoke the certificate first, or PKINIT survives the reset.
6. **svc_helpbot** (O2/O5). Performed the privileged reset; re-drivable through the same injection path.
7. **VPN credentials from `VPN-Access-Credentials.txt`** (C5). The bridge that made on-prem access possible.
8. **ftp_backup — `Ft9$xLm2024`** (O17). Host-scoped, lowest of the three in the file.
9. **Every credential inside the exfiltrated vaults**, including `Personal.kdbx` (C4).
10. **m.smith** (C1). Never credential-compromised — token replay — so session revocation and MFA re-registration matter more than the password.

---

# Appendix — Two mistakes worth recording

**The `.org` / `.com` trap.** The compromised identity is `m.smith@lognpacific.org`. The workspace is contaminated with `lognpacific.com` accounts whose names are SHA256 hashes. Filtering on `.com`, or on a UPN pattern rather than the object ID, returns either nothing or another estate's data. Several early queries in this investigation returned "No results found" for exactly this reason.

**The local-time trap.** CSV exports and the portal grid render `TimeGenerated` in the browser's timezone. Every on-prem timestamp in this case reads five hours early in the export — the ACE write shows as 07:10:22 and is actually 12:10:22 UTC. Any answer submitted from the grid without conversion is wrong by five hours. `format_datetime(TimeGenerated,'HH:mm:ss.fff')` always emits UTC and is the safe habit.

---

*Compiled by @ellie-pham-7436 · Greenfield SOC · Cyber Range Operations · case GF-INC-2026-0806*
