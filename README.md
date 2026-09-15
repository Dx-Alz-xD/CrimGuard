# CrimGuard

### Insider-Threat Detection Built Into a Working File-Sharing Platform

**CrimGuard** is an insider-threat detection platform integrated directly into a functional file-sharing system.

Instead of only asking **"Is this activity unusual?"**, CrimGuard asks a more important question:

> **"Is there a legitimate reason for this activity?"**

The system continuously evaluates user behaviour, compares it against the user's own historical baseline, considers organizational context, and dynamically adjusts access when risk increases.

---

## Table of Contents

* [Overview](#overview)
* [The Problem](#the-problem)
* [How CrimGuard Works](#how-crimguard-works)
* [Red and CrimGuard](#red-and-crimguard)
* [The Risk Score](#the-risk-score)
* [The 100 Risk Variables](#the-100-risk-variables)
* [Personal Baselines](#personal-baselines)
* [Context-Aware Detection](#context-aware-detection)
* [Risk Escalation](#risk-escalation)
* [Decoys and Honeytraps](#decoys-and-honeytraps)
* [Behavioural Biometrics](#behavioural-biometrics)
* [Identity Throttle](#identity-throttle)
* [Access Control](#access-control)
* [Departure Protection](#departure-protection)
* [Download Protection](#download-protection)
* [Shadow AI Detection](#shadow-ai-detection)
* [Architecture](#architecture)
* [Privacy](#privacy)
* [Validation](#validation)
* [Key Results](#key-results)
* [Admin Dashboard](#admin-dashboard)
* [Limitations](#limitations)
* [Project Philosophy](#project-philosophy)

---

# Overview

Traditional cybersecurity focuses heavily on preventing unauthorized people from entering a system.

CrimGuard focuses on a different problem:

**What happens when the person already has legitimate access?**

An employee does not need to break through a firewall to steal data. They may already have permission to access the files they want.

They simply log in normally.

That makes insider threats difficult to detect because malicious behaviour can look exactly like legitimate work.

CrimGuard addresses this by combining:

* Behavioural analysis
* Personal historical baselines
* File and data-access monitoring
* Organizational context
* Role and clearance information
* Behavioural biometrics
* Decoy files and honeytraps
* Risk-based access control
* Departure monitoring
* Explainable risk scoring

The result is a continuous loop:

```text
User Activity
      ↓
Behaviour Collection
      ↓
100 Risk Variables
      ↓
Personal + Contextual Analysis
      ↓
Risk Score (0–100)
      ↓
Policy Decision
      ↓
Access / Verification / Freeze
      ↓
New Behaviour
      ↺
```

---

# The Problem

Most security systems are good at identifying activity that is statistically unusual.

That is not necessarily the same thing as identifying malicious behaviour.

Consider two users.

### Case A — Legitimate activity

An engineer normally accesses approximately **15 files per day**.

One day they access **608 files**.

That is an enormous spike.

A conventional anomaly detector may immediately flag the account.

However, there is an approved migration ticket requiring approximately 600 files to be accessed.

CrimGuard therefore treats the activity as largely explained.

**Risk score: 17.8**

---

### Case B — Insider theft

Another employee normally accesses approximately **15 files per day**.

Their activity gradually increases:

```text
15 → 18 → 22 → 27 → 34 → 41 → 50 → 60 → 70
```

This happens over approximately three months.

There is:

* No migration
* No project
* No role change
* No approved ticket

There is no dramatic spike.

A traditional anomaly detector comparing activity against recent behaviour may never trigger.

CrimGuard uses a **frozen historical baseline** in addition to the recent baseline.

This allows it to detect gradual behavioural drift.

**Risk score: 72.9**

The system detects the theft approximately **7.5 weeks into the gradual escalation**.

---

# Red and CrimGuard

CrimGuard consists of two closely integrated systems.

| Component     | Purpose                                         |
| ------------- | ----------------------------------------------- |
| **Red**       | The actual file-sharing platform                |
| **CrimGuard** | The security and insider-threat detection layer |

### Red

Red provides the normal working environment:

* Accounts
* Authentication
* Projects
* Files
* File sharing
* Permissions
* Downloads
* Activity logs

Users interact with Red as they normally would with a file-sharing platform.

### CrimGuard

CrimGuard continuously observes activity within Red and evaluates risk.

It can:

* Calculate risk scores
* Identify behavioural anomalies
* Detect suspicious sequences
* Introduce additional authentication
* Reduce access
* Deploy decoys
* Freeze accounts
* Record security decisions

The important architectural principle is that **security is integrated into the platform rather than bolted onto it afterwards**.

---

# The Risk Score

Every account receives a continuously updated risk score:

```text
0 ───────────────────────────────────────────── 100
Low                                             Critical
```

The score is based on **100 separate risk variables**.

These variables measure different aspects of behaviour, including:

* File access
* Data movement
* Authentication
* Timing
* Devices
* Networks
* Behavioural biometrics
* Privilege changes
* HR context
* Communication patterns

The score is recalculated periodically and can also change immediately when important events occur.

Most importantly:

> **Every point of the final score can be traced back to the signals that produced it.**

CrimGuard is therefore designed to be explainable rather than a black-box risk classifier.

---

# Personal Baselines

A central design principle of CrimGuard is:

> **Compare users primarily against themselves, not against everyone else.**

Suppose one employee normally downloads 2 GB per day while another normally downloads 10 MB.

A universal rule such as:

```text
Alert if download > 1 GB
```

would constantly generate false positives for the first employee.

Instead, CrimGuard establishes an individual's normal behaviour and measures deviations from it.

For numerical signals, CrimGuard uses robust statistics such as:

* Median
* Median absolute deviation (MAD)

This prevents existing outliers from distorting the baseline.

---

## New Users

A new account has insufficient personal history.

Instead of treating the user as having no baseline, CrimGuard temporarily uses information from people in the same role.

The system gradually transitions from:

```text
Role-based baseline
        ↓
Mixed baseline
        ↓
Personal baseline
```

The transition occurs over approximately ten days.

---

# Detecting Slow Insider Theft

A major problem with conventional anomaly detection is **baseline poisoning**.

If an employee slowly increases their activity, a rolling baseline can gradually absorb the malicious behaviour.

For example:

```text
Month 1: 15 files/day
Month 2: 30 files/day
Month 3: 50 files/day
```

A rolling average eventually starts treating 50 files as normal.

CrimGuard therefore maintains an additional **anchored baseline**.

This is a frozen historical snapshot from approximately three to six months earlier.

The system can therefore detect both:

### Sudden anomalies

```text
15 → 608
```

### Slow behavioural drift

```text
15 → 18 → 22 → 30 → 40 → 50 → 70
```

---

# Context-Aware Detection

Unusual behaviour does not automatically mean malicious behaviour.

CrimGuard therefore asks:

> **Is there a legitimate explanation for what happened?**

The system checks four major dimensions.

| Factor              | Question                                      |
| ------------------- | --------------------------------------------- |
| **Reliability**     | Was the explanation actually approved?        |
| **Timing**          | Was it valid when the activity occurred?      |
| **Scope**           | Were the accessed resources actually covered? |
| **Proportionality** | Was the amount of activity reasonable?        |

For example:

```text
Approved migration
Expected: 600 files
Actual:   650 files
```

This is likely reasonable.

But:

```text
Approved migration
Expected: 600 files
Actual:   3,000 files
```

The explanation becomes much weaker.

### Explanations are capped

A legitimate ticket can reduce risk but can never completely eliminate it.

The maximum explanation factor is **90%**.

This prevents attackers from using fabricated or manipulated tickets as a perfect shield.

---

# Risk Calculation

The scoring process can be summarized as:

```text
Observed Behaviour
        ↓
Is it unusual for this user?
        ↓
How important is the signal?
        ↓
How valuable is the data?
        ↓
Is there a legitimate explanation?
        ↓
Are multiple signals reinforcing each other?
        ↓
Is there a suspicious sequence?
        ↓
Final Risk Score
```

Signals are weighted according to their importance.

### Highest-weight signals

Examples include:

* Data movement
* Personal cloud transfers
* USB activity
* Audit-log tampering
* Impossible travel
* Session-token reuse
* Unauthorized access grants

### Medium-weight signals

Examples include:

* Timing
* Communication
* Behavioural biometrics
* Physical/environmental signals

### Lower-weight signals

Examples include deliberately noisy indicators such as:

* Application switching
* Message volume

---

# Correlated Signals

CrimGuard avoids counting closely related signals as if they were completely independent.

For example, one bulk-copy operation might simultaneously increase:

* File count
* Bytes transferred
* Confidential-file count

These signals overlap.

Therefore, the strongest signal contributes fully while subsequent correlated signals contribute progressively less.

This reduces artificial score inflation.

---

# Suspicious Sequences

CrimGuard also looks for sequences rather than isolated events.

A common exfiltration pattern is:

```text
Collect
  ↓
Stage
  ↓
Send
```

When several stages occur together, CrimGuard applies an additional risk penalty.

This allows the system to recognize behavioural patterns rather than simply counting events.

---

# Risk Escalation

CrimGuard uses a graduated response system.

It does not immediately lock users out because of a suspicious event.

|    Risk | Response                                                          |
| ------: | ----------------------------------------------------------------- |
|  **40** | Decoy appears                                                     |
|  **50** | Additional password confirmation if account takeover is suspected |
|  **60** | Additional decoy                                                  |
|  **70** | Password confirmation required                                    |
|  **75** | Clearance reduced by one level                                    |
|  **80** | Additional decoy                                                  |
|  **85** | Clearance reduced again + verification                            |
|  **90** | Account frozen                                                    |
| **100** | Reserved for confirmed compromise / trap activation               |

The principle is:

> **The higher the confidence and severity, the stronger the response.**

---

# Decoys and Honeytraps

This is one of CrimGuard's strongest detection mechanisms.

At elevated risk levels, the system can create a **decoy project or file** that only the suspicious account can see.

Examples include:

```text
Production API Keys — DO NOT SHARE
Payroll and Compensation — All Staff
Customer Master List
```

These files are fake.

They contain no legitimate information.

---

## Why Decoys Work

Normal behavioural signals provide evidence of possible malicious activity.

A decoy provides substantially stronger evidence.

If a user interacts with a file that:

* Does not actually exist
* Was never part of their legitimate work
* Was specifically planted for detection

then the interaction is highly informative.

### Example

| Behaviour                | Result                                |
| ------------------------ | ------------------------------------- |
| Opens decoy              | No automatic punishment               |
| Reads decoy              | No automatic punishment               |
| Attempts to modify decoy | Account frozen                        |
| Attempts to delete decoy | Account frozen                        |
| Copies fake credential   | Account frozen                        |
| Uses fake credential     | Account and associated account frozen |

The system distinguishes **curiosity** from an action indicating intent.

---

# Canary Credentials

Some decoy files contain fake credentials that look like legitimate:

* API keys
* Passwords
* Authentication tokens

These credentials are monitored.

If they appear elsewhere, CrimGuard can determine that the information was moved.

The credentials can remain active as detection mechanisms even after the original decoy is removed.

This creates a form of persistent tripwire.

---

# Behavioural Biometrics

CrimGuard also attempts to determine whether the person using an authenticated account is actually the account owner.

It does this without recording the contents of what the user types.

Instead, it observes behavioural characteristics such as:

* Average time between keystrokes
* Key-hold duration
* Pointer movement speed
* Scrolling behaviour
* Idle patterns
* Focus changes

The system asks:

> **Does this session behave like the account owner's previous sessions?**

---

## Behavioural Biometrics + Risk

The biometric signal is not interpreted alone.

| Typing change    | Risk score | Interpretation                               |
| ---------------- | ---------: | -------------------------------------------- |
| Yes              |     Normal | Possible account takeover                    |
| Somewhat changed |   Elevated | Multiple signals agree                       |
| No               |   Elevated | Likely legitimate user behaving suspiciously |

This distinction is important.

A changed typing pattern with a normal risk score may indicate that someone else is using the account.

An unchanged typing pattern with a high risk score suggests that the legitimate user may be performing suspicious activity themselves.

---

# Impossible Travel Detection

CrimGuard compares sign-in locations and timestamps.

It calculates:

```text
Implied speed = Distance / Time
```

For example:

| Sign-ins          |   Time | Implied Speed | Result     |
| ----------------- | -----: | ------------: | ---------- |
| Berlin → Lagos    | 20 min |   15,589 km/h | Impossible |
| Paris → Lagos     | 45 min |    6,279 km/h | Impossible |
| Berlin → New York |   2 hr |    3,193 km/h | Impossible |
| Berlin → New York |  10 hr |      639 km/h | Plausible  |

The system uses actual geographic distance rather than simply comparing time zones.

Network changes are also considered to reduce false positives from:

* VPNs
* Browser location settings
* Time-zone manipulation

---

# Identity Throttle

CrimGuard has a centralized response layer called the **Identity Throttle**.

It coordinates multiple security signals and determines what action should occur.

### Step-up

The user must confirm their identity before continuing.

Triggered by:

* Risk score ≥ 70
* Possible account takeover
* Significant biometric change

### Freeze

All active sessions terminate and login is blocked until an administrator restores access.

Triggered by:

* Risk score ≥ 90
* Decoy/honeytrap activation

### Revoke

Existing sessions are terminated, but the user can authenticate again.

The response system records every action so that the security state survives application restarts.

---

# Access Control

CrimGuard uses a unified clearance model.

## Roles

| Role     | Clearance |
| -------- | --------: |
| Intern   |         1 |
| Employee |         2 |
| Admin    |         4 |
| CEO      |         5 |

## Files

| File Level | Classification |
| ---------: | -------------- |
|          1 | Open           |
|          2 | Internal       |
|          3 | Confidential   |
|          4 | Restricted     |
|          5 | Secret         |

A user's clearance must normally meet or exceed the file's confidentiality level.

---

# Risk-Based Clearance Reduction

As risk increases, CrimGuard can automatically reduce the user's effective clearance.

The baseline is calculated from the average confidentiality level of files within the system.

Example:

```text
Risk ≥ 75 → clearance may fall by one level
Risk ≥ 85 → clearance may fall by two levels
```

The goal is not necessarily to lock the employee out of their current work.

Instead, it is to reduce the amount of sensitive information they can reach while an investigation is occurring.

---

# Governance

Administrators can override restrictions for ordinary users when legitimate work requires it.

However:

> **An administrator cannot disable their own automatic restrictions.**

An administrator also cannot override restrictions for another administrator.

Only the CEO can override administrative restrictions.

Every override requires a reason and is logged.

This prevents the security mechanism from becoming optional for the people with the greatest privileges.

---

# Departure Protection

Insider theft can become particularly concerning when an employee is approaching departure.

CrimGuard therefore activates a special **departure gate** during the final 14 days before a recorded leaving date.

If a departing employee attempts to access a file that:

* Was explicitly handed to them by name
* Is above their normal clearance

the request is blocked and sent to an administrator.

The administrator can approve access temporarily.

Approvals:

* Apply to a specific file
* Expire after seven days
* Cannot bypass Secret-level restrictions
* Are recorded

The system also records attempts to access protected files as risk signals.

---

# Download Protection

When a user receives access to a file above their normal clearance, downloading it requires additional verification.

Each download requires a verification code.

A code is:

* Valid for one download
* Valid for one session
* Valid for two minutes

Five incorrect codes lock that file for the current session.

All attempts are logged.

---

## Rapid Download Detection

If a user attempts to download a newly granted file within **five seconds** of receiving access, CrimGuard increases their risk score.

The reasoning is that immediately grabbing a newly granted file can be a stronger indicator of collection behaviour than gradually working with the file.

The score increase is:

```text
+20 risk points
```

and remains relevant for seven days.

---

# Shadow AI Detection

CrimGuard includes a limited mechanism for identifying potential transfer of sensitive information into unauthorized AI systems.

The system can determine:

* Which internal file was copied from
* How much information was copied
* How confidential the source was
* Whether the copied data looked secret-shaped

However, CrimGuard does **not** pretend that a website can see everything happening on a computer.

A website cannot reliably observe:

* Another browser tab
* Another desktop application
* Arbitrary browser extensions
* Data entered into external applications

The system therefore only makes claims based on information it can actually observe.

---

# Sign-In Protection

Before a password is checked, the browser performs a small amount of computational work.

This is designed to increase the cost of large-scale credential attacks.

It is intentionally **not a CAPTCHA**.

The goal is to make thousands of automated login attempts expensive while adding only a small delay to legitimate users.

---

# Email Reputation

CrimGuard can also consider:

* Known breach exposure
* Disposable email domains

These are intentionally weak signals.

They can increase existing risk but **cannot create a high-risk state by themselves**.

This follows a broader design principle:

> **Weak contextual information should amplify evidence, not manufacture it.**

---

# Architecture

CrimGuard deliberately separates the normal application database from the security database.

## Application Database

Contains:

* Accounts
* Passwords
* Roles
* Projects
* Files
* Permissions
* Activity logs

## Risk Database

Contains:

* 100 risk variables
* Raw behavioural events
* Risk scores
* Alerts
* HR context
* Risk history

The application can continue operating independently of the security database.

If the risk database is detached, the file-sharing application continues functioning normally.

---

# End-to-End Data Flow

```text
                  ┌──────────────────┐
                  │      User        │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │       Red        │
                  │ File Sharing App │
                  └───────┬──────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
       Browser Signals         Server Signals
              │                       │
              └───────────┬───────────┘
                          ▼
                 ┌──────────────────┐
                 │  Risk Database   │
                 └────────┬─────────┘
                          ▼
                 ┌──────────────────┐
                 │  Risk Engine     │
                 │ 100 Variables    │
                 └────────┬─────────┘
                          ▼
                 ┌──────────────────┐
                 │ Risk Score 0–100 │
                 └────────┬─────────┘
                          ▼
                 ┌──────────────────┐
                 │ Policy / Throttle│
                 └────────┬─────────┘
                          ▼
                 ┌──────────────────┐
                 │ Access Decision  │
                 └──────────────────┘
```

---

# Browser vs Server Data

The browser is intentionally trusted with as little security authority as possible.

## Browser can report

* Typing rhythm
* Pointer speed
* Scrolling
* Idle time
* Focus changes
* Clipboard size
* Printing
* Browser characteristics

## Server records directly

* File access
* Search activity
* Authentication events
* Role changes
* Permission changes
* Downloads
* Data transferred
* Account activity

The server-side portion is considered more trustworthy because the browser cannot simply fabricate what the server itself observes.

---

# The 100 Risk Variables

The system contains 100 defined risk variables across ten categories.

| Category                    | Variables |
| --------------------------- | --------: |
| Access and resources        |        10 |
| Timing                      |        10 |
| Data movement               |        10 |
| Authentication and identity |        10 |
| Device and network          |        10 |
| Behavioural biometrics      |        10 |
| HR and organization         |        10 |
| Communication               |        10 |
| Privilege and permission    |        10 |
| Physical and environmental  |        10 |
| **Total**                   |   **100** |

The current website implementation provides **64 usable variables**.

The remaining **36 are deliberately marked as unavailable rather than zero** because they require systems outside the website, such as:

* Badge readers
* Endpoint agents
* Device management
* Mail gateways
* Data-loss prevention systems

This distinction is important.

```text
Unavailable ≠ Zero
```

If CrimGuard cannot observe a signal, it should not pretend that the signal is zero.

---

# Privacy

Privacy is a core design constraint rather than an afterthought.

CrimGuard records behavioural metadata, not the actual content of user activity.

## What CrimGuard records

* Typing rhythm
* Average pointer speed
* Clipboard size
* Number of copied characters
* Whether copied material resembles a password/key
* Files opened
* Pages accessed
* Sign-ins
* Browser information
* Approximate network information

## What CrimGuard does NOT record

* Actual keystrokes
* The keys a person typed
* Pointer coordinates
* Pointer paths
* Mouse clicks
* Clipboard contents
* File contents
* Precise physical location

For example:

> **CrimGuard records the rhythm of the typing, not the typing.**

The same principle applies to clipboard monitoring.

The system can determine that something resembling a secret was copied, but the copied text itself is discarded.

---

# User Transparency

Every user can view their own:

* Risk score
* 100 risk variables
* Risk contributions
* Relevant behavioural information

CrimGuard also provides a dedicated privacy explanation describing what is and is not collected.

The goal is to avoid a system where an organization secretly scores people without allowing them to understand the basis of that score.

---

# Admin Dashboard

Administrators can view:

### CrimGuard Dashboard

* Users
* Roles
* Projects
* Files
* Storage
* Online status
* Risk score

### Risk Console

* Current risk scores
* Alerts
* All 100 variables
* Individual score contributions
* HR context

### Activity Log

* Sign-ins
* Password changes
* Role changes
* File permission changes
* Downloads
* Access to administrative records

### Access Requests

A queue containing:

* User
* Requested file
* File classification
* Reason
* Remaining days before departure

---

# Self-Monitoring Administrators

CrimGuard also monitors the people who operate the system.

Looking at another person's sensitive record is itself logged.

Files above the viewer's clearance are counted but their names are not unnecessarily exposed.

This follows a simple principle:

> **A system that watches everyone must also watch its watchers.**

---

# Validation

The system has been tested against controlled scenarios with known expected outcomes.

## Scenario A — Legitimate Migration

```text
Normal behaviour:       15 files/day
Observed behaviour:     608 files/day
Explanation:            Approved migration
Resulting score:        17.8
```

The system recognizes that the behaviour is unusual but largely explained.

---

## Scenario A Without Explanation

```text
Normal behaviour:       15 files/day
Observed behaviour:     608 files/day
Explanation:            None
Resulting score:        96.3
```

The behaviour is identical.

Only the context changes.

The resulting risk therefore changes dramatically.

---

## Scenario B — Slow Insider Theft

```text
Normal behaviour:       15 files/day
Final behaviour:        70 files/day
Duration:               ~90 days
Explanation:            None
Resulting score:        72.9
Detection:              ~7.5 weeks
```

A conventional 3-sigma detector missed this gradual increase.

CrimGuard detected it using the anchored baseline.

---

## False Positive Testing

Five ordinary simulated users were evaluated across approximately:

```text
5 users × ~220 working days
≈ 1,100 user-days
```

Result:

```text
High-risk days: 0
```

The highest single observed day was approximately **44**.

---

# Key Results

| Metric                            |         Result |
| --------------------------------- | -------------: |
| Risk variables                    |        **100** |
| Currently populated variables     |         **64** |
| Risk categories                   |         **10** |
| Risk score                        |      **0–100** |
| Legitimate 608-file day           |       **17.8** |
| Same activity without explanation |       **96.3** |
| Slow-creep theft                  |       **72.9** |
| Slow-theft detection              | **~7.5 weeks** |
| Ordinary simulated user-days      |     **~1,100** |
| High-risk false alarms in test    |          **0** |
| Impossible-travel threshold       |   **900 km/h** |
| First clearance reduction         |         **75** |
| Second clearance reduction        |         **85** |
| Account freeze                    |         **90** |
| Departure monitoring window       |    **14 days** |
| Automated tests                   |        **270** |
| External npm dependencies         |          **0** |

---

# Core Design Principles

CrimGuard is built around several principles.

### 1. Unusual does not mean malicious

A spike in activity can be completely legitimate.

### 2. Context matters

A ticket, role change, project assignment, or other legitimate explanation can dramatically change the interpretation of behaviour.

### 3. Slow theft matters

Insider attacks do not necessarily look like sudden spikes.

### 4. Compare users with themselves

Personal baselines are often more meaningful than global thresholds.

### 5. Weak evidence should not create certainty

Signals such as email reputation or HR context can amplify existing risk but should not create it from nothing.

### 6. Explain every decision

Every risk score should have an identifiable cause.

### 7. Escalate gradually

Low-confidence anomalies should not immediately destroy someone's ability to work.

### 8. Confirm when possible

Step-up authentication and behavioural biometrics help distinguish suspicious behaviour from account takeover.

### 9. Use traps for certainty

A decoy interaction can provide significantly stronger evidence than statistical anomaly detection.

### 10. Never fake visibility

Unavailable signals are recorded as unavailable rather than being represented as zero.

---

# Why CrimGuard Is Different

Traditional security monitoring often follows this pattern:

```text
Detect anomaly
      ↓
Generate alert
      ↓
Send alert to analyst
      ↓
Wait for investigation
```

CrimGuard attempts to close the loop:

```text
Observe
   ↓
Understand personal baseline
   ↓
Understand organizational context
   ↓
Calculate risk
   ↓
Explain risk
   ↓
Change access
   ↓
Challenge identity
   ↓
Deploy decoy if necessary
   ↓
Freeze if confidence becomes high
```

The goal is not simply to produce more alerts.

The goal is to make the system **respond intelligently to the risk it observes**.

---

# Limitations

CrimGuard is intentionally honest about what a browser-based platform can and cannot know.

A website cannot independently observe everything happening on a user's computer.

For example, without endpoint or gateway integrations, it cannot reliably see:

* USB transfers
* Files copied directly through the operating system
* Activity in unrelated applications
* External browser tabs
* External email clients
* Unauthorized cloud-storage uploads outside the platform
* Physical badge access

These signals are therefore left unpopulated rather than fabricated.

Future integrations could provide additional signals through:

* Endpoint Detection and Response (EDR)
* Device management
* Badge systems
* Email gateways
* Data-loss prevention systems
* Network monitoring

---

# Security Philosophy

CrimGuard is based on a distinction between **probability and certainty**.

Most of the system deals with probability:

```text
Unusual behaviour
      +
Sensitive data
      +
No explanation
      ↓
High probability of malicious activity
```

A honeytrap trip is different:

```text
Fake file
      ↓
User modifies it
      ↓
Strong evidence of malicious intent
```

This allows CrimGuard to combine statistical detection with deterministic tripwires.

---

# The Central Idea

The entire project can be summarized in one sentence:

> **CrimGuard does not ask whether someone is behaving unusually; it asks whether their behaviour makes sense.**

An employee accessing hundreds of files because of an approved migration should not be treated like an insider stealing data.

An employee slowly increasing their access over months without any legitimate explanation should not escape detection simply because no individual day looks unusual.

CrimGuard combines **behaviour, context, identity, permissions, and response** into one continuously operating security system.

---

# Project Status

CrimGuard is implemented as a working prototype rather than a purely conceptual design.

The system includes:

* Functional file-sharing platform
* Authentication
* Role-based access control
* File permissions
* Risk database
* Risk engine
* 100-variable risk model
* Personal baselines
* Context-aware scoring
* Risk-based access limiting
* Behavioural biometrics
* Decoy projects
* Decoy files
* Canary credentials
* Departure protection
* Download protection
* Identity throttling
* Admin dashboard
* Activity logging
* Privacy controls
* Automated testing

The documented results and figures are generated from the working system rather than being purely theoretical examples.

---

# Final Statement

> **We are not trying to keep people out. Everyone here is already allowed in. That's the problem.**

CrimGuard is designed around that problem.

It watches for the difference between **someone doing their job** and **someone using their legitimate access against the organization**.

And when the evidence becomes strong enough, it does not merely send an alert.

**It acts.**
