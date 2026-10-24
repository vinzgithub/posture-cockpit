<div align="center">

# 🛡️ Posture Cockpit

### Your website works, your emails get delivered… but how well is your domain protected?

**Understand · Fix · Verify · Keep track**

**English** · [**Français**](README.fr.md)

![Version](https://img.shields.io/badge/version-0.6.0-126caa) ![Docker](https://img.shields.io/badge/install-Docker-2496ED) ![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-0d355d)

<img src="docs/images/en/hero.png" alt="Posture Cockpit displayed on a computer and a phone" width="100%">

<sub>The screenshots feature the fictional domain <code>menuiserie-dupont.example</code>. They are a demonstration, not the findings for a real organization.</sub>

</div>

---

## What is Posture Cockpit?

When you run a website or use email addresses on your own domain, you probably don't spend much time thinking about the security settings behind them. As long as the website loads and messages arrive, everything seems fine.

But a certificate might be close to expiring, your website might be missing useful protections, or your domain might not be sufficiently protected against email spoofing.

**Posture Cockpit helps you find out.** Enter a domain name and it examines the protections it can observe: **website, HTTPS certificates, email and DNS**. It then gives you a readable assessment, highlighting what needs attention and, where possible, how to improve it.

The idea is simple: **don't just tell people something is wrong. Help them understand why it matters and what they can do next.**

It's a self-hosted application with source code available on GitHub. You run it **on your own server**. It doesn't require ChatGPT, an AI subscription or an API key.

## Who is it for?

Anyone managing their own domain, including **craftspeople, small businesses, associations, local organizations** and the people helping them — an IT colleague, a web agency or a service provider.

You don't need to know what SPF, DMARC or TLS mean to read the assessment. If you already work in IT or cybersecurity, the technical findings and references are there too.

## A practical example

Imagine a small woodworking business using `menuiserie-dupont.example` for its website and email.

Its website is online. Customers can write to the business. But how can it tell whether its domain has the right defenses against forged emails, or whether its website uses the expected HTTPS protections?

With Posture Cockpit:

1. **Add the domain** and run an assessment.
2. **Read the results**: what's configured properly, what needs improvement and what couldn't be checked.
3. **Understand the next steps**: why does a setting matter, and is it something you can fix yourself or should ask your provider to handle?
4. **Make the change**, then use the verification button to see whether the specific check now passes.
5. **Follow what happens next** using the history and scheduled assessments.

For example, if a domain's DMARC policy needs work, Posture Cockpit explains what it does and may guide you through an initial improvement. It won't change anything for you: **you stay in control**, and some email protections should be rolled out gradually to avoid disrupting legitimate mail.

## What you'll find in the application

### An assessment you can understand

Posture Cockpit shows which protections are in place, which findings are important and which checks could not be completed. It also provides a **score and coverage figure**, so you know how much of the applicable assessment was actually measured.

**A score of 90/100 does not mean a business is 90% secure.** It summarizes only what this tool was able to check. It doesn't replace a full security audit or penetration test.

### Clear guidance, not just a warning list

<img src="docs/images/en/plan-dns.png" alt="An example of step-by-step DNS guidance">

When a DNS setting needs changing, the tool can guide you through **OVHcloud, Gandi, IONOS or Cloudflare** and prepare the record values to copy. If the fix belongs to your hosting provider or web agency, it can prepare a **message for you to send them**.

Always review changes before applying them, especially to email: the wrong DNS change can interfere with legitimate outgoing mail.

### A PDF you can share

| Summary | Details |
|:--:|:--:|
| <img src="docs/images/en/report-1.png" alt="First page of a Posture Cockpit PDF report" width="100%"> | <img src="docs/images/en/report-2.png" alt="Detailed page of a Posture Cockpit PDF report" width="100%"> |

The report starts with the essentials: what was found and what could be improved. Technical details and references — including **ANSSI** guidance and **RFCs** — are included for those who need them.

### It keeps working after the first assessment

Since **v0.5.0**, Posture Cockpit has kept successive results, compared compatible observations and supported **daily, weekly or monthly scheduled assessments**.

The **Events** area tracks certain security regressions, gaps in measurement coverage and repeated failures of scheduled checks.

**Please note:** events stay inside the application. This version does **not** automatically send emails, SMS messages or external notifications.

[Scheduled assessments](docs/user/ANALYSES_PROGRAMMEES.md) · [Events and alerts](docs/user/EVENEMENTS.md)

### Mission Control: what changed, what should I do next?

Since **v0.6.0**, a portfolio view helps you spot domains that need attention. Each domain has a **Mission Control** page explaining what changed since comparable observations, which fixes to prioritize and what the last scan could not establish.

The **“What if…?”** simulator lets you select several proposed corrections (including successive DMARC stages) and see *conditional* outcomes before doing anything. It does **not** change your DNS or servers, and a new scan is still needed to verify a real improvement.

**Fictional example:** [download a Mission Control PDF report](docs/examples/posture-cockpit-mission-control-demo.en.pdf). Generated by the v0.6.1 candidate for `menuiserie-dupont.example`, with no real organization scanned. Some actions have an unknown effect; projections still need confirmation.

## What does Posture Cockpit actually check?

| Area | In everyday language |
|---|---|
| **Email** | Who is allowed to send messages using your domain? Which anti-spoofing protections are published? Checks include SPF, DKIM, DMARC, MTA-STS and TLS-RPT, within the limits of what can be observed. |
| **Website** | Does the site redirect to HTTPS correctly? Are browser security settings such as HSTS and CSP present? |
| **HTTPS certificates** | Is the certificate valid? Is it nearing expiry? What about the TLS protocols and key properties that the tool checks? |
| **DNS** | Are name servers, DNSSEC and CAA records configured as expected? |

There are **20 built-in checks in v0.6.0**. Some don't apply to every domain; others may be inconclusive if a server doesn't respond. Posture Cockpit distinguishes between **“not applicable”** and **“could not be checked”**: an uncompleted check is never treated as a success.

[How scores and coverage are calculated](docs/user/SCORING.md)

## Try it before assessing your own domain

A **fictional demo domain** is available during first-account setup. It lets you explore the interface, explanations and reports without using a real business domain.

You still need to install Posture Cockpit to open that demo: **there is no hosted online demo service**.

## Getting started

Posture Cockpit runs on a server or computer with **Docker Engine** and **Docker Compose 2.24 or newer**. Ready-built images are available for **AMD64 and ARM64**, so you don't have to install Python, build the software or clone the repository when using Docker.

For a **new installation**, run:

```bash
mkdir posture-cockpit && cd posture-cockpit
curl -fsSLO https://raw.githubusercontent.com/vinzgithub/posture-cockpit/v0.6.0/compose.yaml
docker compose up -d
```

Get the one-time code needed to create the first account:

```bash
docker compose logs posture-cockpit
```

Open `http://<server-address>:8080/setup`, enter the code and create the administrator account. You can then explore the demo or add a domain of your own.

**Important:** don't expose the application to the public Internet over plain HTTP. Use a properly configured **HTTPS reverse proxy** for remote access.

Already running an older version? **Don't use the new-install steps as an upgrade guide.** Back up your existing installation and follow the documented process. A transition from v0.4.x to v0.5.0 or later needs special care around the database schema and scheduler; v0.6.0 keeps schema 5.

📖 [Full installation, configuration, backup and upgrade guide](docs/user/INSTALLATION.md) · [Published v0.6.0 release](https://github.com/vinzgithub/posture-cockpit/releases/tag/v0.6.0)

## What Posture Cockpit does — and doesn't do

**It observes; it doesn't attack.** It makes DNS queries, web and TLS connections, and reads selected public resources. It does not perform penetration testing, scan every port or change the configuration of the domains it checks.

For public Internet domains, outbound web connections are restricted to **public IP addresses** and **ports 80 and 443**, with checks designed to stop DNS or redirect tricks from reaching private networks. Internal-network assessments are a separate feature, **disabled by default** and available only after explicit administrator configuration.

Application access includes user accounts, **TOTP two-factor authentication**, rate limits against repeated login attempts and an audit trail. Results remain on your self-hosted instance; assessments naturally generate network requests to the services being examined.

**One important email precaution:** a domain without an MX record may still send email through a third-party provider. Before publishing a restrictive SPF record such as `v=spf1 -all`, make sure the domain genuinely sends no mail.

[Security information](SECURITY.md) · [Internal-network assessments](docs/user/INSTALLATION.md#audits-of-internal-networks)

## For those who want to go further

Posture Cockpit provides an **API** for integrating results into other tools, including [Home Assistant](docs/user/HOME_ASSISTANT.md). Developers can add checks through [Python extensions](docs/developer/EXTENSIONS.md).

You can explore the [architecture documentation](docs/developer/ARCHITECTURE.md), or [open a GitHub issue](https://github.com/vinzgithub/posture-cockpit/issues) if you find a problem or want to suggest an improvement.

## License and credits

The source is published under the **[PolyForm Noncommercial 1.0.0 License](LICENSE)**. It allows the purposes described as noncommercial by the license; see the [commercial license terms](COMMERCIAL-LICENSE.md) for other uses.

**Project concept, direction and validation: Vincent Fournet.** Development carried out with the assistance of AI tools, under his direction.

Copyright © 2026 Vincent Fournet.

---

<div align="center"><sub>Posture Cockpit v0.6.0 — Understand what protects your domain, and what to do when something is missing.</sub></div>