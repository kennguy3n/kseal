# Showcase screenshots — captions

All captured from a live kseal console (`localhost:5173`) backed by a running server, with
real seeded tenants, attestations, trust decisions and control-plane mutations. Timestamps
read `2026-06-15` (the live run date).

| # | File | Tenant / persona | What it shows |
|---|------|------------------|----------------|
| 01 | `01-dashboard-gameforge.png` | GameForge / SOC | Tenant overview — apps, webhooks, events(24h), trust sessions, protection live |
| 02 | `02-events-gameforge.png` | GameForge / SOC | Risk + policy-decision event stream across builds/regions |
| 03 | `03-policies-gameforge.png` | GameForge / SOC | Active trust policy — risk thresholds, enforcement, module set |
| 04 | `04-apps-gameforge.png` | GameForge / SOC | App inventory + per-app build registry |
| 05 | `05-killswitch-armed-gameforge.png` | GameForge / SOC | Signed remote kill switch — armed |
| 06 | `06-killswitch-disabled-gameforge.png` | GameForge / SOC | Signed remote kill switch — disabled |
| 07 | `07-siem-gameforge.png` | GameForge / SOC | SIEM connector configuration |
| 08 | `08-audit-trail-gameforge.png` | GameForge / SOC | Hash-chained audit trail — chain verified, kill-switch entries |
| 09 | `09-app-detail-gameforge.png` | GameForge / SOC | App detail incl. Builds panel (post-PR #54 fix; correct 2026 dates) |
| 10 | `10-fleet-anomaly-fitpulse.png` | FitPulse / NoOps founder | **Fleet Anomaly Guard** — `fitpulse-3.9` `root_jailbreak` surge, 422 obs, auto step-up |
| 11 | `11-data-processing-meditoken.png` | MediToken / compliance | Data-processing registry — abuse-prevention + clinical-access, aggregates-only |
| 12 | `12-masvs-evidence-meditoken.png` | MediToken / compliance | **MASVS evidence 8/8** from build-proof `meditoken-2.2.0-rasp` + applied transforms |
| 13 | `13-audit-trail-meditoken.png` | MediToken / compliance | Hash-chained audit — data-processing mutations, chain verified |
| 14 | `14-canary-monitor-shopswift.png` | ShopSwift / release eng | Canary 25% rollout — candidate active, auto-rollback armed, last-known-good |
| 15 | `15-events-novapay.png` | NovaPay / fintech | Global decision stream across 8 regions |
| 16 | `16-events-highrisk-filter-novapay.png` | NovaPay / fintech | One-click High-risk triage — 3 root/jailbreak events |
| 17 | `17-webhooks-novapay.png` | NovaPay / fintech | Signed fraud webhook subscription |
| 18 | `18-dashboard-novapay.png` | NovaPay / fintech | Fintech overview — 6000 events/24h, 834 sessions, trust-level split |
| 19 | `19-siem-novapay.png` | NovaPay / fintech | Splunk HEC connector — named `risk_signals` egress, sealed secret |
