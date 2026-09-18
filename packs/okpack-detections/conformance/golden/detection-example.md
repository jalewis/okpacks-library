---
type: detection
id: sigma-example
title: "Suspicious PowerShell Download Cradle"
detection_format: sigma
rule_level: high
rule_status: stable
logsource: "windows / process_creation"
covers_techniques: [T1059.001]
author: "Example Author"
sources: [SigmaHQ]
---
# Suspicious PowerShell Download Cradle

Detects a PowerShell download cradle. Covers [[T1059.001]].

> Example golden — a Sigma detection page seeded from an open ruleset.
