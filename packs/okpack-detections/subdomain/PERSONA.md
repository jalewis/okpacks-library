## Installed domain: detections & mitigations (the defensive-response layer)

This vault also tracks the **defensive layer**: `detection` rules (namespace `detections/`) seeded
`no_agent` from the open SigmaHQ ruleset, and `course-of-action` mitigations (ATT&CK M####) in
`entities/`. Each detection carries `covers_techniques` — the ATT&CK technique(s) it fires on — as
`[[technique]]` links, so the vault answers "which techniques do we detect / mitigate, and where are
the gaps" when composed with an actor pack. Keep a detection page to the rule's essentials (format,
logsource, level, the techniques it covers, false-positive notes); link — don't paste — the full rule
when it lives in a repo. Never claim coverage a rule doesn't actually provide.
