---
schema: ego.mode/1
id: PRODUCTION_ADVISORY
kind: authority
title: Production advisory
overrides:
  - capability: fs.repo.write
    verdict: DENY
  - capability: fs.repo.delete
    verdict: DENY
  - capability: fs.repo.rename
    verdict: DENY
  - capability: command.local-mutation
    verdict: DENY
  - capability: command.destructive
    verdict: DENY
  - capability: git.local.commit
    verdict: DENY
  - capability: db.local.migrate
    verdict: DENY
  - capability: k8s.local.apply
    verdict: DENY
---
# PRODUCTION_ADVISORY

Analyse, explain, compare, recommend, plan. Nothing executes: local mutation is denied as well as production mutation,
so a production incident discussion cannot drift into an unreviewed change. Read-only forge and observability access
remains available.
