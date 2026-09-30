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
  # ...AND EVERY OTHER WAY THE CHECKOUT CHANGES. The mode says nothing executes and denied `git commit`, while
  # `git merge`, `git cherry-pick`, `git switch`/`checkout` (which rewrite every tracked file to another branch's
  # content), `git stash`, `git pull` and staging were all open — so a production incident discussion could still
  # drift into an unreviewed change (exit review 10).
  - capability: git.local.merge
    verdict: DENY
  - capability: git.local.cherry-pick
    verdict: DENY
  - capability: git.local.checkout
    verdict: DENY
  - capability: git.local.stash
    verdict: DENY
  - capability: git.local.stage
    verdict: DENY
  - capability: git.local.branch.create
    verdict: DENY
  - capability: git.local.tag
    verdict: DENY
  - capability: git.remote.pull
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
