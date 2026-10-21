---
schema: ego.mode/1
id: PRODUCTION_ADVISORY
kind: authority
title: Production advisory
overrides:
  - capability: fs.repo.write
    verdict: DENY
  # (a secret-bearing file is a file of the checkout: the mode that writes none refuses this one too)
  - capability: fs.env-file.write
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
  # ...AND EVERY ADMINISTRABLE WRITE (ADMIN_GOVERNED). "Nothing executes" has to hold for the pushes and the forge writes an organization has
  # enabled too: a mode may narrow an ADMIN_GOVERNED capability and may never widen one, and with no organization policy these are a no-op
  # (they are DENY already). The test of this file derives the list from the ADMIN_GOVERNED capabilities.
  - capability: git.remote.push
    verdict: DENY
  - capability: git.remote.push.force
    verdict: DENY
  - capability: git.remote.tag.push
    verdict: DENY
  - capability: git.remote.branch.delete
    verdict: DENY
  - capability: git.remote.tag.delete
    verdict: DENY
  - capability: forge.pr.create
    verdict: DENY
  - capability: forge.pr.modify
    verdict: DENY
  - capability: forge.pr.close
    verdict: DENY
  - capability: forge.pr.merge
    verdict: DENY
  - capability: forge.pr.approve
    verdict: DENY
  - capability: forge.release.publish
    verdict: DENY
  - capability: forge.release.delete
    verdict: DENY
  - capability: forge.repo.delete
    verdict: DENY
  - capability: forge.branch.protection.modify
    verdict: DENY
  - capability: forge.repo.permissions.modify
    verdict: DENY
  - capability: forge.issue.create
    verdict: DENY
  - capability: forge.issue.edit
    verdict: DENY
  - capability: forge.issue.transition
    verdict: DENY
  - capability: forge.issue.close
    verdict: DENY
  - capability: forge.issue.delete
    verdict: DENY
  - capability: forge.api.mutate
    verdict: DENY
---
# PRODUCTION_ADVISORY

Analyse, explain, compare, recommend, plan. Nothing executes: local mutation is denied as well as production mutation,
so a production incident discussion cannot drift into an unreviewed change. Read-only forge and observability access
remains available.
