---
schema: ego.grants/1
id: grants
title: Human grant verb table
notes: >
  A grant is recognised deterministically by the human prompt hook: the whole prompt is normalized (lowercase, accents
  folded, punctuation collapsed) and each phrase is matched as a whole-word sequence. A negation token within the
  negation window before the phrase cancels the grant. A grant moves one ASK capability to ALLOW for the current task
  only and expires with the task or the session, whichever ends first. Grants never touch DENY and never reach absolute
  denies. Intent recognition for routing is a separate, fuzzy mechanism (lexicon/); this table is exact.
negation_window_tokens: 4
negations:
  - "don't"
  - "do not"
  - "never"
  - "not"
  - "no"
  - "ne"
  - "pas"
  - "jamais"
  - "sans"
  - "without"
grants:
  - capability: git.local.commit
    phrases: ["commit this", "commit it", "commit the changes", "you can commit", "go ahead and commit", "commit ca", "commit ça", "tu peux commit", "tu peux commiter", "fais le commit", "commite"]
  - capability: git.local.amend
    phrases: ["amend the commit", "amend it", "you can amend", "tu peux amend", "amende le commit"]
  - capability: git.local.rebase
    phrases: ["rebase it", "you can rebase", "rebase the branch", "tu peux rebase", "fais le rebase"]
  - capability: git.local.reset
    phrases: ["reset it", "you can reset", "tu peux reset"]
  - capability: git.local.restore
    phrases: ["discard the changes", "discard my changes", "restore the files", "you can discard", "tu peux jeter les changements", "annule les changements"]
  - capability: git.local.clean
    phrases: ["clean untracked files", "you can git clean", "tu peux nettoyer les fichiers non suivis"]
  - capability: git.local.branch.delete
    phrases: ["delete the branch", "delete the local branch", "you can delete the branch", "supprime la branche"]
  - capability: forge.issue.assign
    phrases: ["assign it to me", "assign me", "assign the issue to me", "assigne moi", "assigne la moi", "assigne-moi"]
  - capability: forge.issue.comment
    phrases: ["post the criteria to the issue", "comment on the issue", "add the comment to the issue", "you can comment on the issue", "poste les criteres dans l issue", "commente l issue"]
  - capability: forge.review.thread.resolve
    phrases: ["resolve the thread", "resolve the review thread", "you can resolve the thread", "resous le fil", "resous le thread"]
  - capability: forge.review.comment
    phrases: ["reply to the review", "answer the review comment", "reply to the comment", "reponds au commentaire", "reponds a la review"]
  - capability: db.local.drop
    phrases: ["drop the local database", "you can drop the database", "supprime la base locale"]
  - capability: container.prune
    phrases: ["prune docker", "you can prune", "nettoie docker"]
  - capability: k8s.local.delete
    phrases: ["delete the local cluster", "delete the namespace", "you can delete the cluster", "supprime le cluster local"]
  - capability: ego.skills.install
    phrases: ["install the skill", "install the skills", "you can install the skill", "installe le skill", "installe les skills"]
  - capability: ego.pin.change
    phrases: ["upgrade ego", "rollback ego", "you can upgrade ego", "mets a jour ego", "upgrade the harness", "rollback the harness"]
  - capability: command.privileged
    phrases: ["you can use sudo", "run it with sudo", "tu peux utiliser sudo"]
  - capability: command.network-tool
    phrases: ["you can curl it", "you can download it", "fetch it with curl", "tu peux le telecharger", "tu peux curl"]
---
# Human grant verb table

Grants are the only way a human widens authority for a task, and only from ASK to ALLOW. The table is exact on
purpose: a grant is authority, and authority is never inferred from fuzzy intent. Organizations may add phrases and
languages in their overlay for existing ASK capabilities; they cannot add a grant for a DENY or absolute capability.
