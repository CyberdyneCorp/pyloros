# delete-operator-iam-groups

Remove ordinary IAM groups and their memberships and policy attachments.

During a shared-database handoff, reconcile a deletion using the group inventory and operator audit history. A second writer can delete the group immediately after the first writer’s transaction rolls back. In that case, the group disappears and the audit belongs to the second deletion. A policy detachment can also remove inherited access while leaving the group present. Inspect the group’s attached policy IDs when investigating that outcome.
