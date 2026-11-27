## Decisions

Read policy statements and conditions from the selected provider and retain their ordering. Preserve role session limits, timestamps, policy versions, and provider identifiers. Keep these read endpoints under the same operator authorization as the group inventory.

## Verification

Compare empty and populated PostgreSQL inventories, historical statement data, partial chain reads and provider failures. Exercise all three inventory reads together with the original IAM console.
