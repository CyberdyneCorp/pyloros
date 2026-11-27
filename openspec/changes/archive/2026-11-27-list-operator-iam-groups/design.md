## Decisions

Use the configured IAM provider for each request. Project the provider's group identifiers, timestamps, policy references and membership counts into the existing operator response.

## Verification

Compare PostgreSQL and chain-backed results for empty and populated inventories, authorization failures, method handling and unavailable providers. Exercise the existing clients.

## Console dependency

The IAM console loads the policy, group and role inventories together. Verify the group endpoint with the CLI independently, then exercise the full console when all three inventory reads are available on Rust.

The original CLI consumed the Rust inventory. The unchanged console displayed a Rust group, member count and attached policy in a mixed deployment using reference policy and role reads. The companion inventory change tracks the all-Rust console check.
