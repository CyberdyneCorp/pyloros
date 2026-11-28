## Context

The subscription and its first item can both contain billing information.

## Decisions

Select entitlement metadata as one pair so a plan from another metadata source cannot be combined with the selected product. Resolve expiry independently of product selection. Use integral Unix seconds, including zero.

## Verification

Exercise conflicting dates, item fallback and missing dates. Verify the stored product, plan, reference and expiry on a disposable PostgreSQL database.
