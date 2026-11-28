## Why
A migration package can group registrations under a different date when its PostgreSQL driver selects a different session time zone.

## What Changes
Allow the deployment to carry the reference registration calendar alongside its other migration assets.

## Capabilities
### Modified Capabilities
- `admin-analytics` defines how the migration launcher supplies the reporting calendar.

## Impact
This affects the packaged launcher's configuration of registration analytics.
