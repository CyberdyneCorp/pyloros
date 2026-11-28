## Why

A failed passkey ceremony insert can be reported as an inventory outage on authenticated options routes.

## What Changes

Return HTTP 500 on explicit commit rejection for all three options flows. Withhold browser and native binding material until the ceremony commits.

## Impact

Passkey registration and reauthentication options adopt the same commit rejection response as login options.
