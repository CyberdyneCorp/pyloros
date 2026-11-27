## Why

A CLI that receives a loopback code needs to finish signing in against either backend during migration.

## What Changes

Add the HTTP exchange for CLI login codes and verify that both services can redeem each other's codes.

## Impact

The CLI uses the existing PostgreSQL code and session tables, signing configuration and login rate limit.
