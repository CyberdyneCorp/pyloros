## Delivery

- [x] Resolve active clients and validate registered callbacks, including native loopback listeners.
- [x] Decide when hosted login or fresh authentication is required and construct the return URL.
- [x] Validate authenticated grants and issue single-use codes for approved scopes and resources.
- [x] Connect browser sessions, hosted login and approved grants to the GET authorization endpoint.
- [ ] Implement consent tickets, approval and denial with the existing browser workflow.
- [x] Redeem authorization codes through the HTTP endpoints in both migration directions and reject replay.
- [ ] Verify interactive consent and hosted login journeys with the shared frontend.
