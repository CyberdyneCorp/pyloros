## Delivery

- [x] Resolve active clients and validate registered callbacks, including native loopback listeners.
- [x] Decide when hosted login or fresh authentication is required and construct the return URL.
- [x] Validate authenticated grants and issue single-use codes for approved scopes and resources.
- [x] Connect browser sessions, hosted login and approved grants to the GET authorization endpoint.
- [x] Verify signed consent submissions, merge approved scopes and redirect on approval or denial.
- [x] Issue consent tickets and serve the shared consent page.
- [x] Redeem authorization codes through the HTTP endpoints in both migration directions and reject replay.
- [x] Verify interactive consent and hosted login journeys with the shared frontend.
