# Mixed authentication traffic on PostgreSQL

## Workload

A single Apple M3 Pro host (12 CPU cores, 36 GiB RAM) ran the Rust release, PostgreSQL 17.12 and the HTTP driver over loopback. Each trial used a fresh migrated database and 16 synthetic accounts. The API used RS256 signing, token revocation enforcement and Argon2id with 64 MiB, three iterations and four lanes. Hooks and webhooks were disabled. Each API process allowed two concurrent password hash jobs.

The driver warmed up all 16 accounts with a login, a refresh and an introspection. Each account had its own sequential HTTP client. In the two-process configuration, eight clients used each process and both processes shared a PostgreSQL primary. The driver scheduled requests independently of completions and gave each ticket to the next available client. The mix repeated one password login, one refresh and two introspections. Each response had to identify the expected account, and each refresh had to rotate its token.

Each phase offered 1,024 requests and drained before the next phase. The arrival rates were 64, 96, 128, 160 and finally 64 requests/s. The four trials used one, two, two and one API processes in that order. Reported latency includes waiting in the driver queue. This counts the delay an overloaded server imposes on arriving work. Repeating the 64 requests/s phase measures recovery once the backlog drains.

## Results

All 20,480 measured requests succeeded. Each trial produced the expected 1,296 sessions and 2,592 refresh-token rows including warmup. At 96 requests/s, both configurations held p99 below 87 ms. At 128 requests/s, one process accumulated a backlog in both runs. With two processes the driver queue peaked at one ticket even at 160 requests/s. Both configurations returned to a p99 below 86 ms in the final phase.

Each range covers the two repetitions of that configuration. A request completing just after the arrival window counts as a success and contributes to drain time. The CSV includes individual trials, per-operation p99, generator delay and API CPU time. [Trial data](capacity-trials.csv)

| Offered requests/s | API processes | Completed within window (of 1,024) | End-to-end p99 (ms) | Peak queued | Drain (ms) |
|---|---:|---:|---:|---:|---:|
| 64 | 1 | 1023 | 83.8–84.4 | 1 | 16.4–29.2 |
| 64 | 2 | 1023 | 83.6–84.6 | 1 | 17.5–17.6 |
| 96 | 1 | 1022 | 85.3–86.3 | 1 | 38.4–49.0 |
| 96 | 2 | 1023 | 84.8–85.6 | 1 | 37.5–38.0 |
| 128 | 1 | 845–849 | 2092.8–2131.1 | 161–164 | 2137.4–2177.5 |
| 128 | 2 | 1022 | 113.3–117.7 | 1 | 52.3–62.1 |
| 160 | 1 | 685 | 3626.3–3663.7 | 323–325 | 3741.7–3779.9 |
| 160 | 2 | 1020 | 182.4–196.6 | 1 | 64.4–121.9 |
| 64 (recovery) | 1 | 1023 | 83.2–83.8 | 1 | 17.0–17.3 |
| 64 (recovery) | 2 | 1023 | 83.2–85.5 | 1 | 17.1–18.4 |

The packaged binary had SHA-256 `17fa9667b7b8872be03b551f29e39f71014dc72a3cc534bc24a435a4d2059104`. Its backend source matches revision `fb70d84`. The 160 requests/s phase offered traffic for 6.4 seconds. Production sizing still needs sustained traffic with the deployed endpoint mix, ingress, background jobs, database topology and latency budget.

## One minute at 160 requests/s

Revision `7e07b24` ran the same mix for 60 seconds per configuration using 16 clients and a fresh PostgreSQL database each time. Two API processes ran first, then one. Each completed all 9,600 requests, including 2,400 logins, 2,400 refreshes and 4,800 introspections. Each database contained the expected 2,416 sessions and 4,832 refresh-token rows after warmup and measurement.

| API processes | Completed within 60 s | End-to-end p99 (ms) | Peak queued | Drain (s) | Throughput including drain (requests/s) |
|---:|---:|---:|---:|---:|---:|
| 1 | 6,078 | 34,555 | 3,507 | 35.317 | 100.72 |
| 2 | 9,596 | 177 | 1 | 0.061 | 159.84 |

Each row represents one local trial. The load generator and PostgreSQL shared the API host. The results cover this endpoint mix and password-hashing configuration. Production sizing still requires the deployed traffic mix and latency budget. [Per-operation measurements](capacity-minute.csv)

## Two-process baseline at 32 to 64 requests/s

Two repetitions at revision `1d42455` measured the login, refresh and introspection mix described above. Each repetition used a fresh PostgreSQL database, two API processes and 16 clients. Each phase offered 512 requests and allowed outstanding work to finish before the next phase. The arrival windows were 16, 10.7 and 8 seconds respectively.

| Offered requests/s | End-to-end p99 across repetitions (ms) | Completed within arrival window per repetition | Peak queued | Drain (ms) |
|---:|---:|---:|---:|---:|
| 32 | 82.09–82.56 | 512/512 | 1 | 0 |
| 48 | 77.91–78.09 | 512/512 | 1 | 0 |
| 64 | 81.80–82.03 | 511/512 | 1 | 17.01–17.38 |

All 3,072 measured requests succeeded. Including warmup, each database contained 400 sessions and 800 refresh-token rows. These short phases establish a repeatable local latency baseline for this workload. The tested Rust executable had SHA-256 `6c97706df5af72943a2dc1f2b143fb64d81ea128aec51472d0ccfaa8be88dd15`.

## Mixed-backend canary rehearsal

At revision `a4af506`, one Pyloros process and one migration reference process shared a PostgreSQL primary, RS256 keys and an issuer. Each of 16 synthetic accounts alternated between the two processes on successive requests. Two trials started with fresh databases and each offered 512 requests per phase. The driver included queueing and drain time in response latency.

| Offered requests/s | End-to-end p99 (ms) | Finished within arrival window (of 512) |
|---:|---:|---:|
| 32 | 1,223–1,565 | 502–504 |
| 48 | 4,863–5,850 | 304–378 |
| 64 | 8,257–8,644 | 241–246 |

All 3,072 measured requests succeeded. Across both trials, 519 refreshes rotated a credential issued by the other backend, and 1,040 introspections confirmed the account of a token issued by the other backend. Both directions succeeded at every rate. Each database ended with 400 sessions and 800 refresh-token rows, including warmup.

At 64 requests/s the mixed pair completed fewer than half the requests within the eight-second arrival window in both trials. This local result measures short periods of alternating traffic with hooks disabled. A production canary still needs measurements with its own traffic split, ingress, background work and latency budget.

### One minute at 24 requests per second

Two further trials used the same mixed pair and 16 clients. Each trial started with a fresh PostgreSQL database and scheduled 360 logins, 360 refreshes and 720 introspections over one minute. Latency includes time spent waiting for a client.

| Trial | Requests completed within the minute | End-to-end p99 | Time to finish remaining requests | Cross-backend refreshes | Cross-backend introspections |
|---|---:|---:|---:|---:|---:|
| 1 | 1,440 of 1,440 | 767 ms | 0 ms | 254 | 463 |
| 2 | 1,434 of 1,440 | 718 ms | 132 ms | 238 | 470 |

All 2,880 requests succeeded. Each trial exercised credential handoffs in both directions and ended with the expected 376 sessions and 752 refresh-token rows, including warmup. This measures one local minute with hook delivery disabled. Production canary sizing still requires the deployment's traffic mix and latency budget.

### Canary with one quarter of requests routed to Rust

Two local trials used one reference process, one Rust process and 16 clients. Each client sent every fourth request to Rust, starting at a different point in the cycle. Each phase scheduled 512 requests and drained before the next phase. Rust received 764 of the 3,072 measured requests (24.9%). Hooks and webhooks were disabled.

| Offered requests/s | Rust requests (trial 1 / 2) | Finished within window (trial 1 / 2) | End-to-end p99 (trial 1 / 2) | Drain (trial 1 / 2) |
|---|---:|---:|---:|---:|
| 24 | 127 / 128 | 441 / 428 | 3.49 / 4.48 s | 3.27 / 4.28 s |
| 32 | 127 / 124 | 340 / 339 | 7.59 / 8.58 s | 7.50 / 8.56 s |
| 24 | 128 / 130 | 445 / 422 | 3.66 / 4.69 s | 3.41 / 4.58 s |

All requests succeeded. Across both trials, 352 refreshes and 805 introspections used credentials issued by the other backend. Each database reconciled to 400 sessions and 800 refresh-token rows including warmup. Even at 24 requests/s, the pair needed additional time to finish each phase on this host. Measure the deployment's expected split against its latency budget before increasing canary traffic.

### Canary with a fixed Rust share for each operation

At 32 requests/s on the local PostgreSQL host, routing 75% of each operation to Rust gave an end-to-end p99 of 229–230 ms. Routing 25% to Rust gave a p99 of 8.96–9.05 s. In both repetitions the 75% split completed all 512 requests within the 16-second arrival window. The 25% split completed 326 and took another 8.88–8.93 s to drain.

The workload used one process per backend and 16 synthetic accounts. Each phase scheduled 128 logins, 128 refreshes and 256 introspections. The driver shuffled destinations within blocks of four requests separately for each operation, so the selected share also applied to expensive password checks. In a preliminary trial, routing by client turn sent every introspection in one phase to Rust. The table uses only the operation-balanced trials. Four fresh databases ran in the order 25%, 75%, 75%, 25%.

| Offered requests/s | Rust share | Finished within window, of 512 (trial 1 / 2) | End-to-end p99, ms (trial 1 / 2) | Drain, ms (trial 1 / 2) |
|---:|---:|---:|---:|---:|
| 24 | 25% | 435 / 435 | 3771 / 3780 | 3621 / 3646 |
| 24 | 75% | 512 / 512 | 225 / 225 | 0 / 0 |
| 32 | 25% | 326 / 326 | 8957 / 9049 | 8881 / 8927 |
| 32 | 75% | 512 / 512 | 230 / 229 | 0 / 0 |
| 24 (recovery) | 25% | 440 / 441 | 3792 / 3906 | 3628 / 3691 |
| 24 (recovery) | 75% | 512 / 512 | 223 / 221 | 0 / 0 |

All 6,144 requests succeeded. Across the four trials, 597 refreshes rotated credentials issued by the other backend and 1,404 introspections verified the expected account across backends. Both handoff directions succeeded in every phase. Each database reconciled to 400 sessions and 800 refresh-token rows. The Rust executable had SHA-256 `9312cc4fcbab135489c4c77b035c6bc200418bd3f6fe0978d8cb7b722d15d922`. These short loopback phases excluded hooks and webhooks. Production canary signoff still requires the deployment workload, ingress and latency objective.

### ReBAC revocation under concurrent reads

Two Rust API processes shared a PostgreSQL 17 primary. A client alternated 12 grants and 12 revocations of a library membership, distributing writes across both processes. After each HTTP 204, the driver issued eight concurrent permission checks to each process for a child collection that inherited access from the library. Eight background readers continuously checked an unrelated collection for the same user.

| Loopback trial | Post-commit checks | Post-commit check p95 | Unrelated checks | Unrelated check p95 |
|---|---:|---:|---:|---:|
| 1 | 384 | 57.7 ms | 1,280 | 20.7 ms |
| 2 | 384 | 54.8 ms | 1,212 | 18.1 ms |

Both replicas allowed every inherited check after a grant and denied every check after a revocation. Every unrelated check returned a denial. Latencies include the HTTP round trip as measured by the driver. Each trial used a fresh database and a single parent edge. The measured phases lasted 1.6–1.8 seconds. Sustained throughput on deployment-sized graphs remains to be measured.

### ReBAC checks across two active clients

Two Rust replicas and PostgreSQL 17 shared an Apple M3 Pro with the HTTP driver. One client issued ten direct membership checks per second, split equally between both replicas and between allowed and denied users. For 60 seconds a second client kept eight requests in flight, checking an inherited permission through 32 parent folders and their teams. Those checks all returned the expected denial. Each trial started with a fresh database containing 11,213 object relationships.

| Trial | Direct p99 before load | Direct p99 under load | Direct p99 after load | Inherited checks completed during load |
|---|---:|---:|---:|---:|
| 1 | 14.05 ms | 12.71 ms | 13.43 ms | 91,735 |
| 2 | 15.61 ms | 12.16 ms | 13.99 ms | 88,807 |

All 1,200 scheduled direct checks during the two load windows returned the expected decision. Direct latency includes driver scheduling delay. The before and after windows lasted 12 seconds each. These loopback measurements cover one graph shape with two clients and no concurrent writes. Deployment sizing still needs its own graph distribution, client mix and latency budget.

### Starting a ReBAC permission snapshot

Each permission check opens a read-only repeatable-read transaction. Opening it with both modes in the initial SQL statement removes one round trip to PostgreSQL. Statement traces confirmed the change on direct, inherited and wide-graph checks.

Two loopback trials per version added 2 ms of delay per database response chunk. Each trial sent 32 sequential requests per graph shape, alternating between two API processes. The table gives the range of trial medians.

| Permission check | Separate transaction setup | Single-statement setup |
|---|---:|---:|
| Direct team membership | 34.0–34.4 ms | 31.5–35.0 ms |
| Inherited document access | 45.7–47.7 ms | 42.9–46.3 ms |
| Denial across 32 parent folders and their teams | 158.8–159.8 ms | 155.4–157.1 ms |

The direct and inherited latency ranges overlap. Measure on the deployment's network and graph before estimating its latency savings.

In a separate 60-second run without injected delay, one tenant alternated 60 grants and 60 revocations while eight readers checked another tenant's wide graph. Both tenants used the same document, team and user identifiers. All 960 checks issued after acknowledged writes returned the expected inherited decision on both replicas. The unchanged tenant retained access throughout. The background readers completed 78,041 wide checks including warmup and drain. Each write had one audit entry. The p99 time from write acknowledgement until all eight decisions returned was 41.8 ms on this host.

### Reading the model and account eligibility

After checking the service client's grant, the permission evaluator fetches its model and the subject account's active status in one PostgreSQL statement. Two trials per version traced direct grants, inherited grants and wide denials. Every trace on the earlier build included a separate account lookup. The updated build returned eligibility with the model in all six traces.

Each trial also measured 32 sequential requests per shape with 1 ms of simulated delay per database response chunk. Direct-check trial medians were 16.8–17.2 ms before and 16.8–17.3 ms after. Inherited-check medians were 19.3–23.1 ms before and 21.5–22.2 ms after. Wide-denial medians were 67.5–88.7 ms before and 89.1–95.8 ms after. These trials demonstrate the statement reduction. Deployment latency and throughput still need measurement on the target graph and network.

### Checking membership across 32 teams

When all queued teams use the same single direct membership rule, Pyloros checks the eligible team IDs in one membership query. One paired loopback trial used a folder with 32 parent folders, each linked to a different team. The account belonged to none of those teams. The trace changed from 32 membership reads and four object-edge reads to one membership read and three object-edge reads.

With 1 ms of injected delay per database response chunk, 32 sequential wide denials had a median of 90.8 ms before grouping and 18.7 ms after. Both builds gave the same decisions for direct grants, short inherited grants and the wide denial. This measurement describes the tested graph and network conditions.

A separate two-replica trial gave each of two service clients a folder linked to the same 65 team IDs. One client kept a fixed membership. The other granted and withdrew membership on the first, 33rd and 65th teams, sometimes leaving two granting paths open. After each acknowledged write, both replicas checked both users in both clients. All 960 decisions matched the expected access. The other client's concurrent readers completed 73,134 checks, and the database recorded 60 grant audits and 60 withdrawal audits. The p99 time from write acknowledgement until all eight decisions returned was 20.16 ms in this loopback trial.

## Concurrent MFA verification

Sixteen accounts completed password-bound MFA simultaneously on a local Apple M3 Pro with PostgreSQL 17.12 and RS256 signing. Each wave submitted eight authenticator codes and eight recovery codes through warmed HTTP connections. Password verification and challenge issuance happened before timing. The timer covered the HTTP request to complete MFA, including session creation. Hooks and webhooks were disabled.

| Receiving Rust processes | Completions across two trials | Median latency per trial (ms) | p95 latency per trial (ms) |
|---:|---:|---:|---:|
| 1 | 128 | 11.97–12.63 | 25.33–27.11 |
| 2 | 128 | 12.05–12.96 | 24.41–26.73 |

All 256 sessions authenticated on the backend that issued the challenge. PostgreSQL recorded one session, one successful MFA audit and the expected factor consumption per account. Each trial used a fresh database and four waves. With two receiving processes, each handled eight requests per wave and alternated factors between waves. These short bursts measure completion latency at a fixed concurrency. Sustained capacity and production latency targets remain open.

Rust executable SHA-256: `af2b79ed968f986ad1849b60092178e4964787bdf95f29a27d67ace4d721ee56`.
