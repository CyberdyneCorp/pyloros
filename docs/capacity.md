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
