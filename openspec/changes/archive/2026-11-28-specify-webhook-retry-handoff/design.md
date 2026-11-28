## Decisions

Use the existing jittered retry schedule. A worker taking ownership reads the due time from the shared delivery row. The PostgreSQL regression supplies claim times on either side of that deadline.
