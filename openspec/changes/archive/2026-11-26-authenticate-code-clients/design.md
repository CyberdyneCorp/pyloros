## Decisions

Verify the stored Argon2 PHC string for confidential clients. Evaluate the previous hash only inside its rotation window. Bound concurrent verification jobs and run them outside async executor threads. Check grant membership after authenticating the client. Return a protocol refusal separately from infrastructure failures.
