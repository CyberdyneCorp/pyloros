## Decisions

The worker checks the active flag when claiming a due row. Stopping the delivery records the reason on the delivery itself. Explicit redelivery starts a fresh attempt budget and retains the historical attempts for the event.
