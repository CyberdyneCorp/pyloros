## Decisions

Apply the existing document decoder to the bytes already accepted by the session handler. Parse only the relevant fields for validation and retain the original submitted JSON for diagnostics. Share this validation with the existing field reader.
