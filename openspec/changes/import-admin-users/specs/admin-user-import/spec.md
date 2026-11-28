## ADDED Requirements

### Requirement: Import password accounts from CSV

The API SHALL accept administrative user imports with email and password columns and return a result for each submitted data record.

#### Scenario: Import a mixed batch

- **WHEN** an operator uploads valid rows alongside invalid or duplicate entries
- **THEN** return row numbers, normalized successful accounts and individual failures. Persist the successful verified accounts and report the counts.

#### Scenario: Reject an unusable file

- **WHEN** the upload lacks required columns, exceeds 1000 data records or contains invalid UTF-8
- **THEN** reject the import before creating an account.

#### Scenario: Audit the batch

- **WHEN** an import commits
- **THEN** record the aggregate counts in the operator audit and identify each created account's source row in its authentication event.

#### Scenario: Ignore an unfinished final form part

- **WHEN** an upload ends before its final part is complete
- **THEN** use the last completed file field, or apply the missing-file response if none was supplied and the caller is authorized.

#### Scenario: Roll back a conflicting batch

- **WHEN** another transaction creates an account after the import has checked its email and before it can insert the account
- **THEN** return a server error and roll back all account and audit writes from the losing batch.

#### Scenario: Return the submitted multipart text in a file-type error

- **WHEN** the operator submits the file field as text using a declared multipart charset
- **THEN** return HTTP 422 with the decoded text as the validation input. Use UTF-8 by default and Latin-1 when the text cannot be decoded. Interpret uploaded CSV file bytes as UTF-8 independently of the form charset.

#### Scenario: Decode the multipart field name before selecting the upload

- **WHEN** the declared form charset decodes a part name to a value other than `file` and no other part supplies the file
- **THEN** report the missing field and create no accounts.
