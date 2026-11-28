## Approach

Parse the multipart envelope before operator authentication and validate the selected CSV afterwards. Preserve record order and field-specific errors. Reuse the single-account wallet and password implementation. Successful rows create account activity and webhook deliveries. Commit the batch audit with the imported accounts.

Read the multipart charset from the envelope. Decode the selected text field only after collecting all its bytes so that a multibyte character can span chunks. Preserve the original bytes of file parts for CSV parsing.
