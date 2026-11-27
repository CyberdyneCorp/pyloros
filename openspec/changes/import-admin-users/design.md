## Approach

Parse the multipart envelope before operator authentication and validate the selected CSV afterwards. Preserve record order and field-specific errors. Reuse the single-account wallet and password implementation. Successful rows create account activity and webhook deliveries. Commit the batch audit with the imported accounts.
