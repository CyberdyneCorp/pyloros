## Decisions

Apply the limit to the accumulated body before dispatch. Verify accepted bytes with an echo handler and require the ordinary size-error response when a final chunk takes the body over the limit.
