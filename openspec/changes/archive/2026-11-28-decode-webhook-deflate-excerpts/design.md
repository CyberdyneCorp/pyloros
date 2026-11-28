## Decisions

Reuse the streaming HTTP decoder for raw and zlib-wrapped deflate. A webhook needs the first 1,024 decoded bytes, while a provider exchange needs a complete bounded document. Keep both policies explicit and enforce their limits during decompression.
