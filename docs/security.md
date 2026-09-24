# Security

## KEK handling

- The key-encryption key (KEK) comes from `CF_KEK` (base64) or `CF_KEK_FILE`. It is never stored in the database or logged, and config errors never echo it.
- Each secret is sealed with its own AES-256-GCM data key. The data key is wrapped by the KEK. The KEK id (`static-` plus 16 hex characters of a SHA-256 of the key) is stored in every blob and bound as authenticated data.
- At startup the server decrypts the `crypto.canary` setting, or writes it on first boot. With a wrong KEK the server keeps serving, but `/readyz` returns 503 with `kek: failed` and every secret read fails with a clear error. Nothing is overwritten.
- Escrow the KEK outside the server. Without it, backups cannot be decrypted.
