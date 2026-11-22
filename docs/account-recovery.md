# Account recovery design

**Status: recovery-code setup, rotation, and password reset are implemented. Email delivery and passkey enrollment are not implemented.**

## Preserve the existing data-key model

Each account has a random data-encryption key (DEK). The finance payload is encrypted with that DEK. Today, the DEK is wrapped by a key derived from the user's password. Changing or resetting a password must re-wrap the same DEK; generating a new DEK would make existing finance data unreadable.

Ledgerly now supports a recovery-code envelope in addition to the password envelope:

- **Password:** keep the current password-derived envelope.
- **Recovery key (implemented):** generate a random 256-bit recovery code and wrap the DEK with a key derived from it. Store the random salt and authenticated encrypted DEK envelope, never the recovery code itself. Let the user rotate it after signing in.
- **Passkey (optional):** where the browser and authenticator support WebAuthn's `prf` extension, derive a wrapping key on the client and create a separate DEK envelope for that credential. Each registered passkey needs its own envelope because the PRF result is credential-specific.

The server stores public WebAuthn credential data and wrapped DEK envelopes, never a passkey private key. WebAuthn PRF output is generated in the browser. After a valid passkey assertion, the browser can use that output to unwrap the DEK and send the DEK over HTTPS to establish the app's normal server-side session. Ledgerly's current API decrypts finance data on the server, so passkeys would not make the server blind to plaintext while serving requests. This keeps the current encryption model; moving to client-side-only decryption would be a separate architecture change.

## Recovery flow

1. The user enters their account email and recovery code. The email identifies the account; possession of the recovery code proves the user can unlock its DEK. Email addresses are not verified yet, and no email service is configured.
2. The user chooses a new password. The app derives a new password wrapping key and re-wraps the same DEK.
3. The app rotates the recovery code, returns a new one-time display, and invalidates active process-local sessions. The user must save the replacement code.
4. The user signs in with the new password. They can later replace the recovery code from **Security & recovery**.

If the user loses both the password and recovery code, the encrypted finance data is unrecoverable. The registration, legacy-account setup, and recovery screens explain that the code must be saved. A code can be replaced from **Security & recovery** while signed in.

## Passkey recommendation

Use platform-neutral WebAuthn passkeys, not an Apple-only authentication API. Apple passkeys can work well for users whose credentials sync with iCloud Keychain, and Apple's developer docs describe using the WebAuthn PRF extension to derive a symmetric key. PRF support is not guaranteed by every browser or authenticator, so feature-detect it and keep the recovery code as the cross-platform fallback. A passkey alone authenticates a user; it does not automatically recover a password-wrapped DEK.

Before enabling PRF-based recovery, test registration, assertion, and consistent key recovery across supported browsers, Apple devices, and at least one non-Apple passkey provider. If an enrolled credential is deleted or cannot reproduce its PRF output, the recovery code must still work.

References: [W3C Web Authentication](https://www.w3.org/TR/webauthn/) · [Apple: Authentication Services updates](https://developer.apple.com/documentation/updates/authenticationservices) · [Apple: Passkeys](https://developer.apple.com/passkeys/)

## Required safeguards before implementation

- Serve recovery and passkey ceremonies only over HTTPS, validate WebAuthn challenges, origins, and relying-party IDs, and make challenges short-lived and single-use.
- Rate-limit login, email recovery, and credential-management endpoints.
- Notify users when a password, recovery code, or passkey changes; provide passkey revocation and recovery-code rotation.
- Expire recovery links, invalidate sessions after recovery, and avoid logging secrets, codes, PRF outputs, or wrapped keys.
- Back up MongoDB and practice restoring it. Recovery cannot restore data that has been lost from the database.
