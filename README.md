# sombe-chat-crypto

End-to-end encryption for SOMBE ChatPay messages, published so anyone can read and
check it. It is a thin layer over [vodozemac](https://github.com/matrix-org/vodozemac)
(Olm), exposed to Android through [UniFFI](https://github.com/mozilla/uniffi-rs). It holds
no business logic: no networking, no storage, no payments.

- [PROTOCOL.md](PROTOCOL.md): identity signed by the wallet, one time keys, envelope,
  content format, session rules, identity pinning, safety number.
- [vectors/v1.json](vectors/v1.json): test vectors for every format.

## Build and test

```bash
cargo test                      # Rust tests and test vectors
cargo run --bin make-vectors    # only to regenerate the vectors (a protocol change)
```

The CI also compiles the generated Kotlin bindings with Kotlin 1.7.21 (the app's
version) and runs them on the JVM, then builds the Android AAR for `arm64-v8a`,
`armeabi-v7a` and `x86_64`.

## Releases

Pushing a tag `vX.Y.Z` (matching `Cargo.toml`) publishes a GitHub release with
`sombe-chat-crypto-X.Y.Z.aar` and its SHA-256. The SOMBE app pins that SHA-256 and its
build fails if the downloaded AAR does not match, so the app ships exactly the code
published here.

Using the AAR also needs JNA: `implementation 'net.java.dev.jna:jna:5.14.0@aar'`.

## Kotlin API

```kotlin
val account = ChatCrypto.createAccount()          // or ChatCrypto.restoreAccount(pickle, key)
val statement = account.identityStatement(walletAddress, createdAt)  // signed by the wallet
val keys = account.generateOneTimeKeys(50u)       // publish, then account.markKeysPublished()

val contact = verifyIdentity(statement, walletAddress, walletSignature)  // a contact's identity
checkIdentityUpdate(pinned, contact)              // New, Unchanged or Changed; an older one throws
val code = safetyNumber(me, contact)              // 60 digits and the QR text to compare
compareScannedSafetyCode(me, contact, scannedText) // Match, Mismatch or NotASafetyCode
val sent = account.encryptFor(remote, session, claimedKey, plaintext, pickleKey)
val read = account.decryptFrom(remote, sessions, envelope, pickleKey)
```

Sessions travel in and out of each call as encrypted pickles, so the app can store the
advanced session in the same transaction as the message.

## Security

This layer has not been audited yet; vodozemac itself was audited by Least Authority
in 2022. Please report a vulnerability privately through GitHub's security advisories
for this repository, not in a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE).
