# sombe-chat-crypto

End-to-end encryption for SOMBE ChatPay messages, published so anyone can read and
check it. It is a thin layer over [vodozemac](https://github.com/matrix-org/vodozemac)
(Olm), exposed to Android through [UniFFI](https://github.com/mozilla/uniffi-rs). It holds
no business logic: no networking, no storage, no payments.

- [PROTOCOL.md](PROTOCOL.md): the account key drawn from the wallet, identity signed by
  that key, one time keys, envelope, content format, session rules, identity pinning and
  rotation, safety number, (since 0.10.0) the sealed sender and (since 0.11.0) the alias
  vault and the alias token.
- [vectors/v1.json](vectors/v1.json): test vectors written by 0.4.0 (frozen).
- [vectors/v2.json](vectors/v2.json): content version 2, one vector per kind (since 0.5.0; wallet card and payments since 0.6.0).
- [vectors/v3.json](vectors/v3.json): the account key, the texts it signs, its rotation and the safety number v2 (since 0.7.0).
- [vectors/v4.json](vectors/v4.json): alias attestations accepted and refused (since 0.8.0), and the content version 3 of 0.8.0, no longer read (frozen).
- [vectors/v5.json](vectors/v5.json): content version 4 with its binding, account ids and identity keys (since 0.8.1, frozen).
- [vectors/v6.json](vectors/v6.json): the access key and its verifier, the `access_key` content and an acceptance with and without an access key (since 0.9.0, frozen).
- [vectors/v7.json](vectors/v7.json): the identity statement v4, a sealing key and its pickle, envelopes sealed and refused, the `identity_statement` content (since 0.10.0).
- [vectors/v8.json](vectors/v8.json): the alias vault (key, block, blocks refused), the alias token (RFC 9474, prepared, signed blind, finalized, memo) and the `alias_change` content (since 0.11.0). Signing key: [vectors/alias-token-test-key.json](vectors/alias-token-test-key.json); the RFC 9474 test vector: [vectors/rfc9474-pss-randomized.json](vectors/rfc9474-pss-randomized.json).
- [vectors/rfc9180-base-x25519-sha256-chacha20poly1305.json](vectors/rfc9180-base-x25519-sha256-chacha20poly1305.json): the RFC 9180 test vectors of the one HPKE suite the sealed sender uses, unchanged from the CFRG file (source and SHA-256 inside).

## Build and test

```bash
cargo test                                        # Rust tests and test vectors
cargo test --features vectors                     # also checks v8.json is what the module writes
cargo run --features vectors --bin make-vectors   # regenerates vectors/v8.json (deterministic); v1.json to v7.json are frozen
```

vodozemac is a crates.io dependency pinned with `=`, never copied into this repository.
Dependabot proposes each new version of it and of the other dependencies, and the
`Audit` workflow (`cargo audit`, on every pull request and weekly) fails on a known
vulnerability in `Cargo.lock`.

The CI also compiles the generated Kotlin bindings with Kotlin 1.7.21 (the app's
version) and runs them on the JVM, then builds the Android AAR for `arm64-v8a`,
`armeabi-v7a` and `x86_64`.

## Releases

Pushing a tag `vX.Y.Z` (matching `Cargo.toml`) publishes a GitHub release with
`sombe-chat-crypto-X.Y.Z.aar` and its SHA-256. Publishing a release `vX.Y.Z` by hand on
github.com (for example from a phone) works too: the CI then attaches the AAR and its
SHA-256 to that release. The SOMBE app pins that SHA-256 and its
build fails if the downloaded AAR does not match, so the app ships exactly the code
published here.

Since the release after 0.7.1, each AAR also carries a build provenance attestation: a
statement signed through GitHub (Sigstore) that this file was built by this repository's
`CI` workflow, from the commit of its tag. Anyone can check it with the GitHub CLI:

```bash
gh attestation verify sombe-chat-crypto-X.Y.Z.aar --repo sombeProject/sombe-chat-crypto
```

It shows that the AAR comes from this source and this workflow, not that the build can be
reproduced bit for bit elsewhere.

Using the AAR also needs JNA: `implementation 'net.java.dev.jna:jna:5.14.0@aar'`.

## Kotlin API

```kotlin
// The account key (since 0.7.0): Kotlin sees only its public key and what it signed.
val derived = deriveAccountKey(walletSeed, 1u)    // the key and its wallet card; zero walletSeed after
val sealed = derived.key.seal(sealingKey)         // keep it; ChatAccountKey.unseal(sealed, sealingKey)
val signature = derived.key.signSignIn(message, devicePublicKeyDer)  // RefusedToSign on any other text
val moved = derived.key.signMove(derived.card, devicePublicKeyDer, identityId)
val rotation = derived.key.rotate(walletSeed)     // new key, its card and the proof; WrongGeneration
val proof = proveRotation(walletSeed, announced, current)  // from the key a contact pinned

val account = ChatCrypto.createAccount()          // or ChatCrypto.restoreAccount(pickle, key)
val sealing = ChatSealingKey.generate()           // or ChatSealingKey.restore(pickle, key); keep sealing.pickle(key)
val signed = derived.key.signIdentityStatement(account, sealing, createdAt)  // statement v4 (since 0.10.0)
val keys = account.generateOneTimeKeys(50u)       // publish, then account.markKeysPublished()

val contact = verifyIdentity(statementFields)     // the server's columns; the module rebuilds the text
checkIdentityUpdate(pinned, contact, rotation)    // New, Unchanged, Changed, AccountRotated(AndChanged);
                                                  // StaleIdentity, AccountChanged throw
verifyWalletCard(card)                            // InvalidKey or InvalidSignature
val code = safetyNumber(me, contact)              // 60 digits and the QR text to compare
compareScannedSafetyCode(me, contact, scannedText) // Match, Mismatch, OutdatedCode or NotASafetyCode
val sent = account.encryptFor(remote, session, claimedKey, plaintext, pickleKey)
val read = account.decryptFrom(remote, sessions, envelope, pickleKey)

// Content (since 0.8.1): version 4 written, bound to its sender and recipient (account id and
// ed25519 identity key of each), its channel and its envelope.
val myKey = account.identityKeys().ed25519Key      // contact.ed25519Key: from verifyIdentity, as pinned
val json = encodeContent(OutgoingContent(myAccountId, myKey, peerAccountId, contact.ed25519Key, envelopeId,
    ContentBody.Text(clientId, "Salut", null, null)))
val binding = ContentBinding(ContentChannel.MAILBOX, element.id, element.senderAccountId, contact.ed25519Key,
    myAccountId, myKey, null)
when (val body = decodeContent(read.plaintext, binding).body) { // UnboundContent: drop, still acknowledge
    is ContentBody.Receipt -> body.status                          // UnsupportedContent: authentic, not shown
    is ContentBody.Typing -> body.state                            // InvalidContent: kept as unreadable
    is ContentBody.ContactRequest ->                               // the alias only from the attestation
        verifyAliasAttestation(body.attestation, body.attestationSignature, trustedKeys,
            element.senderAccountId, senderAccountPublicKey, element.createdAt)
    else -> Unit
}

// Access key (since 0.9.0): drawn from a random 32 byte profile key, given to contacts only.
val accessKey = deriveAccessKey(profileKey)          // 16 bytes, base64 without padding
val verifier = accessKeyVerifier(accessKey)          // SHA-256 of those bytes: the server keeps only this
val accept = ContentBody.ContactAccept(requestId, attestation, attestationSignature,
    AccessKeyGrant(accessKey, generation))           // null in an acceptance written by 0.8.1
val give = ContentBody.AccessKey(AccessKeyGrant(accessKey, generation)) // a higher generation replaces

// Sealed sender (since 0.10.0): the server takes the envelope without knowing who sent it.
val ciphertext = seal(SealedRecipient(peerAccountId, peerIdentityId, contact.sealingKey!!), envelopeId,
    SealedSender(myAccountId, myIdentityId, myStatementFields), sent.envelope) // protocol sealedProtocolId()
val opened = sealing.openSealed(element.ciphertext, myAccountId, myIdentityId, element.id) // InvalidSealed
val sender = verifyIdentity(opened.sender.statement)  // then: an active contact, the pinned account key,
                                                      // the pinned Olm keys and identity id; only then
val readSealed = account.decryptFrom(pinnedKeys, sessions, opened.envelope, pickleKey)
val tell = ContentBody.IdentityStatement(myStatementFields) // gives contacts my sealing key

// Alias vault and alias token (since 0.11.0).
val vaultKey = deriveAliasVaultKey(walletSecret, myAccountId)       // never returns its key
val sealedVaultKey = vaultKey.sealKey(sealingKey)                   // kept by the Keystore
val block = vaultKey.sealVault(AliasVault(seq, alias, retired, tokens)) // 16 384 bytes, base64 with padding
val vault = vaultKey.openVault(block)                               // InvalidVault / UnsupportedVault
val prepared = aliasTokenPrepare(trustedSpki, keyId, burnIdempotencyKey) // put it in the vault, then pay
val memo = aliasTokenMemo(prepared.blindedMsg)                      // "sombe-alias-token:<43>"
val tokenSignature = aliasTokenFinalize(trustedSpki, prepared.nonce, prepared.blindedMsg,
    prepared.secret, blindSignatureFromWalletApi)                   // InvalidToken unless it verifies
val changed = verifyAliasChange(text, signature, trustedKeys, senderAccountId,
    senderAccountPublicKey, depositedAt)                            // alias and the signed expires
```

Sessions travel in and out of each call as encrypted pickles, so the app can store the
advanced session in the same transaction as the message.

## Security

This layer has not been audited yet; vodozemac itself was audited by Least Authority
in 2022. Please report a vulnerability privately through GitHub's security advisories
for this repository, not in a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE).
