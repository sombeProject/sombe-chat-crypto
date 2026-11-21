# SOMBE chat crypto, protocol `olm-v1`

This is how SOMBE ChatPay encrypts messages between two people. Messages are
encrypted on the sender's phone and only the recipient's phone can read them. The
SOMBE server stores and relays ciphertext; it never sees the text.

The cryptography is [vodozemac](https://github.com/matrix-org/vodozemac), the
Matrix project's Rust implementation of Olm (the Double Ratchet with an X3DH style
handshake, as in Signal). This repository only adds the thin layer SOMBE needs on top:
the account key drawn from the person's Solana wallet, an identity signed by that key,
signed one time keys, the envelope, the content format, and the safety number two people
compare. Nothing here invents new cryptography: the account key uses HKDF-SHA256
(RFC 5869), Ed25519 and XChaCha20-Poly1305, from the RustCrypto crates `hkdf` and
`chacha20poly1305`; the sealed sender (since 0.10.0) uses HPKE (RFC 9180), from the
crate [`hpke`](https://github.com/rozbb/rust-hpke), one suite only.

0.7.1 changes no text and no signature: it refuses dates that do not exist or lie far
ahead, keys written with base64 padding, and base58 fields too long to be a key or a
signature, and it binds each stored session to its contact. What a 0.7.0 phone writes is
still read, and the vectors are unchanged.

0.8.0 writes content version 3: the server keeps no conversation any more, so each content
names its sender's and its recipient's account ids, and the module itself binds it to the
element it came with. It adds the alias attestation and the three contact kinds. Versions
1 and 2 are read only for an element deposited before the switch, vouched for by the app
with its old conversation id. `vectors/v1.json`, `v2.json` and `v3.json` are frozen: their
contents can no longer be written, only read.

0.8.1 writes content version 4, which also names the ed25519 keys of the sender's and the
recipient's Olm identities: account ids are given by the server, and an identity does not
prove that its author holds its curve25519 key, so the ids alone did not stop a server from
passing one person's messages off as another's (*Version 4*). Version 3 was written by
0.8.0 only, is no longer read, and `vectors/v4.json` is frozen in turn.

0.9.0 adds the access key (*Access key*): a capability drawn from a random profile key,
which a person gives only to their contacts, so that the server can keep a share of their
mailbox for them. Content version 4 carries it in two places: an optional pair of fields
of `contact_accept`, and a new `access_key` kind. A 0.9.0 phone reads an acceptance written
by 0.8.1 (without the pair). The other way does not hold: a 0.8.1 module reads every field
of a kind strictly, so it refuses an acceptance that carries an access key as
`InvalidContent`, and its phone never sees that it was accepted. SOMBE moves every phone
to 0.9.0 together. A 0.8.1 module reads the `access_key` kind as `UnsupportedContent`
(authentic, not shown). `vectors/v5.json` is frozen in turn.

0.10.0 adds the sealed sender (*Sealed sender*): an Olm envelope sealed with HPKE for one
identity of a contact, so that the server, which takes it without a token, does not learn
who sent it. Each identity gets a sealing key, published in a new identity statement
version 4 (*Identity*), and a new `identity_statement` kind gives it to existing contacts.
The module now writes only statements v4, and reads v3 and v4: the server serves both
while phones move over, and the app refuses a v3 for a contact once it saw a v4 of theirs.
`ChatAccountKey.sign_identity_statement` takes the sealing key (`ChatSealingKey`);
`StatementFields` and `VerifiedIdentity` carry `sealing_key`, absent for a v3. A 0.9.0
module reads a statement v4 as a v3 and refuses it (`InvalidSignature`), and reads the
`identity_statement` kind as `UnsupportedContent`. `vectors/v6.json` is frozen in turn.

0.11.0 adds the alias vault and the alias token (*Alias vault and alias token*) and a new
content kind, `alias_change`. The vault is one block of 16 384 bytes that the phone seals
and the server keeps without reading; the token is an RSA blind signature that lets a person
pay for an alias without the server linking the payment to the account. Both are new
functions; nothing that 0.10.0 writes or reads changes. A 0.10.0 module reads the
`alias_change` kind as `UnsupportedContent` (authentic, not shown). `vectors/v7.json` is
frozen in turn.

0.12.0 adds the secret of the alias seal (*Alias seal*), one new method on `AliasVaultKey`.
Nothing that 0.11.0 writes or reads changes; `vectors/v8.json` is frozen in turn.

0.13.0 reads aliases with digits (*Alias rule*): a name, a dot and 2 to 9 digits, such as
`blaise.46`. The alias rule of the attestation, of `alias_change` and of the vault reads both
forms; the form without digits stays readable for good, because vaults, retired aliases and
attestations of accounts that have not moved yet still carry it. Which form can still be taken
is the ChatPay API's and the app's rule, not the module's. The vault format stays `v: 1`; its
worst case grows from 11 564 to 11 774 bytes. A 0.12.0 module refuses an alias with digits in
an attestation (`InvalidAttestation`), in an `alias_change` and in a vault (`InvalidVault`):
every phone must run 0.13.0 before the first alias gets its digits. `vectors/v9.json` is
frozen in turn; `vectors/v10.json` holds the new cases.

`vectors/v1.json` holds test vectors written by 0.4.0 (its identity statement and safety
number are no longer read since 0.7.0; its keys, sessions and version 1 contents still
are), `vectors/v2.json` those of content version 2 (since 0.5.0; wallet card and payment
kinds since 0.6.0), and `vectors/v3.json` those of the account key (since 0.7.0): its
derivation, the sealed key, the wallet card and its fingerprint, the four texts it signs,
the rotation proof, the `account_rotation` content and the safety number v2. The ChatPay
server replays `vectors/v3.json` byte for byte, so the server and the module never build
a text differently. `vectors/v4.json` (since 0.8.0) holds alias attestations, accepted and
refused, with the test signing seeds; the server replays it too. `vectors/v5.json` (since
0.8.1) holds content version 4 with its binding. `vectors/v6.json` (since 0.9.0) holds
the access key derived from two profile keys with its verifier, keys refused for their
form, the `access_key` content, an acceptance with and without an access key, and contents
refused; the server replays its verifiers. `vectors/v7.json` (since 0.10.0) holds the
statement v4 signed with raw test keys (written from this text, not by the module) and
statements refused, a sealing key with its pickle, envelopes sealed for it (one per Olm
message type, with their clear text and the fixed randomness that gives the same bytes)
and sealed envelopes refused, and the `identity_statement` content with contents refused;
the server replays its statements. `vectors/rfc9180-base-x25519-sha256-chacha20poly1305.json`
holds the RFC 9180 test vectors of the HPKE suite, unchanged from the CFRG file; the
module's tests replay its key derivation, its encapsulation, all 257 encryptions and its
exports.

## Account key (since 0.7.0)

A ChatPay account is held by its own Ed25519 key, the account key, not by the wallet.
The server only ever sees its public key; it never learns the wallet address.

**Derivation.** The 32 byte seed of the key of generation `n` (1 to 32767, the range of a
`smallint`) is

```
HKDF-SHA256(IKM = wallet seed, salt = empty, info = "sombe:chat_account:<n>", L = 32)
```

where the wallet seed is the 32 byte Ed25519 seed of the Solana key at `m/44'/501'/0'/0'`
and an empty salt means 32 zero bytes (RFC 5869). The same recovery phrase therefore gives
the same account key on any phone. HKDF is one way: the account key does not give the
wallet key back. Its public key is written in base58 (32 bytes), and every signature by
the account key in base58 (64 bytes), like a Solana signature.

**Only the module sees it.** `derive_account_key(wallet_secret, generation)` returns a
`ChatAccountKey` object and its wallet card. The object gives only `public_key()` and
`generation()`; no function returns its seed or private key, and none signs a free text.
The module erases `wallet_secret` and every intermediate value from its memory before
returning (`Zeroizing`), and the key itself when the object is dropped. It uses the wallet
key only in `derive_account_key`, `rotate` and `prove_rotation`.

**Sealed on the phone.** `seal(sealing_key)` returns, in standard base64 without
padding, the bytes

```
0x01 (format version) ‖ nonce (24 random bytes, drawn for each call) ‖ XChaCha20-Poly1305 output
```

The clear text (34 bytes) is the generation (2 bytes, big endian) followed by the seed;
the output is those 34 bytes encrypted, then the 16 byte tag. The associated data
(authenticated, not encrypted) is the UTF-8 bytes of `sombe:chat_account_seal:v1`
followed by the version byte. `ChatAccountKey.unseal(sealed, sealing_key)` opens it; a
wrong sealing key, a changed or truncated text, or another version are all
`InvalidSealedKey`, with no more detail. The sealing key is 32 bytes (`InvalidKey`
otherwise); the app keeps it apart, sealed by the Android Keystore.

Vector (also in `vectors/v3.json`, test values only):

```
sealing key  5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
nonce        000102030405060708090a0b0c0d0e0f1011121314151617
generation   1
seed         2a79a28bc80a3bdec9d8d576d656135496132b817f5188c19782e06d7a887c62
sealed       AQABAgMEBQYHCAkKCwwNDg8QERITFBUWFyvTqAiQaQoI3kjDjS1mXVz+dlOV6PniGwa0u9LOD0xu//bNm6jWbHXPGvOlH9cWbR9L
```

**The four texts it signs.** The account key signs only these texts, each recognized by
its first line, so no text of one format can pass for another. Lines are separated by a
single `\n`, with no final newline, in UTF-8.

| Text | First line | Signed by |
|---|---|---|
| Identity statement v3 | `SOMBE chat identity v3` | `sign_identity_statement`, see Identity |
| Sign in | `SOMBE ChatPay sign in` | `sign_sign_in` |
| Account move | `SOMBE account move v1` | `sign_move` |
| Rotation | `SOMBE account rotate v1` | `rotate`, `prove_rotation` |

*Sign in.* The server writes the message; `sign_sign_in(message, device_public_key_der)`
signs it only if it has exactly these five lines, and returns `RefusedToSign` otherwise
(nothing signed):

```
SOMBE ChatPay sign in
account:<this account key>
device:<SHA-256, lower case hexadecimal, of device_public_key_der, computed by the module>
nonce:<32 lower case hexadecimal digits>
issued:<ISO 8601 UTC>
```

The module does not compare `issued` with the phone's clock; the server keeps the nonce
for 5 minutes and accepts it once.

*Account move* (the one time move of an account from the wallet to its account key):

```
SOMBE account move v1
card:<SHA-256, lower case hexadecimal, of the wallet card text alone, signature excluded>
device:<SHA-256, lower case hexadecimal, of device_public_key_der>
identity:<the identity id as a lower case UUID, or ->
```

`sign_move(card, device_public_key_der, identity_id)` first checks the card (below) and
that it names this account key (`RefusedToSign` otherwise). An identity id that is not a
lower case UUID is `InvalidStatement`.

The card fingerprint of `vectors/v3.json` (test values only): the text

```
SOMBE wallet card v1
wallet:FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF
account:ASN6cYbgCioRtpRNg2NqqN3NuN5kRPhXiRRAedYNVwh3
```

gives `card:5cea19842b9c66cce702d71fd63ed461a6ba594e720855fbd38cb42b39bd4dd9`.

**The wallet card.** The wallet vouches for the account key once, with the text

```
SOMBE wallet card v1
wallet:<wallet address, base58>
account:<account key, base58>
```

signed by the wallet key (Ed25519, base58). `derive_account_key` computes the wallet
address itself (the base58 public key of the wallet seed) and signs the card; no function
takes an address from the app to sign. `verify_wallet_card(card)` rebuilds the text and
checks the signature against `wallet_address`: a field that is not canonical base58 of
32 bytes is `InvalidKey`, a wrong signature `InvalidSignature`. The card travels only
inside encrypted content (`wallet_card`, `account_rotation`), never to the server.

**Rotation.** A person may change their account key (a key they fear was seen, for
instance). `rotate(wallet_secret)` first checks that the wallet seed gives this very key
at its generation `n` (`WrongGeneration` otherwise, nothing returned), then derives the
key of generation `n + 1` and returns it with its wallet card and the proof: both keys
sign the same text

```
SOMBE account rotate v1
old:<old account key>
new:<new account key>
generation:<n + 1>
```

At generation 32767 `rotate` returns `GenerationExhausted`. Since every generation comes
from the same seed, `prove_rotation(wallet_secret, from, to)` (1 ≤ from < to ≤ 32767)
gives the proof from any earlier key to a later one (`generation:<to>`) and the card of the
later key. A proof `k → n` is as strong as one step: it needs the key `k`, the key `n`
and the wallet key. A proof holds only public data.

The phone sends the server the two signatures (`/account/rotate`), which checks them
against the account's current key and the new key, then keeps neither. It sends each
contact an `account_rotation` content (below) from the key that contact pinned.

## Identity

Each account has at most one active chat identity: an Olm account living on one phone.
Its two public keys (`curve25519`, `ed25519`, unpadded base64) and the account key vouch
for each other with this UTF-8 text (version 3, since 0.7.0):

```
SOMBE chat identity v3
protocol:olm-v1
account:<account key, base58>
curve25519:<identity curve25519 key>
ed25519:<identity ed25519 key>
created:<ISO 8601 UTC, e.g. 2026-10-14T18:30:01.183Z>
identity_signature:<signature of the six lines above by the identity ed25519 key, base64>
```

Lines are separated by a single `\n`, with no trailing newline. The identity's ed25519
key first signs the first six lines (the body), so the identity vouches for the account
key: without it, any account key could sign a statement naming someone else's keys. The
account key then signs the whole seven line text (base58). `sign_identity_statement(account,
created_at)` does both and returns the text, `identity_signature` and `account_signature`;
`created_at` that is not this ISO 8601 UTC form is `InvalidStatement`. Since 0.7.1 it must
also be a date and a time that exist (month 1 to 12, a day of that month, hour up to 23,
minute and second up to 59): `2026-02-30T00:00:00Z` is `InvalidStatement`, when signed and
when verified.

Since 0.10.0 the module writes version 4, the same text with another header and one more
line before the identity's signature:

```
SOMBE chat identity v4
protocol:olm-v1
account:<account key, base58>
curve25519:<identity curve25519 key>
ed25519:<identity ed25519 key>
created:<ISO 8601 UTC>
sealing:<sealing key of the identity, X25519, base64 without padding of 32 bytes>
identity_signature:<signature of the seven lines above by the identity ed25519 key, base64>
```

The identity signs the first seven lines, the sealing key with them, and the account key
signs the eight. `sign_identity_statement(account, sealing, created_at)` writes it. The
sealing key is used for nothing but the sealed sender, never for Olm: no key serves two
protocols. It changes only with the identity. A reader rebuilds a v4 when the columns carry
`sealing_key` (base64 without padding of 32 bytes, the one spelling of its bytes, or
`InvalidKey`) and a v3 when they do not, so a v4 given without its sealing key, a v3 text
with a sealing line or a v4 header without one never verify (`InvalidSignature`).
`VerifiedIdentity.sealing_key` is present exactly for a v4. The module never tells a
contact's v3 from a later downgrade: the app keeps, for each contact, whether it saw a v4,
and then refuses a v3, so that a server cannot force the identified path back.

The server stores and returns only the fields, never the text. A verifier calls
`verify_identity` with those fields (`account_public_key`, `curve25519_key`,
`ed25519_key`, `created_at`, `identity_signature`, `account_signature`): the module
rebuilds the seven lines itself, checks `identity_signature` over the first six with the
`ed25519` key, then `account_signature` over the seven with `account_public_key`. The app
never builds a statement text. Since 0.7.1 the two keys and `identity_signature` must be
written as vodozemac writes them, standard base64 without padding (`InvalidKey` for a key,
`InvalidSignature` for the signature, otherwise): the text is signed and compared as
written, so the same keys with a final `=` would be another identity with another safety
number. The same holds for a one time key, its signature and the identity key that signed
it. Statements v1 (0.2.0 and earlier) and v2 (signed by the
wallet, up to 0.6.0) are no longer read.

The server checks the statement before accepting an identity, and refuses one that is
older than the previous identity of the same account or more than 24 hours away from its
clock. The app checks it again before it encrypts anything to a contact.

The app pins, for each contact, the account key it first saw (and, once a rotation of
theirs was accepted, its generation), the wallet address of the first wallet card it
accepted, and the latest verified Olm keys. `check_identity_update(pinned, candidate,
rotation)` compares each identity it receives with them, in this order:

| Case | Result |
|---|---|
| no account key pinned | `New` |
| same account key, no Olm keys pinned yet | `New` (the first identity of this account) |
| same account key, same Olm keys | `Unchanged` |
| same account key, other Olm keys, strictly later `created` | `Changed`: a new phone. The app pins it, removes the verified mark, shows that the safety number changed |
| same account key, other Olm keys, same or earlier `created` | `StaleIdentity`: a server that relays an old, validly signed identity cannot bring it back |
| another account key, every rotation condition holds, same Olm keys | `AccountRotated` |
| another account key, every rotation condition holds, other Olm keys (or none pinned) | `AccountRotatedAndChanged`: the verified mark falls, as for `Changed` |
| another account key, any condition missing (even with no Olm keys pinned) | `AccountChanged`: the app pauses the contact until the safety codes match |

The rotation conditions, all required: an `account_rotation` content is given; its old key
is the pinned account key and its new key the candidate's; both signatures hold on the
rotation text; if the contact's generation is known, the proof's generation is strictly
greater (no way back to a key already left); a wallet address is pinned; the card
(`wallet_address`, new key, `wallet_signature`) holds and names that pinned wallet; and if
Olm keys are pinned, the candidate's `created` is strictly later. A proof `k → n` passes
whatever the gap, as long as `k` is the pinned key. No card and no answer from the server
ever changes the pinned account key on its own.

`created` values compare in time order; a value without milliseconds counts as `.000`.

Since 0.7.1 an identity is pinned only if its `created` is at most 24 hours after this
phone's clock, the bound the server applies, checked again because the server is not
trusted. Without it, whoever held an account key could publish an identity dated at the end
of time, and every later identity of the contact, a proven rotation included, would be
refused for ever. `New` and `Changed` become `InvalidStatement`; an identity that is not
strictly later stays `StaleIdentity`; for another account key it is one more rotation
condition, so `AccountChanged`. `Unchanged` is never refused. A phone whose clock is more
than 24 hours late refuses fresh identities until its clock is set.

## One time keys

An identity publishes signed one time keys and one fallback key. Each signature is
made by the identity's ed25519 key over this UTF-8 text, and written in base64:

```
SOMBE one-time key v1
key_id:<key id, base64>
curve25519:<one time key, base64>
fallback:<true|false>
```

A sender verifies the signature against the recipient's verified identity before
opening a session with the key. The server hands out each one time key once, and the
fallback key only when no one time key is left.


## Alias rule (since 0.13.0)

An alias has one of two forms, checked byte by byte, never through a regular expression engine:

- a **name**, `^[a-z][a-z0-9_]{2,19}$` (the only form before 0.13.0, still read);
- a name, one dot, then **digits**: `^[a-z][a-z0-9_]{2,19}\.(0[1-9]|[1-9][0-9]|[1-9][0-9]{2,8})$`.
  Two digits run from `01` to `99`; three to nine digits never start with `0`, so `blaise.046`
  is never taken for `blaise.46`. 30 bytes at most.

Nothing else is an alias: no upper case, no other separator, no digit outside ASCII, no second
dot. Lower casing and trimming are the server's and the app's, before the module sees it.

## Alias attestation (since 0.8.0)

A contact request (and its acceptance) carries a short proof, signed by the ChatPay server,
that an alias belongs to an account. The phone checks it offline, so the alias it shows
always comes from the server's signature, never from a free field of the envelope. The
server is trusted for the link between an alias and an account, as it already is for a
search by alias.

The text is six lines, UTF-8, separated by `\n`, without a final `\n`:

```
SOMBE alias attestation v1
kid:<kid>
alias:<alias>
account_id:<account_id>
account:<account_public_key>
expires:<unix seconds>
```

- `kid`: the server key that signed it, 1 to 16 characters among `a` to `z` and `0` to `9`.
- `alias`: the alias rule below, checked byte by byte.
- `account_id`: the account's random id, a lower case UUID.
- `account`: the account public key (base58 of 32 bytes), the one that signs the identity v3.
- `expires`: seconds since 1970, decimal digits without sign or leading zero. The server
  sets it 24 hours after signing.

The server signs the whole text with Ed25519; the signature is base58 of 64 bytes. It keeps
neither the text nor the signature.

`verify_alias_attestation(text, signature, trusted_keys, sender_account_id,
sender_account_public_key, deposited_at)` returns the alias only if all of these hold:

- the text is at most 512 bytes, has exactly the six lines above, and is exactly the text
  rebuilt from its parsed values (so CRLF, a final newline or any other spelling fails);
- every value follows its rule above;
- `trusted_keys` lists each `kid` once, every key is base58 of 32 bytes, and it contains
  the text's `kid`;
- the signature holds under that key (strict Ed25519 verification);
- `account_id` equals `sender_account_id` (the mailbox element's sender), and `account`
  is the same 32 bytes as `sender_account_public_key` (from the sender's verified
  identity v3). An attestation carried by another account's envelope is refused;
- `deposited_at` (the element's `created_at`, `2026-10-14T18:30:01.183Z` or without
  milliseconds, a date that exists) is at most `expires`, compared to the millisecond.

Anything else is `InvalidAttestation`, with no detail. The app holds the trusted keys of
its environment in the APK; a public key is not a secret. An attestation whose `kid` the
app does not know is refused like any other.

## Access key (since 0.9.0)

Each person's phone draws a profile key at random, 32 bytes, and keeps it with its other
secrets; a new phone or a restore draws a new one. The access key is

```
access_key = HKDF-SHA256(ikm = profile_key, salt = empty, info = "sombe:access_key:1", L = 16)
```

(an empty salt is 32 zero bytes, as RFC 5869 says), written in base64 without padding (22
characters). `derive_access_key(profile_key)` gives it; another length of profile key is
`InvalidKey`, and the module erases the profile key from its memory before returning.

The server keeps only the verifier, `SHA-256(access_key)` computed over the 16 bytes (not
over their base64 text), in base64 without padding (43 characters), as
`access_key_verifier(access_key)` gives it. An access key in any other spelling (with
padding, URL safe, another length, or a spelling that is not the one of its bytes) is
`InvalidKey`. The access key is 128 bits drawn from 256 random bits, so a plain SHA-256 is
enough: there is no dictionary to try.

A phone gives its access key only to an account it became a contact of: in its
`contact_accept`, or in an `access_key` content right after it saw its request accepted.
Each carries a generation, 1 for the first profile key of an account and higher for each
new one; a phone replaces a key it keeps only with one of a higher generation, so two
contents read out of order never bring an old key back.

A sender shows the access key of its recipient, in the body of its mailbox request, never
inside the ciphertext, so the server can tell which share of the recipient's mailbox it
counts in. The server therefore sees, while it deposits, that a sender it knows holds that
key. It never keeps the key itself. The key opens no content: it only lets an envelope
count among a person's contacts.

## Sealed sender (since 0.10.0)

The mailbox takes a sealed envelope without a token: the server checks the recipient's
access key, not who sends. The envelope then carries the sender inside the seal.

**Sealing key.** `ChatSealingKey.generate()` draws 32 bytes from the system and derives the
X25519 key pair from them with HPKE's `DeriveKeyPair`. The private key stays in the module
(erased when dropped). `pickle(pickle_key)` writes it under a 32 byte key: base64 without
padding of `0x01`, a fresh 24 byte nonce, then XChaCha20-Poly1305 of the 32 private key
bytes (written clamped, RFC 9180 7.1.2), with the associated data
`sombe:sealing_key_pickle:v1`. `restore(pickle, pickle_key)` opens it; anything else is
`InvalidPickle`. `public_key()` is the `sealing:` line.

**Seal.** `seal(recipient, envelope_id, sender, envelope)` uses HPKE (RFC 9180), base mode,
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 (suite `0x0020`, `0x0001`,
`0x0003`), single shot, to `recipient.sealing_key`, with

```
info = "sombe:sealed:1"
aad  = recipient_account_id + "\n" + recipient_identity_id + "\n" + envelope_id
```

each a lower case UUID, no trailing newline. The sealed envelope's `ciphertext` is base64
without padding of the 32 byte encapsulated key followed by the HPKE ciphertext (clear text
and 16 byte tag). Before sealing, the module checks the recipient's key, the ids, that the
sender's statement is a v4 whose signatures hold (`InvalidKey`, `InvalidMessage`,
`InvalidStatement`, `InvalidSignature`), and that the Olm envelope is `olm-v1` with
`olm_type` 0 or 1. A recipient key that gives no shared secret (a low order point) is
`Encryption`. The ephemeral key is 32 bytes drawn from the system before the call; a seal
that would draw anything else is refused (`Encryption`), so a change in the library is
never silent.

**Clear text.** A JSON object, these fields in this order, nothing else:

| Field | Value |
|---|---|
| `v` | `1` (a JSON integer) |
| `sender_account_id`, `sender_identity_id` | lower case UUIDs |
| `account_public_key`, `curve25519_key`, `ed25519_key`, `sealing_key`, `created_at`, `identity_signature`, `account_signature` | the columns of the sender's statement v4 |
| `olm_type` | `0` or `1` |
| `ciphertext` | the Olm message, base64 without padding, as in *Envelope* |
| `pad` | spaces |

The whole text is a multiple of 256 bytes. Three fields vary in length from one sender to
another (the account key and the account signature in base58, `created_at` with or without
milliseconds), so the pad is counted as if they had their longest length (45, 89 and 24
characters): two senders give the same size for the same Olm message. The Olm message
inside already has the size bucket of its content.

**Open.** `open_sealed(ciphertext, my_account_id, my_identity_id, envelope_id)` on my
sealing key opens with my ids and the element's id, so a sealed envelope copied to another
recipient, identity or id does not open. It reads the clear text strictly (a multiple of
256 bytes, exactly the fields above in their order, `v` 1, lower case UUIDs, a statement v4
whose own signatures hold, `olm_type` 0 or 1, a non empty base64 ciphertext, a pad of
spaces). Any failure is `InvalidSealed`, with no detail. It returns the sender (ids and
statement columns) and the Olm `Envelope`.

**What the app checks.** The module does not know the contacts. Before it trusts a sealed
envelope, the app checks that `sender.account_id` is an active contact, that
`verify_identity(sender.statement)` names the account key pinned for that contact, and that
its Olm keys and the identity id are the ones pinned for them. Only then does it call
`decrypt_from` with the pinned keys, and `decode_content` with the sealed sender's account
id. HPKE base mode does not authenticate the sender, and does not need to: the statement
signed by the pinned account key and the Olm session do; the seal only hides the sender
from the server. A server that writes a statement under its own account key and someone
else's account id gets a seal that opens, and fails the account key check.

## Alias vault and alias token (since 0.11.0)

Everything the APIs take here is **base64 standard with padding**, written and read by a
strict codec of this module: a text is accepted only if writing the bytes it gives yields
that very text. (vodozemac's codec writes without padding.) Only the sealed vault key,
which never goes to a server, keeps the no padding form of the account key.

**Vault key.** `derive_alias_vault_key(wallet_secret, account_id)`: HKDF-SHA256 over the
32 byte wallet seed, empty salt, info `sombe:alias_vault:1`, 32 bytes. `account_id` is a
lower case UUID. The seed is used once and erased; the `AliasVaultKey` object never returns
its key. `seal_key(sealing_key)` returns `0x01`, a fresh 24 byte nonce and
XChaCha20-Poly1305 of the 32 byte key, in base64 without padding, with associated data
`sombe:alias_vault_key_seal:v1`, `0x01` and the account id; `AliasVaultKey.unseal(sealed,
sealing_key, account_id)` opens it, or fails with `InvalidSealedKey`.

**Vault.** One block of exactly 16 384 bytes, sent in base64 (21 848 characters):
`0x01` (the format of the encryption), a 24 byte nonce drawn at random at every write, and
XChaCha20-Poly1305 of a clear text of 16 343 bytes (so a tag of 16 bytes), with associated
data the UTF-8 bytes of `sombe alias vault v1`, then `0x01`, then the 36 ASCII characters
of the account id: a vault opens only for its account and its format. The clear text is a
2 byte length `L` (big endian), a JSON of `L` bytes, and zeros up to 16 343 bytes. The JSON
is **exactly** the text this module writes (no space, fixed order, no extra field, decimal
integers without a leading zero, no escape), compared byte for byte when a vault is opened.

```
{"v":1,"seq":0,"alias":"…","retired":[{"alias":"…","retired_at":1795000000}],"tokens":[…]}
```

- `seq`: an integer from 0 to 2^53 (inclusive), which goes up at each change of content.
- `alias`: the alias rule (*Alias rule*), as are the retired aliases. `retired`: at most 20 entries, sorted by `retired_at`
  from the latest, then by alias; `retired_at` is in seconds, 1 to 2^53; no alias twice, and
  the current alias is never among them. `seal_vault` sorts them and cuts them to 20 (the
  oldest leave).
- `tokens`: at most 10, sorted by the **decoded bytes** of `nonce` (not by its text, which
  sorts differently), no `nonce` twice. More than 10, a `nonce` twice, an alias twice or the
  current alias among the retired is `InvalidVault` when sealing: a paid token is never
  lost without an error.
- A token being prepared: `{"state":"preparing","key_id","nonce","blinded_msg","secret","idem"}`
  and, once known, `"burn_signature"` (base58, 64 to 90 characters). `idem` is the burn's
  `client_idempotency_key`, a lower case UUID v4. A token ready:
  `{"state":"ready","key_id","nonce","signature"}`. `nonce` is 64 bytes, `blinded_msg`,
  `secret` and `signature` 256 bytes, all in base64 with padding; `key_id` is
  `^[a-z0-9]{1,16}$`.
- The worst case allowed (an alias of 30 bytes, 20 retired aliases of 30 bytes and 10 tokens
  being prepared) is a JSON of 11 774 bytes since 0.13.0 (11 564 before, with aliases of 20
  bytes), within the 16 341 bytes that fit.

**Opening.** A format byte other than `0x01` is `UnsupportedVault`, read before anything
else (also on a block of another size); so is a schema `v` other than 1, read after the
decryption. Everything else that fails (a wrong key, another account, a changed or cut
block, a padding that is not zeros, a JSON that is not exactly the one written) is
`InvalidVault`, with no detail. An app never rewrites a vault it could not open: an older
app must not erase a newer vault.

The server can give back an older vault or none, and cannot read any. So the phone keeps a
sealed copy of the whole content, which is authoritative, with the last `seq` it saw; a
server vault with a lower `seq` is merged and rewritten, never taken as it is.

**Alias token.** RFC 9474, `RSABSSA-SHA384-PSS-Randomized`, with a 2 048 bit RSA key
(exponent 65 537), through the `blind-rsa-signatures` crate (pinned with `=`, MIT, pure
Rust, `serde` off). The module has no function that signs a token.

- The public key is given as DER `SubjectPublicKeyInfo` with `rsaEncryption`, in base64
  with padding. It is read with `from_der`, never `from_spki` (which takes only the
  RSASSA-PSS template), written back and compared, and checked to be exactly the 294 bytes
  of a 2 048 bit key with exponent 65 537 (the library accepts 2 048 to 4 096 bits and the
  exponent 3). The appendix A key of the RFC has 4 096 bits, so the RFC vector is replayed
  through the library (`tests/alias_token.rs`), byte for byte, and not through these
  functions.
- `alias_token_prepare(public_key_spki, key_id, idem)` draws a 32 byte message `msg` and
  blinds it with the system's randomness. The **nonce** is the prepared message of the RFC,
  `msg_prefix || msg`: the 32 bytes of the randomizer, then `msg`; 64 bytes. It names the
  token. The result holds `key_id`, `nonce`, `blinded_msg` (what the wallet API signs),
  `secret` (the unblinding factor) and `idem`. Keep it in the vault before paying.
- The wallet API signs `blinded_msg` without seeing it. `alias_token_finalize(
  public_key_spki, nonce, blinded_msg, secret, blind_signature)` unblinds and returns the
  `token_signature` (256 bytes, base64) only if it verifies under the key; otherwise
  `InvalidToken`. `alias_token_verify(public_key_spki, nonce, token_signature)` is
  `AliasTokenCheck.Valid` if it verifies and `BadSignature` if not (an enum, so the app must
  handle both); a key or a length that is not valid is `InvalidToken`, an error of the app's
  key and never a reason to throw a token away. ChatPay verifies
  RSASSA-PSS, SHA-384, MGF1 SHA-384, salt of 48 bytes, over the 64 byte nonce.
- The burn that pays a token carries the memo `sombe-alias-token:` and the SHA-256 of the
  **bytes** of `blinded_msg`, in base64url without padding (43 characters):
  `alias_token_memo(blinded_msg)`.
- The app picks the key by `key_id` in a list of trusted keys built into the APK, each with
  the window in which it signs; the module knows no key.

`vectors/v8.json` holds the vault key, the key sealed, the block that opens to its vault,
fourteen blocks refused with their error, the worst case, two nonces whose text and byte
order differ, a token prepared, signed, finalized and verified (with refusals), its memo,
and the `alias_change` content. The signing key of the test is in
`vectors/alias-token-test-key.json`. The ChatPay and wallet APIs replay it.

## Alias seal (since 0.12.0)

The seal lets an account prove its alias again after the ChatPay API lost the key of its
alias fingerprints. The phone never makes a seal: it gives the server a secret with the alias,
the server computes `HMAC-SHA256(secret, normalized alias)` for the alias it really grants,
keeps that seal and forgets the secret.

- **Epoch.** 16 random bytes drawn by the phone at the first seal and again at every alias
  changed, sent as `seal_epoch` (base64 standard with padding). The server returns it so a
  restored phone finds the same secret.
- **Secret.** `AliasVaultKey.alias_seal_secret(epoch)`: HKDF-SHA256 over the alias vault key,
  empty salt, info `sombe:alias_seal:1:`, the 16 epoch bytes, then the account id (36 ASCII
  characters), 32 bytes in base64 standard with padding. The vault key comes from the wallet
  seed, so the recovery phrase gives the secret back; the phone derives it when it needs it
  and never keeps it. The account id in the info means two accounts of one wallet never give
  the same secret for the same epoch, so a server that replays an epoch learns nothing.
- An epoch that is not 16 bytes in canonical base64 with padding is `InvalidKey`.
- The secret leaves the module as a JVM string that cannot be erased: never log it.

`vectors/v9.json` holds three secrets (two epochs of one account, the same epoch for another
account), epochs refused, the normalization of an alias as the ChatPay API's `normalizeAlias`
does it (JavaScript `trim` and `toLowerCase`, which differ from Rust's on U+FEFF and U+0085),
and the seals the API makes. The ChatPay API replays it.

## Envelope

What the server stores and relays for each message:

| Field | Meaning |
|---|---|
| `protocol` | `olm-v1` |
| `olm_type` | `0`: a first message, which opens a session. `1`: a following message. |
| `ciphertext` | The Olm message, unpadded base64. |

A sealed envelope (since 0.10.0) has `protocol` `sealed-v1` (`sealed_protocol_id()`), the
recipient's identity id and the sealed `ciphertext` (*Sealed sender*), and no `olm_type`:
the Olm type is inside the seal.

The server also records which identities sent and received it, so a phone can tell
which identity a message was meant for.

## Content

The plaintext inside the ciphertext is a JSON object. Its field `v` is the content
version. Since 0.8.1 a phone writes only version 4 and reads versions 1, 2 and 4. The app
never builds nor reads this JSON itself: it calls `encode_content` with an
`OutgoingContent` record and `decode_content` with the plaintext and a `ContentBinding`;
`body` has one variant per kind.

### Version 4 (since 0.8.1)

The server no longer keeps conversations, so a content can no longer name one. Instead it
names who wrote it and for whom, as Matrix does inside an Olm payload (`sender`,
`recipient`, `keys` and `recipient_keys`, which a receiving client "MUST" check,
discarding any event that does not comply):

```json
{"v":4,"kind":"text","sender_account_id":"…","sender_ed25519":"…","recipient_account_id":"…","recipient_ed25519":"…","envelope_id":"…","client_message_id":"…","body":"…","pad":"   …"}
```

Fields come in this order: `v`, `kind`, `sender_account_id`, `sender_ed25519`,
`recipient_account_id`, `recipient_ed25519`, `envelope_id` (every kind but `typing`), the
fields of the kind as in version 2, then `pad`. Every kind of version 2 exists in version 4
with the same fields, plus three (since 0.8.0), one (since 0.9.0) and one (since 0.10.0):

| `kind` | Its own fields | Channel |
|---|---|---|
| `contact_request` | `attestation` (1 to 512 bytes), `attestation_signature` (base58 of 64 bytes) | mailbox |
| `contact_accept` | `request_id` (the envelope id of the request it accepts), `attestation`, `attestation_signature` | mailbox |
| `contact_cancel` | `request_id` (the envelope id of the request it withdraws) | mailbox |
| `access_key` (since 0.9.0) | `access_key` (base64 without padding of 16 bytes), `generation` (JSON integer, 1 to 2147483647) | mailbox |
| `alias_change` (since 0.11.0) | `attestation` (1 to 512 bytes), `attestation_signature` (base58 of 64 bytes): the form of `contact_request` | mailbox, version 4 only |
| `identity_statement` (since 0.10.0) | `account_public_key`, `curve25519_key`, `ed25519_key`, `sealing_key`, `created_at`, `identity_signature`, `account_signature`: the columns of the sender's statement v4 | mailbox |

Since 0.9.0 `contact_accept` may also carry, after `attestation_signature`,
`access_key` and `access_key_generation`: the accepting account's access key and its
generation, with the same forms as the `access_key` kind. Both come together or neither
(an acceptance written by 0.8.1 has neither); one without the other, a key in another
spelling, or a generation that is not a JSON integer from 1 to 2147483647 is
`InvalidContent`. The `access_key` kind is read only in version 4: in version 2 it is
`UnsupportedContent`.

The `alias_change` kind (since 0.11.0) has the form and the form checks of `contact_request`,
in version 4 only; any older version is `UnsupportedContent`, and the websocket is
`UnboundContent`. A contact sends it to each of their contacts when their alias changes.
`verify_alias_change(text, signature, trusted_keys, sender_account_id,
sender_account_public_key, deposited_at)` makes the checks of `verify_alias_attestation` and
returns `VerifiedAliasChange { alias, expires }`. The order of two changes is the order of
their `expires`, which the server signed inside the encrypted envelope, and never the date
of deposit, which the server can change: a contact applies a change only if its `expires` is
later than the last one applied for that sender, and an attestation whose alias is already
the contact's alias changes nothing.

The `identity_statement` kind (since 0.10.0) is read only in version 4 too. Its statement
must be a v4 whose own signatures hold, and its `ed25519_key` must be the content's
`sender_ed25519` (the identity whose session carried it); otherwise `InvalidContent`. It
falls in the 1024 byte bucket. The app still checks it against the account key and the
identity pinned for the contact, and keeps its sealing key only if `created_at` is later
than the statement it keeps.

The module checks only the form of an attestation here. Its alias comes out only of
`verify_alias_attestation` (*Alias attestation*); no kind carries an alias of its own. The
request id is the request's envelope id, so a cancellation or an acceptance names one
request and cannot touch another that replaced it.

The account ids are UUIDs written in lower case, and version 4 reads every id only in that
spelling: an id in upper case is `InvalidContent`.

`sender_ed25519` and `recipient_ed25519` are the ed25519 keys of the two Olm identities,
base64 without padding of 32 bytes, the one spelling `identity_keys` and `verify_identity`
give (any other is `InvalidContent`). They are what makes the link hold against the server:

- An identity statement is signed by the identity's ed25519 key and by the account key.
  Nothing in it proves that its author holds its curve25519 key, so anyone can publish a
  valid identity that carries another person's curve25519 key.
- Olm opens a first message for whoever is said to own that curve25519 key. A server could
  therefore hand Alice's message to Bob as Mallory's, Mallory being an account, the
  server's own or an accomplice's, whose identity carries Alice's curve25519 key. Bob's
  answers to Mallory would then be readable by Alice. No one reads anything they could not
  already open, but Bob is wrong about who wrote, and a safety number compared with
  Mallory does not show it.
- The account ids do not stop this: the server gives them, and can tell Alice that her
  own id is the one Bob knows as Mallory's. An ed25519 key cannot be borrowed that way,
  since an identity must be signed by it. Alice's content names her key, Bob binds the
  element to the key of Mallory's verified identity, and they differ.

The keys are those of the Olm identity, not the account key: an account key changes at
each rotation while the Olm keys stay, so a content sealed before a contact saw the
rotation still reads.

`decode_content(json, binding)` first reads the form (`InvalidContent`,
`UnsupportedContent` for a kind it does not know, for version 3 or for a `v` above 4),
then the link, and refuses any mismatch as `UnboundContent`, which the app drops without a
trace (it still acknowledges the element and keeps the advanced session). `binding` is
what the app knows of the element, every id a lower case UUID and every key base64
without padding of 32 bytes (any other spelling binds nothing):

- `channel`: `Mailbox` takes every kind but `typing`, `Websocket` only `typing`;
- `envelope_id`: the mailbox element's id, required on the mailbox and equal to the
  content's, absent on the websocket;
- `sender_account_id`: the element's sender, which chose the session; equal to the
  content's `sender_account_id`;
- `sender_ed25519_key`: the ed25519 key of that sender's verified identity, the very one
  whose keys the app gave to `decrypt_from` for this element; equal to the content's
  `sender_ed25519`. The app never takes it from the content;
- `my_account_id`: equal to the content's `recipient_account_id`;
- `my_ed25519_key`: the ed25519 key of this phone's identity (`identity_keys`); equal to
  the content's `recipient_ed25519`;
- `legacy_conversation_id`: see below; ignored for version 4.

When writing, the app gives `encode_content` its own account id and identity key, and the
recipient's account id with the ed25519 key of the verified identity it then encrypts for.

A version 1 or 2 content is read only on the mailbox, only when the app gives
`legacy_conversation_id`, and only when it equals the content's `conversation_id`; a
version 2 content's `envelope_id` must also equal the element's. The app gives that id
only for an element deposited before the switch, and only the one kept for that contact.
A legacy `typing` is refused on either channel. A version 1 or 2 content names no identity
key, so what version 4 closes stays open for these elements: the app should stop giving
the old conversation id at a date it sets itself, not one the server tells it.

Padding is as before, but nothing fits the smallest bucket (256 bytes) any more: the two
identity keys add about 130 bytes to the 115 of the two account ids. A `typing`, a
receipt, a cancellation, an `access_key` content (whatever its generation) and a short text (up to 110 bytes of body, without a reply) are at
512 bytes; a longer text, a contact request or acceptance and an `account_rotation` at
1024, and so on by powers of two. The longest text allowed, 4000 characters of 4 bytes,
is 18 bytes too long for 16384 and is padded to 32768; 4000 characters of one byte are at
8192. Encrypted on a confirmed session, a `typing` stays well under the 2048 characters the
server relays.

`vectors/v5.json` holds one content of each kind the app sends most, with its binding,
contents that must be refused as `UnboundContent` (among them the right account ids with
another identity key), a version 2 content read with and without its old conversation id,
and a version 3 content, refused.

### Version 3 (0.8.0 only, no longer read)

0.8.0 wrote the same content without `sender_ed25519` and `recipient_ed25519`:

```json
{"v":3,"kind":"text","sender_account_id":"…","recipient_account_id":"…","envelope_id":"…","client_message_id":"…","body":"…","pad":"   …"}
```

It was bound by the account ids alone, which the server gives (*Version 4*). No app was
published with 0.8.0, so since 0.8.1 a version 3 content is `UnsupportedContent`, whatever
its binding. `vectors/v4.json` keeps the version 3 contents of 0.8.0, which are now all
refused; its alias attestations are unchanged and still checked.

### Version 2 (since 0.5.0, read only since 0.8.0)

Every element the server delivers is a closed envelope: the server no longer sees its
kind, its target, its client id, nor whether it is a delivery or read receipt. Typing
signals travel through the websocket as the same kind of envelope, never stored.

```json
{"v":2,"kind":"text","conversation_id":"…","envelope_id":"…","client_message_id":"…","body":"…","reply_to_message_id":"…","reply_excerpt":"…","pad":"   …"}
```

Fields come in this order: `v`, `kind`, `conversation_id`, `envelope_id`, then the
fields of the kind in the order of the table, then `pad`. Every content has `v` (2),
`kind` and `conversation_id`. Every kind but `typing` has `envelope_id`, the random id
the sending phone drew for this envelope; a `typing` never has one (it is never stored).

| `kind` | Its own fields | Channel |
|---|---|---|
| `text` | `client_message_id`, `body` (1 to 4000 characters, not blank), `reply_to_message_id` (optional), `reply_excerpt` (optional, at most 200 characters) | mailbox |
| `edit` | `client_message_id`, `edits_message_id`, `body` (1 to 4000 characters, not blank) | mailbox |
| `reaction` | `client_message_id`, `reacts_to_message_id`, `body` (one emoji: 1 to 16 code points, no white space) | mailbox |
| `reaction_remove` | `client_message_id`, `reacts_to_message_id` | mailbox |
| `delete` | `client_message_id`, `deletes_message_id` | mailbox |
| `payment` | `client_message_id`, `body` (the card's comment or note, 1 to 500 characters, not blank) | mailbox, with its card |
| `receipt` | `status` (`delivered` or `read`), `up_to_envelope_id`, `up_to_created_at` | mailbox |
| `typing` | `state` (`start` or `stop`) | websocket only |
| `wallet_card` (since 0.6.0) | `wallet_address`, `account_public_key`, `wallet_signature` | mailbox |
| `wallet_card_request` (since 0.6.0) | none | mailbox |
| `payment_request` (since 0.6.0) | `request_id`, `amount_base_units`, `mint`, `decimals`, `note` (optional) | mailbox |
| `payment_sent` (since 0.6.0) | `request_id` (`null` for a direct payment), `signature`, `amount_base_units`, `mint`, `decimals`, `note` (optional) | mailbox |
| `payment_request_declined` (since 0.6.0) | `request_id` | mailbox |
| `payment_request_cancelled` (since 0.6.0) | `request_id` | mailbox |

Rules, all checked by the module, when written and when read:

- A version 2 content has exactly these fields, no more, no fewer (an optional field may
  be absent or `null`; `pad` is ignored when read). An unknown field is
  `InvalidContent`: a later addition goes through a version 3.
- `conversation_id`, `envelope_id`, `client_message_id`, every target
  (`reply_to_message_id`, `edits_message_id`, `reacts_to_message_id`,
  `deletes_message_id`) and `up_to_envelope_id` are well formed UUIDs (8-4-4-4-12
  hexadecimal digits). They are written and returned in lower case, whatever case the
  caller gave. A target is the envelope id of the targeted element.
- `up_to_created_at` is an RFC 3339 date with its offset (`Z` or `+hh:mm`), as the
  server gave it, for example `2026-11-04T12:34:56.789Z`. The module compares it with
  nothing.
- `envelope_id` is required on every kind but `typing`, and forbidden on `typing`.
- The wallet card and payment kinds (since 0.6.0) carry no `client_message_id`:
  `envelope_id` names the envelope, and `request_id` ties a request to what follows it.
  Their rules are in *Wallet card and payments* below.
- An unknown `kind`, or a `v` above 2, is `UnsupportedContent`: the message is authentic
  but this phone cannot show it. It is never read as another kind. A malformed content
  of a known kind is `InvalidContent`.

Since 0.8.0 the module itself checks the binding of a version 2 content (*Version 4*
above). Up to 0.7.1, the app checked that `conversation_id` and
`envelope_id` equal the element they came with (so a server can neither move an
envelope to another conversation nor replay it under another id), that each kind came
through its channel (the websocket accepts only `typing`, the mailbox everything but
`typing`), the author and time windows of an edit or delete, and until when a version 1
content is still accepted. The module draws no random value: the app draws
`envelope_id`.

A receipt covers every visible message of the conversation whose server date is at or
before the one of `up_to_envelope_id` (or `up_to_created_at`, when the phone no longer
has that message). A receipt never causes a receipt.

Padding is unchanged from version 1 (below): the smallest power of two, at least 256
bytes, that holds the JSON. A `typing` is always in the smallest bucket (256 bytes, its
JSON is about 96 bytes), and a `receipt` always in the next one (512 bytes: its JSON is at
least 251 bytes, more than the 247 that fit with the `pad` field in 256), the bucket of
a medium text. A short text and a payment comment stay at 256 bytes; an edit, a
reaction, its removal and a delete now land at 512 bytes, since `envelope_id` adds 53
bytes. Encrypted on a confirmed session (Olm type 1), a `typing` is a ciphertext of 427
base64 characters, well under the 2048 the server relays.

`vectors/v2.json` holds one padded content of each kind, how each version 1 kind is
read, and contents that must be refused (`UnsupportedContent` or `InvalidContent`).

### Wallet card and payments (since 0.6.0)

These six kinds are new kinds of version 2, not a version 3: `v` stays 2. A phone on 0.5.0
reads them as `UnsupportedContent`, never as another kind. The server sees none of them:
it no longer keeps any payment, nor the wallet address of an account.

```json
{"v":2,"kind":"payment_request","conversation_id":"…","envelope_id":"…","request_id":"…","amount_base_units":"1500000000","mint":"So11111111111111111111111111111111111111112","decimals":9,"note":"…","pad":"   …"}
```

Rules, all checked by the module, when written and when read (otherwise `InvalidContent`):

- `wallet_card`: the sender's wallet card. `wallet_address` and `account_public_key` are
  the base58 form of exactly 32 bytes, `wallet_signature` of exactly 64 bytes. The wallet
  signed the text `SOMBE wallet card v1\nwallet:<wallet_address>\naccount:<account_public_key>`
  (lines joined by `\n`, no final `\n`) once, and the same card is sent again as is.
  `decode_content` checks only the form of the fields; since 0.7.0 the app checks the
  signature with `verify_wallet_card`, and that `account_public_key` is the contact's
  pinned account key.
- `wallet_card_request` asks the contact to send their card again. It has no field of
  its own.
- `request_id` is a well formed UUID, written and returned in lower case like every other
  id. The requester's phone draws it (version 4); the module does not check the version.
  It is required on every payment kind but `payment_sent`, where `null` (or absent) means
  a direct payment, not tied to a request. The module writes `null` for a direct payment.
- `amount_base_units` is a JSON string of decimal digits only, without sign, space nor
  leading zero, from `1` to `9223372036854775807` (the largest signed 64 bit integer: the
  app signs transfers with a `Long`). For example `"1500000000"` for 1.5 SOL. Never a JSON
  number, never a decimal comma or point. In the `Content` record it is an `i64`.
- `mint` is always present: the base58 form of exactly 32 bytes (a mint may be off the
  curve). Native SOL is written `So11111111111111111111111111111111111111112`, and the
  app then sends a native SOL transfer, never wrapped SOL.
- `decimals` is a JSON integer from 0 to 255 (the range of an SPL mint).
- `note` is absent, `null`, or 1 to 500 characters counted in code points, not only white
  space. The module leaves it out when there is none; an empty note is refused.
- `signature` is the base58 form of exactly 64 bytes (a Solana transaction signature).

What the module does not check, and the app does: that the mint is one of the coins the
app accepts for this network and that `decimals` are those of that coin (the list changes
with the network, the module does not know it), who sent a refusal, a cancellation or a
payment tied to a request, and that a `payment_sent` agrees with its request.

Sizes, without a note: a request or a payment sent is 512 bytes, a refusal or a
cancellation 256 bytes, a wallet card 512 bytes and its request 256 bytes. By its size the
server can therefore tell a refusal or a cancellation from a request or a payment, without
seeing what it says (a known leak, accepted for version 2). A long note moves the
envelope to a larger bucket, like a long text: up to 4096 bytes for 500 emoji.

The old `payment` kind (the comment of a payment card the server kept) is still read by
0.6.0. The app no longer writes it: payments now travel as the kinds above.

### Account rotation (since 0.7.0)

Another new kind of version 2: the rotation proof and the new key's wallet card,
together. Not urgent, never shown in the conversation, never notified. A phone on 0.6.0
reads it as `UnsupportedContent`.

```json
{"v":2,"kind":"account_rotation","conversation_id":"…","envelope_id":"…","old_account_public_key":"…","new_account_public_key":"…","generation":2,"old_signature":"…","new_signature":"…","wallet_address":"…","wallet_signature":"…","pad":"   …"}
```

Checked when written and when read (otherwise `InvalidContent`): the two keys and the
address are canonical base58 of 32 bytes, the three signatures canonical base58 of 64
bytes, `generation` a JSON integer from 2 to 32767, the old key differs from the new
one, every field is present and there is no other. The signatures are checked by
`check_identity_update`, not by `decode_content`. In the `Content` record the variant is
`AccountRotation { rotation }`, whose record is the one `check_identity_update` takes. It
is padded to 1024 bytes.

### Reading version 1

A version 1 content is read with the rules of 0.4.0 (below; unknown fields ignored, ids
only checked to be present) and returned with `version` 1 and no `envelope_id`, every id
in lower case:

| Version 1 `kind` | Variant | Mapping |
|---|---|---|
| `text` | `Text` | `body` and `reply_excerpt` kept; `reply_to_message_id` absent (a version 1 quote had only an excerpt) |
| `payment` | `Payment` | its `comment` becomes `body`; empty when the card had none |
| `edit` | `Edit` | `edits_message_id` and `body` |
| `reaction` | `Reaction` | `reacts_to_message_id` and `body` |
| `reaction_remove` | `ReactionRemove` | `reacts_to_message_id` |
| `delete` | `Delete` | `deletes_message_id` |
| any other | none | `UnsupportedContent` (0.4.0 had no fallback either) |

### Version 1 (read only since 0.5.0)

Up to 0.4.0 the plaintext was this JSON. Since 0.5.0 it is still read, never written.

```json
{"v":1,"conversation_id":"…","client_message_id":"…","kind":"text","body":"…","reply_excerpt":"…"}
```

- `kind` is `text`, `payment`, (since 0.2.0) `edit` or `reaction`, (since 0.3.0)
  `reaction_remove`, or (since 0.4.0) `delete`. A text has a `body` (1 to 4000
  characters) and may carry `reply_excerpt` (at most 200 characters, the quoted message
  as the sender saw it). A payment carries only an optional `comment` (at most 500
  characters).
- An `edit` corrects an earlier text. It has a `body` (1 to 4000 characters, the new
  text) and `edits_message_id`, the server id of the corrected text, and carries neither
  `reply_excerpt` nor `comment`. No other kind may carry `edits_message_id`:

  ```json
  {"v":1,"conversation_id":"…","client_message_id":"…","kind":"edit","body":"…","edits_message_id":"…"}
  ```

  `edits_message_id` must equal the one on the server row, like the two other ids. A
  phone applies an edit only when its sender also wrote the corrected text, in the same
  conversation, so a server cannot point a correction at another message. A phone built
  before 0.2.0 refuses an `edit` as unreadable content.
- A `reaction` (since 0.2.0) sets one emoji on a text. Its `body` is the emoji, 1 to 16
  characters (code points) without any white space, and `reacts_to_message_id` is the
  server id of that text. It carries neither `reply_excerpt`, `comment` nor
  `edits_message_id`, and no kind but `reaction` and `reaction_remove` may carry
  `reacts_to_message_id`:

  ```json
  {"v":1,"conversation_id":"…","client_message_id":"…","kind":"reaction","body":"❤️","reacts_to_message_id":"…"}
  ```

  `reacts_to_message_id` must equal the one on the server row, so a server cannot move
  a reaction to another message. Each person has at most one reaction per text: the
  latest row wins. A phone built before 0.2.0 refuses a `reaction` as unreadable content.
- A `reaction_remove` (since 0.3.0) removes the sender's reaction from a text. It is
  encrypted like any other content, carries only `reacts_to_message_id` (no `body`,
  `reply_excerpt`, `comment` nor `edits_message_id`), and that id must equal the one on
  the server row:

  ```json
  {"v":1,"conversation_id":"…","client_message_id":"…","kind":"reaction_remove","reacts_to_message_id":"…"}
  ```

  Before 0.3.0 a removal was a server row that was never encrypted, so a server could
  invent one. A phone now applies a removal only from this encrypted content, sent by
  the person whose reaction it removes, and ignores a removal row without it. A server
  can still withhold any message, a removal included, but can no longer invent one. A
  phone built before 0.3.0 refuses a `reaction_remove` as unreadable content.
- A `delete` (since 0.4.0) deletes one of the sender's texts for everyone. It carries
  only `deletes_message_id`, the server id of that text (no `body`, `reply_excerpt`,
  `comment`, `edits_message_id` nor `reacts_to_message_id`), and no other kind may carry
  `deletes_message_id`:

  ```json
  {"v":1,"conversation_id":"…","client_message_id":"…","kind":"delete","deletes_message_id":"…"}
  ```

  `deletes_message_id` must equal the one on the server row. A phone applies a delete
  only when its sender also wrote the deleted text, in the same conversation: it then
  erases that text and its edits, shows that the message was deleted, and drops its
  reactions and the excerpt of any reply quoting it, whichever of the delete and the
  text arrives first. A server cannot point a delete at another message, nor make a
  phone erase anything without one; it can only withhold a delete, or empty a ciphertext
  it already stores. A phone built before 0.4.0 refuses a `delete` as unreadable
  content, so the text stays on that phone.
- `conversation_id` and `client_message_id` must equal the server row the message
  came with. A phone refuses content that does not match, so the server can neither
  move a message to another conversation nor replay it as a new one.
- Padding (since 0.3.0): the JSON ends with a `pad` field of spaces that brings its
  UTF-8 length to the next power of two, at least 256 bytes (256, 512, 1024, and so on). The other fields come first, then `"pad":"   …"` last. A reader
  ignores `pad`, and a content without it (from a phone built before 0.3.0) is still
  read; phones built before 0.3.0 ignore it in turn. The server then sees a size
  bucket, not a length: `Oui` and a sentence of a few words both encrypt to the same
  size, and so do a reaction, its removal and a short text.

## Sessions

- A first message (`olm_type` 0) whose session id matches no stored session opens a new
  inbound session and uses up the one time key it was built on.
- A following message (`olm_type` 1) is tried against the stored sessions with that
  identity. If none decrypts it, the message is unreadable; it never opens a session.
- Each message is decrypted once. The app stores the plaintext and the advanced session
  in the same database transaction, and resends an encrypted message with the exact same
  bytes, never encrypting it twice.
- Gaps (measured on vodozemac 0.11.1 by `tests/content.rs`): a message still decrypts
  after up to 2000 messages the receiver never got (typing signals dropped while the
  contact was offline), not after 2001. A message overtaken by a later one (a mailbox
  message read after a typing signal sent after it) can be read late only if that later
  one was at most 40 messages ahead of it; its key is lost otherwise.
- Accounts and sessions are stored only on the phone, as vodozemac pickles encrypted
  with a 32 byte key, and are never backed up or sent anywhere.
- Since 0.7.1 a stored session opens only for the contact it was made with. Its pickle is
  the text `v2:` followed by the vodozemac pickle, encrypted not with the pickle key but
  with `HKDF-SHA256(IKM = pickle key, salt = empty, info = "sombe:session_pickle:v2" ‖ the
  contact's curve25519 key (32 bytes), L = 32)`. `encrypt_for` and `decrypt_from` draw that
  key from the `remote` they are given, so a session passed with another contact is
  `InvalidPickle` (or `NoMatchingSession` when decrypting a following message): a mix up in
  the app can no longer encrypt to the wrong person. A pickle without `v2:`, written by
  0.7.0 or earlier, still opens with the pickle key and comes back bound. A session stored
  by 0.7.1 cannot be read by 0.7.0.
- The app must still never use the same stored session twice: two messages encrypted from
  one stored session share their key and IV. It writes the advanced session in the same
  transaction as the message, one encryption at a time, and keeps its database out of
  Android backups.

## Safety number

Two people check that no one sits between their phones by comparing a safety number,
in person (one scans the other's QR code) or by reading it aloud on a video call. Each
phone computes it from both verified identities; the server is not involved. Since 0.7.0
it is version 2, computed from the account key (a phone takes its own account key from
`ChatAccountKey.public_key()`).

1. For each identity, the input is this UTF-8 text:

   ```
   SOMBE safety number v2
   account:<account key, base58>
   curve25519:<identity curve25519 key>
   ed25519:<identity ed25519 key>
   ```

2. `h = SHA-512(input)`, then 5199 more times `h = SHA-512(h || input)`.
3. The first 30 bytes of `h`, cut into six chunks of 5 bytes, each read as a big endian
   integer and kept modulo 100000, written as 5 digits with leading zeros: 30 digits.
4. The two identities' 30 digit strings are sorted (as strings) and joined: 60 digits,
   shown as 12 groups of 5. Both phones get the same number whichever side computes it.
5. The QR code holds the text `SOMBE-SN2:` followed by the 60 digits. A phone that scans
   it compares those digits with its own: same (`Match`, the person can mark the contact
   verified), different (`Mismatch`), a version 1 code `SOMBE-SN1:` and 60 digits from a
   phone not yet on 0.7.0 (`OutdatedCode`), or not a SOMBE safety number.

Both account keys must differ (`InvalidKey` otherwise). The number changes as soon as
either account key or either Olm key changes, so a substituted key shows other digits on
each side, and so does a rotation: contacts lose their verified mark. Whether a contact
is verified is stored only on the phone that verified it, never sent to the server.

## What this does not protect

- Metadata: on the identified path, the server sees who talks to whom and when, and the
  size bucket of each message. The sealed sender (since 0.10.0) hides the sender of a
  sealed envelope from the server, not its recipient, its time, its size, nor the IP
  address it comes from. Payments are also public on the Solana
  blockchain, wallet to wallet.
- The very first contact trusts the account key the server gives for that contact. From
  then on the phone pins it, and another key without a rotation proof pauses the contact.
  Comparing the safety number is what removes that trust; until two people do it, they
  rely on it.
- A phone taken whole, recovery phrase and PIN included: the attacker is then the person,
  and can rotate the account key with a valid proof. Only comparing the codes again with
  the new phone would show it.
- Right after `/account/rotate`, the server sees an envelope of the same size bucket leave
  for each contact, which confirms a list of contacts it already knows.
- The safety number v2 no longer covers the wallet address: only the wallet card vouches
  for it.
- The generation of a rotation is stated by the two account keys, not by the wallet: the
  wallet card does not carry it. Whoever holds two account keys of the same wallet (without
  the wallet key) can therefore sign a proof between them with any generation: one at 32767,
  after which that contact refuses every later rotation until the safety codes are compared
  again, or one that goes back to the earlier key. Someone who holds only a key already
  left can do neither, since the proof must be signed by the pinned key. A known limit,
  accepted: it reads no message and moves no payment, and closing it needs a wallet card
  that carries the generation.
- The wallet seed passes through the app's memory (the JVM) when the account key is
  derived or rotated; it is already there for Solana. The module erases its own copies,
  not the app's, nor the buffer UniFFI copies the call's bytes into on the way in.
- The unblinding factor of an alias token passes through the app's memory (the JVM) and is
  kept in the vault; the module erases its own copies, not the app's. The library draws the
  blinding factor with `random_mod_vartime`, which is not constant time: it tells nothing to
  someone who is not already on the phone. `blind-rsa-signatures` has no published paid
  audit; its version is pinned with `=`, and the RFC 9474 vector is replayed in CI.
- The server sees when a vault is written and its size (always the same), and that a token
  is spent, never by whom. A phone that keeps a vault older than the server's is merged,
  never overwritten by the server.
- No post quantum protection (Olm has none, nor does the X25519 suite of the sealed
  sender).
- The crate `hpke` (sealed sender) has no published paid audit. Its version is pinned with
  `=`, and the RFC 9180 test vectors of our suite are replayed in this repository's CI.
- One phone per wallet. A restored wallet gets a new identity and cannot read older
  messages.
