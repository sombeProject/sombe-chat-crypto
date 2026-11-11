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
`chacha20poly1305`.

`vectors/v1.json` holds test vectors written by 0.4.0 (its identity statement and safety
number are no longer read since 0.7.0; its keys, sessions and version 1 contents still
are), `vectors/v2.json` those of content version 2 (since 0.5.0; wallet card and payment
kinds since 0.6.0), and `vectors/v3.json` those of the account key (since 0.7.0): its
derivation, the sealed key, the wallet card and its fingerprint, the four texts it signs,
the rotation proof, the `account_rotation` content and the safety number v2. The ChatPay
server replays `vectors/v3.json` byte for byte, so the server and the module never build
a text differently.

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
`created_at` that is not this ISO 8601 UTC form is `InvalidStatement`.

The server stores and returns only the fields, never the text. A verifier calls
`verify_identity` with those fields (`account_public_key`, `curve25519_key`,
`ed25519_key`, `created_at`, `identity_signature`, `account_signature`): the module
rebuilds the seven lines itself, checks `identity_signature` over the first six with the
`ed25519` key, then `account_signature` over the seven with `account_public_key`. The app
never builds a statement text. Statements v1 (0.2.0 and earlier) and v2 (signed by the
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

## Envelope

What the server stores and relays for each message:

| Field | Meaning |
|---|---|
| `protocol` | `olm-v1` |
| `olm_type` | `0`: a first message, which opens a session. `1`: a following message. |
| `ciphertext` | The Olm message, unpadded base64. |

The server also records which identities sent and received it, so a phone can tell
which identity a message was meant for.

## Content

The plaintext inside the ciphertext is a JSON object. Its field `v` is the content
version. Since 0.5.0 a phone writes only version 2 and reads versions 1 and 2. The app
never builds nor reads this JSON itself: it calls `encode_content` and `decode_content`
with a `Content` record, whose `body` has one variant per kind.

### Version 2 (since 0.5.0)

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

What the module does not check, and the app does: that `conversation_id` and
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

- Metadata: the server sees who talks to whom and when (no sealed sender, no hidden
  timing), and the size bucket of each message. Payments are also public on the Solana
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
- The wallet seed passes through the app's memory (the JVM) when the account key is
  derived or rotated; it is already there for Solana. The module erases its own copies,
  not the app's, nor the buffer UniFFI copies the call's bytes into on the way in.
- No post quantum protection (Olm has none).
- One phone per wallet. A restored wallet gets a new identity and cannot read older
  messages.
