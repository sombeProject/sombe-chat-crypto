# SOMBE chat crypto, protocol `olm-v1`

This is how SOMBE ChatPay encrypts messages between two people. Messages are
encrypted on the sender's phone and only the recipient's phone can read them. The
SOMBE server stores and relays ciphertext; it never sees the text.

The cryptography is [vodozemac](https://github.com/matrix-org/vodozemac), the
Matrix project's Rust implementation of Olm (the Double Ratchet with an X3DH style
handshake, as in Signal). This repository only adds the thin layer SOMBE needs on top:
an identity signed by the person's Solana wallet, signed one time keys, the envelope,
the content format, and the safety number two people compare. Nothing here invents new
cryptography.

`vectors/v1.json` holds test vectors for every format below.

## Identity

Each wallet has at most one active chat identity: an Olm account living on one phone.
Its two public keys (`curve25519`, `ed25519`, unpadded base64) and the wallet vouch for
each other with this UTF-8 text:

```
SOMBE chat identity v2
protocol:olm-v1
wallet:<wallet address, base58>
curve25519:<identity curve25519 key>
ed25519:<identity ed25519 key>
created:<ISO 8601 UTC, e.g. 2026-10-14T18:30:01.183Z>
identity_signature:<signature of the six lines above by the identity ed25519 key, base64>
```

Lines are separated by a single `\n`, with no trailing newline. The identity's ed25519
key first signs the first six lines (the body, also without a trailing newline), so the
identity vouches for the wallet: without it, any wallet could sign a statement naming
someone else's keys. The wallet then signs the whole seven line text with its ed25519
key (the Solana key); that signature is the 64 byte ed25519 signature in base58.

A verifier checks the wallet signature against the wallet address it expects (never
against an address taken from the text alone), then checks the text is exactly this
format, then checks `identity_signature` against the `ed25519` key of the text. A `v1`
statement (0.2.0 and earlier, six lines and no identity signature) is refused: each
identity publishes a `v2` statement again, signed by its wallet.

The server checks the statement before accepting an identity, and refuses one that is
older than the previous identity of the same wallet or more than 24 hours away from
its clock. The app checks it again before it encrypts anything to a contact, against
the wallet address it pinned for that contact the first time it saw it.

The app also pins the contact's latest verified identity, and compares each identity it
receives with it (`check_identity_update`):

- Nothing pinned yet: the identity is new, the app pins it.
- Same `curve25519` and `ed25519` keys: unchanged.
- Other keys and a strictly later `created`: the contact moved to a new phone. The app
  pins the new identity, removes the contact's verified mark and shows that the safety
  number changed.
- Other keys and the same or an earlier `created`: refused. A server that relays an old,
  validly signed identity (from a lost or stolen phone, say) cannot bring it back.
- Another wallet: refused; a changed address blocks sending, as above.

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

The plaintext inside the ciphertext is JSON:

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
- Accounts and sessions are stored only on the phone, as vodozemac pickles encrypted
  with a 32 byte key, and are never backed up or sent anywhere.

## Safety number

Two people check that no one sits between their phones by comparing a safety number,
in person (one scans the other's QR code) or by reading it aloud on a video call. Each
phone computes it from both verified identities; the server is not involved.

1. For each identity, the input is this UTF-8 text:

   ```
   SOMBE safety number v1
   wallet:<wallet address, base58>
   curve25519:<identity curve25519 key>
   ed25519:<identity ed25519 key>
   ```

2. `h = SHA-512(input)`, then 5199 more times `h = SHA-512(h || input)`.
3. The first 30 bytes of `h`, cut into six chunks of 5 bytes, each read as a big endian
   integer and kept modulo 100000, written as 5 digits with leading zeros: 30 digits.
4. The two identities' 30 digit strings are sorted (as strings) and joined: 60 digits,
   shown as 12 groups of 5. Both phones get the same number whichever side computes it.
5. The QR code holds the text `SOMBE-SN1:` followed by the 60 digits. A phone that scans
   it compares those digits with its own: same (`Match`, the person can mark the contact
   verified), different (`Mismatch`), or not a SOMBE safety number.

Both wallets must differ. The number changes as soon as either wallet or either key
changes, so a substituted key shows other digits on each side. Whether a contact is
verified is stored only on the phone that verified it, never sent to the server.

## What this does not protect

- Metadata: the server sees who talks to whom and when (no sealed sender, no hidden
  timing), and the size bucket of each message. Payments are also public on the Solana
  blockchain, wallet to wallet.
- The very first contact trusts the wallet address the server gives for that contact.
  From then on the phone pins it, and a changed address blocks sending. Comparing the
  safety number is what removes that trust; until two people do it, they rely on it.
- No post quantum protection (Olm has none).
- One phone per wallet. A restored wallet gets a new identity and cannot read older
  messages.
