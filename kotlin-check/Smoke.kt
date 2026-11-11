// Compiled with kotlinc 1.7.21 (the SOMBE app's Kotlin) against the generated bindings,
// then run on the JVM with the host library: proves the bindings work from that Kotlin.
import org.sombe.chatcrypto.ChatCrypto
import org.sombe.chatcrypto.ChatCryptoException
import org.sombe.chatcrypto.Content
import org.sombe.chatcrypto.ContentBody
import org.sombe.chatcrypto.IdentityUpdate
import org.sombe.chatcrypto.ReceiptStatus
import org.sombe.chatcrypto.ScanResult
import org.sombe.chatcrypto.TypingState
import org.sombe.chatcrypto.VerifiedIdentity
import org.sombe.chatcrypto.checkIdentityUpdate
import org.sombe.chatcrypto.compareScannedSafetyCode
import org.sombe.chatcrypto.decodeContent
import org.sombe.chatcrypto.encodeContent
import org.sombe.chatcrypto.safetyNumber
import org.sombe.chatcrypto.verifyOneTimeKey

fun check(condition: Boolean, what: String) {
    if (!condition) throw IllegalStateException("FAILED: $what")
    println("ok  $what")
}

fun main() {
    val key = ByteArray(32) { 7 }
    val alice = ChatCrypto.createAccount()
    val bob = ChatCrypto.createAccount()

    val otk = bob.generateOneTimeKeys(3u).first()
    bob.markKeysPublished()
    check(verifyOneTimeKey(bob.identityKeys(), otk), "one time key signature verifies")

    val conversation = "0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01"
    val target = "3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34"
    val content = Content(
        version = 2u,
        conversationId = conversation,
        envelopeId = "7c4f1e3b-0d8a-4f5b-9e9c-2a3b4c5d6e78",
        body = ContentBody.Text(
            clientMessageId = "1c8f5e7b-4d2a-4f9b-8e3c-6a7b8d9e0f12",
            body = "Salut ! Tu es rentré ?",
            replyToMessageId = null,
            replyExcerpt = null,
        ),
    )
    val first = alice.encryptFor(bob.identityKeys(), null, otk, encodeContent(content), key)
    check(first.envelope.olmType.toInt() == 0, "first message is type 0")

    val received = bob.decryptFrom(alice.identityKeys(), emptyList(), first.envelope, key)
    check(decodeContent(received.plaintext) == content, "bob reads alice's first message")

    // One variant per kind, each read back as itself.
    val bodies = listOf(
        ContentBody.Edit("2d9a6f8c-5e3b-4a0c-9f4d-7b8c9e0f1a23", target, "Salut ! Tu es rentrée ?"),
        ContentBody.Reaction("4f1c8b0e-7a5d-4c2e-9b6f-9d0e1f2a3c45", target, "❤️"),
        ContentBody.ReactionRemove("5a2d9c1f-8b6e-4d3f-8c7a-0e1f2a3b4d56", target),
        ContentBody.Delete("6b3e0d2a-9c7f-4e4a-8d8b-1f2a3b4c5e67", target),
        ContentBody.Payment("f4c19abd-8f6c-4b3d-9a7e-0c1d2e3f4a56", "Pour le marché"),
        ContentBody.Receipt(ReceiptStatus.READ, content.envelopeId!!, "2026-11-04T12:34:56Z"),
    )
    for (body in bodies) {
        val each = content.copy(body = body)
        check(decodeContent(encodeContent(each)) == each, "${body::class.simpleName} round trips")
    }
    val typing = content.copy(envelopeId = null, body = ContentBody.Typing(TypingState.START))
    check(decodeContent(encodeContent(typing)) == typing, "a typing signal round trips")
    check(encodeContent(typing).encodeToByteArray().size == 256, "a typing signal is padded to 256 bytes")
    check(
        encodeContent(content.copy(body = bodies.last())).encodeToByteArray().size == 512,
        "a receipt is padded to 512 bytes",
    )
    // Since 0.6.0: the wallet card and the payments travel encrypted too.
    val sol = "So11111111111111111111111111111111111111112"
    val signature = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"
    val requestId = "27f4cde0-bc9f-4e6a-8dab-3f4a5b6c7d89"
    val newKinds = listOf(
        ContentBody.WalletCard("FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF", "3ogUn1GNXoASaRbxPNeVJnVv5rG4EPBtmQmX61jVorUe", signature),
        ContentBody.WalletCardRequest,
        ContentBody.PaymentRequest(requestId, Long.MAX_VALUE, sol, 9u, "Pour le marché"),
        ContentBody.PaymentSent(null, signature, 1_500_000_000L, sol, 9u, null),
        ContentBody.PaymentRequestDeclined(requestId),
        ContentBody.PaymentRequestCancelled(requestId),
    )
    for (body in newKinds) {
        val each = content.copy(body = body)
        check(decodeContent(encodeContent(each)) == each, "${body::class.simpleName} round trips")
    }
    check(
        encodeContent(content.copy(body = newKinds[2])).encodeToByteArray().size == 512,
        "a payment request is padded to 512 bytes",
    )
    check(
        encodeContent(content.copy(body = newKinds[4])).encodeToByteArray().size == 256,
        "a refusal is padded to 256 bytes",
    )
    try {
        encodeContent(content.copy(body = ContentBody.PaymentRequest(requestId, 0L, sol, 9u, null)))
        check(false, "an amount of 0 must throw")
    } catch (e: ChatCryptoException.InvalidContent) {
        check(true, "an amount of 0 is refused")
    }
    try {
        encodeContent(typing.copy(envelopeId = content.envelopeId))
        check(false, "a typing signal with an envelope id must throw")
    } catch (e: ChatCryptoException.InvalidContent) {
        check(true, "a typing signal with an envelope id is refused")
    }
    try {
        encodeContent(content.copy(version = 1u))
        check(false, "version 1 must not be written")
    } catch (e: ChatCryptoException.InvalidContent) {
        check(true, "version 1 is never written")
    }
    try {
        decodeContent("""{"v":2,"kind":"poll","conversation_id":"$conversation","envelope_id":"$target"}""")
        check(false, "an unknown kind must throw")
    } catch (e: ChatCryptoException.UnsupportedContent) {
        check(true, "an unknown kind is UnsupportedContent")
    }
    val legacy = decodeContent(
        """{"v":1,"conversation_id":"${conversation.uppercase()}","client_message_id":"c","kind":"payment","comment":"Merci"}"""
    )
    check(
        legacy.version.toInt() == 1 && legacy.envelopeId == null && legacy.conversationId == conversation &&
            legacy.body == ContentBody.Payment("c", "Merci"),
        "a version 1 card is read, its comment as body, ids in lower case",
    )
    check(received.newSession && received.accountChanged, "a new inbound session was opened")

    val reply = bob.encryptFor(alice.identityKeys(), received.session, null, "Oui", key)
    val read = alice.decryptFrom(bob.identityKeys(), listOf(first.session), reply.envelope, key)
    check(read.plaintext == "Oui", "alice reads bob's reply")

    val restored = ChatCrypto.restoreAccount(bob.pickle(key), key)
    check(restored.identityKeys() == bob.identityKeys(), "account pickle round trip")

    try {
        alice.decryptFrom(bob.identityKeys(), emptyList(), reply.envelope, key)
        check(false, "no session must throw")
    } catch (e: ChatCryptoException.NoMatchingSession) {
        check(true, "following message without a session throws NoMatchingSession")
    }

    // Identities as verifyIdentity returns them (the wallet signatures are checked in Rust tests).
    fun identity(of: ChatCrypto, wallet: String, created: String) = VerifiedIdentity(
        walletAddress = wallet,
        curve25519Key = of.identityKeys().curve25519Key,
        ed25519Key = of.identityKeys().ed25519Key,
        createdAt = created,
    )
    val aliceId = identity(alice, "AliceWallet", "2026-10-14T18:30:01.183Z")
    val bobId = identity(bob, "BobWallet", "2026-10-14T18:30:01.183Z")
    val code = safetyNumber(aliceId, bobId)
    check(code == safetyNumber(bobId, aliceId), "both phones get the same safety number")
    check(code.digits.length == 60 && code.groups.size == 12, "60 digits in 12 groups")
    check(compareScannedSafetyCode(aliceId, bobId, code.qrPayload) == ScanResult.MATCH, "scanned code matches")
    check(
        compareScannedSafetyCode(aliceId, bobId, "https://example.com") == ScanResult.NOT_A_SAFETY_CODE,
        "a foreign QR code is not a safety code",
    )

    val bobNewPhone = ChatCrypto.createAccount()
    val bobLater = identity(bobNewPhone, "BobWallet", "2026-10-15T09:00:00Z")
    check(checkIdentityUpdate(null, bobId) == IdentityUpdate.NEW, "first identity is pinned")
    check(checkIdentityUpdate(bobId, bobLater) == IdentityUpdate.CHANGED, "a newer identity is a change")
    try {
        checkIdentityUpdate(bobLater, bobId)
        check(false, "an older identity must throw")
    } catch (e: ChatCryptoException.StaleIdentity) {
        check(true, "an older identity is refused")
    }

    listOf(alice, bob, restored, bobNewPhone).forEach { it.close() }
    println("Kotlin ${KotlinVersion.CURRENT}: all checks passed")
}
