// Compiled with kotlinc 1.7.21 (the SOMBE app's Kotlin) against the generated bindings,
// then run on the JVM with the host library: proves the bindings work from that Kotlin.
import org.sombe.chatcrypto.ChatCrypto
import org.sombe.chatcrypto.ChatCryptoException
import org.sombe.chatcrypto.ContentKind
import org.sombe.chatcrypto.MessageContent
import org.sombe.chatcrypto.decodeContent
import org.sombe.chatcrypto.encodeContent
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

    val content = MessageContent(
        conversationId = "0b7e4d6a-3c1f-4e8a-9d2b-5f6a7c8e9d01",
        clientMessageId = "1c8f5e7b-4d2a-4f9b-8e3c-6a7b8d9e0f12",
        kind = ContentKind.TEXT,
        body = "Salut ! Tu es rentré ?",
        replyExcerpt = null,
        comment = null,
    )
    val first = alice.encryptFor(bob.identityKeys(), null, otk, encodeContent(content), key)
    check(first.envelope.olmType.toInt() == 0, "first message is type 0")

    val received = bob.decryptFrom(alice.identityKeys(), emptyList(), first.envelope, key)
    check(decodeContent(received.plaintext) == content, "bob reads alice's first message")
    check(content.editsMessageId == null, "a text built without editsMessageId (as in 0.1.0) still works")

    val edit = MessageContent(
        conversationId = content.conversationId,
        clientMessageId = "2d9a6f8c-5e3b-4a0c-9f4d-7b8c9e0f1a23",
        kind = ContentKind.EDIT,
        body = "Salut ! Tu es rentrée ?",
        replyExcerpt = null,
        comment = null,
        editsMessageId = "3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34",
    )
    check(decodeContent(encodeContent(edit)) == edit, "an edit round trips")
    try {
        encodeContent(edit.copy(editsMessageId = null))
        check(false, "an edit without target must throw")
    } catch (e: ChatCryptoException.InvalidContent) {
        check(true, "an edit without edits_message_id is refused")
    }
    check(edit.reactsToMessageId == null, "an edit built without reactsToMessageId still works")

    val reaction = MessageContent(
        conversationId = content.conversationId,
        clientMessageId = "4f1c8b0e-7a5d-4c2e-9b6f-9d0e1f2a3c45",
        kind = ContentKind.REACTION,
        body = "❤️",
        replyExcerpt = null,
        comment = null,
        reactsToMessageId = "3e0b7a9d-6f4c-4b1d-8a5e-8c9d0e1f2b34",
    )
    check(decodeContent(encodeContent(reaction)) == reaction, "a reaction round trips")
    try {
        encodeContent(reaction.copy(body = "👍 👍"))
        check(false, "a reaction with a space must throw")
    } catch (e: ChatCryptoException.InvalidContent) {
        check(true, "a reaction with a space is refused")
    }
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

    listOf(alice, bob, restored).forEach { it.close() }
    println("Kotlin ${KotlinVersion.CURRENT}: all checks passed")
}
