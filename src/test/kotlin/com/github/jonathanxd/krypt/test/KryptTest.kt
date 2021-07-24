/**
 *      krypt - Extensions functions to work with BouncyCastle PGP
 *              Public and Private key Data encryption, decryption and signing.
 *
 *         The MIT License (MIT)
 *
 *      Copyright (c) JonathanxD <https://github.com/JonathanxD/>
 *      Copyright (c) contributors
 *
 *      Permission is hereby granted, free of charge, to any person obtaining a copy
 *      of this software and associated documentation files (the "Software"), to deal
 *      in the Software without restriction, including without limitation the rights
 *      to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *      copies of the Software, and to permit persons to whom the Software is
 *      furnished to do so, subject to the following conditions:
 *
 *      The above copyright notice and this permission notice shall be included in
 *      all copies or substantial portions of the Software.
 *
 *      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *      IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *      FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *      AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *      LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *      OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *      THE SOFTWARE.
 */
package com.github.jonathanxd.krypt.test

import com.github.jonathanxd.krypt.*
import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class KryptTest {

    @Test
    fun signatureTest() {
        val private = GPG_PRIVATE_KEY.loadPrivateKey(PASSPHRASE)
        val public = GPG_PUBLIC_KEY.loadPublicKey()

        val signed = (private and public).sign("Example".encodeToByteArray())

        assertTrue {
            public.checkSignature(signed, "Example".encodeToByteArray())
        }

        assertFalse {
            public.checkSignature(signed, "elpmaxE".encodeToByteArray())
        }
    }

    @Test
    fun encryptTest() {
        val private = GPG_PRIVATE_KEY.loadPrivateKey(PASSPHRASE)
        val public = GPG_PUBLIC_KEY.loadPublicKey()

        val encrypted = public.encrypt("Example".encodeToByteArray())
        val decrypt = private.decrypt(encrypted).decodeToString()

        assertEquals("Example", decrypt)
    }
}

const val PASSPHRASE = "1krypt-test**/"

val GPG_PUBLIC_KEY = ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
        "\n" +
        "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\n" +
        "F0yncYPrayIxP8ZjYQ==\n" +
        "=MrMb\n" +
        "-----END PGP PUBLIC KEY BLOCK-----\n").encodeToByteArray()

val GPG_PRIVATE_KEY = ("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\n")
            .replace(Regex("\\n"), "")
            .let {
                Base64.getDecoder().decode(it)
            }