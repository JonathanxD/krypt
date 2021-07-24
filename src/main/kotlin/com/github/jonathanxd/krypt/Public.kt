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
package com.github.jonathanxd.krypt

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom

fun ByteArray.loadPublicKey(): PGPPublicKey {
    val ring = BcPGPPublicKeyRingCollection(
        PGPUtil.getDecoderStream(ByteArrayInputStream(this))
    )

    return ring.keyRings.next().publicKey
}

fun ByteArray.encrypt(
    publicKey: PGPPublicKey,
    armored: Boolean = false
): ByteArray = publicKey.encrypt(this, armored)

fun PGPPublicKey.encrypt(
    content: ByteArray,
    armored: Boolean = false
): ByteArray {
    val contentStream: InputStream = ByteArrayInputStream(content)

    val generator = PGPEncryptedDataGenerator(
        BcPGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
            .setWithIntegrityPacket(true)
            .setSecureRandom(SecureRandom())
    )

    generator.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(this))


    val byteOutputStream = ByteArrayOutputStream()
    var outputStream: OutputStream = byteOutputStream

    if (armored) {
        outputStream = ArmoredOutputStream(byteOutputStream)
    }

    val encryptOutputStream = generator.open(byteOutputStream, ByteArray(2048))
    contentStream.copyTo(encryptOutputStream, 8 * 1024)

    if (armored) {
        outputStream.flush()
        outputStream.close()
    }

    byteOutputStream.close()
    encryptOutputStream.close()

    return byteOutputStream.toByteArray()
}

fun ByteArray.checkSignature(publicKey: PGPPublicKey, originalContent: ByteArray): Boolean =
    publicKey.checkSignature(this, originalContent)

fun PGPPublicKey.checkSignature(signedContent: ByteArray, originalContent: ByteArray): Boolean {
    val bais = ByteArrayInputStream(signedContent)

    val decodeStream = PGPUtil.getDecoderStream(bais)

    val factory = PGPObjectFactory(decodeStream, BcKeyFingerprintCalculator())
    val l = factory.nextObject() as PGPSignatureList
    val pgpSignature = l.iterator().next()

    pgpSignature.init(
        BcPGPContentVerifierBuilderProvider(),
        this
    )
    pgpSignature.update(originalContent)

    return pgpSignature.verify()
}