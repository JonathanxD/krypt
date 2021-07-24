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

import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

fun ByteArray.loadPrivateKey(passphrase: String): PGPPrivateKey {
    val privateRing = PGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(ByteArrayInputStream(this)),
        BcKeyFingerprintCalculator()
    )

    return privateRing.keyRings.next().secretKey.extractPrivateKey(
        BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
            .build(passphrase.toCharArray())
    )
}

infix fun PGPPrivateKey.and(publicKey: PGPPublicKey): Pair<PGPPrivateKey, PGPPublicKey> =
    this to publicKey

infix fun PGPPublicKey.and(privateKey: PGPPrivateKey): Pair<PGPPrivateKey, PGPPublicKey> =
    privateKey to this

fun ByteArray.sign(
    publicKey: PGPPublicKey,
    privateKey: PGPPrivateKey,
    hashAlgorithm: Int = PGPUtil.SHA1
): ByteArray = (privateKey to publicKey).sign(this, hashAlgorithm)

fun PGPPrivateKey.sign(
    publicKey: PGPPublicKey,
    content: ByteArray,
    hashAlgorithm: Int = PGPUtil.SHA1
): ByteArray = (this to publicKey).sign(content, hashAlgorithm)

fun Pair<PGPPrivateKey, PGPPublicKey>.sign(
    content: ByteArray,
    hashAlgorithm: Int = PGPUtil.SHA1
): ByteArray {
    val (privateKey, publicKey) = this
    val generator = PGPSignatureGenerator(
        BcPGPContentSignerBuilder(publicKey.algorithm, hashAlgorithm)
            .setSecureRandom(SecureRandom())
    )
    generator.init(PGPSignature.BINARY_DOCUMENT, privateKey)
    generator.update(content)

    val baos = ByteArrayOutputStream()
    val bout = BCPGOutputStream(baos)
    generator.generate().encode(bout)

    bout.close()
    baos.close()
    return baos.toByteArray()
}

fun ByteArray.decrypt(
    privateKey: PGPPrivateKey
): ByteArray =
    privateKey.decrypt(this)

fun PGPPrivateKey.decrypt(
    content: ByteArray
): ByteArray {
    val bais = ByteArrayInputStream(content)

    val decodeStream = PGPUtil.getDecoderStream(bais)

    val factory = PGPObjectFactory(decodeStream, BcKeyFingerprintCalculator())

    val o = factory.nextObject()
    val l: PGPEncryptedDataList = if (o is PGPEncryptedDataList) {
        o
    } else {
        factory.nextObject() as PGPEncryptedDataList
    }

    val pgpEncryptedData = l.iterator().next() as PGPPublicKeyEncryptedData
    val dataStream = pgpEncryptedData.getDataStream(BcPublicKeyDataDecryptorFactory(this))

    val baos = ByteArrayOutputStream()

    dataStream.copyTo(baos, 8 * 1024)

    return baos.toByteArray()
}