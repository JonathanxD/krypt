# Krypt

Kotlin Extension functions to work with BouncyCastle to encrypt, decrypt and sign data using Public Key and Private Key.

## How to use

Add gradle dependency:

```kotlin
repositories {
    maven(url="https://jitpack.io")
}

dependencies {
    implementation("com.github.JonathanxD:krypt:1.0.3")
}
```

### Load Private and public key
```kotlin
val gpgPrivateKey: ByteArray = byteArrayOf(/* Private Key Bytes*/)
val gpgPublicKey: ByteArray = byteArrayOf(/* Armored Public Key Bytes*/)
val keyPassphrase = "PASSWORD"
val privateKey = gpgPrivateKey.loadPrivateKey(keyPassphrase)
val publicKey = gpgPublicKey.loadPublicKey()
```

#### Encrypt data with public key

```kotlin
val encryptedData = publicKey.encrypt("Example".encodeToByteArray())
```

##### Decrypt with private key

```kotlin
val decryptedData = privateKey.decrypt(encryptedData).decodeToString()
```

#### Sign data with Public and Private Key

```kotlin
val signedData = (privateKey and publicKey).sign("Example".encodeToByteArray())
```

##### Check signature with Public Key

```kotlin
val validSignature = publicKey.checkSignature(signedData, "Example".encodeToByteArray())
```
