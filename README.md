# Virgil Security PHP Crypto Library

### [Introduction](#introduction) | [Library purposes](#library-purposes) | [Usage examples](#usage-examples) | [Installation](#installation) | [Docs](#docs) | [License](#license) | [Contacts](#support)

## Introduction
VirgilCrypto is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and an open-source high-level [cryptographic library](https://github.com/VirgilSecurity/virgil-crypto) that allows you to perform all necessary operations for securely storing and transferring data in your digital solutions. Crypto Library is written in C++ and is suitable for mobile and server platforms.

Virgil Security, Inc., guides software developers into the forthcoming security world in which everything will be encrypted (and passwords will be eliminated). In this world, the days of developers having to raise millions of dollars to build a secure chat, secure email, secure file-sharing, or a secure anything have come to an end. Now developers can instead focus on building features that give them a competitive market advantage while end-users can enjoy the privacy and security they increasingly demand.

## Library purposes
* Asymmetric Key Generation
* Encryption/Decryption of data and streams
* Generation/Verification of digital signatures
* PFS (Perfect Forward Secrecy)

## Usage examples

#### Generate a key pair

Generate a Private Key with the default algorithm (EC_X25519):
```php
use Virgil\CryptoImpl\VirgilCrypto;

$crypto = new VirgilCrypto();
$keyPair = $crypto->generateKeys();
```

#### Generate and verify a signature

Generate signature and sign data with a private key:
```php
use Virgil\CryptoImpl\VirgilCrypto;

$crypto = new VirgilCrypto();

// prepare a message
$messageToSign = "Hello, Bob!";

// generate a signature
$signature = $crypto->generateSignature($messageToSign, $senderPrivateKey);
```

Verify a signature with a public key:
```php
use Virgil\CryptoImpl\VirgilCrypto;

$crypto = new VirgilCrypto();

// verify a signature
$crypto->verifySignature($signature, $dataToSign, $senderPublicKey);
```
#### Encrypt and decrypt data

Encrypt Data on a Public Key:

```php
use Virgil\CryptoImpl\VirgilCrypto;

$crypto = new VirgilCrypto();

// prepare a message
$messageToEncrypt = "Hello, Bob!";

// encrypt the message
$encryptedData = $crypto->encrypt($messageToEncrypt, $receiverPublicKey);
```
Decrypt the encrypted data with a Private Key:
```php
use Virgil\CryptoImpl\VirgilCrypto;

$crypto = new VirgilCrypto();

// prepare data to be decrypted
$decryptedData = $crypto->decrypt($encryptedData, $receiverPrivateKey);
```
Need more examples? Visit our [developer documentation](https://developer.virgilsecurity.com/docs/how-to#cryptography).

## Installation

### Requirements

* PHP 5.6 and newer
* virgil_crypto_php extension

You can download virgil_crypto_php extension from our [CDN](https://cdn.virgilsecurity.com/virgil-crypto/php/).

### Installation via composer

```bash
composer require virgil/crypto
```

## Docs
- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto)
- [More usage examples](https://developer.virgilsecurity.com/docs/how-to#cryptography)

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://join.slack.com/t/VirgilSecurity/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).
