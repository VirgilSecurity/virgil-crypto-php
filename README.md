# Virgil Security PHP Crypto Library

[![Build Status](https://api.travis-ci.com/VirgilSecurity/virgil-crypto-php.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-crypto-php/)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/virgil/crypto.svg?style=flat-square)](https://packagist.org/packages/virgil/crypto)
[![Total Downloads](https://img.shields.io/packagist/dt/virgil/crypto.svg?style=flat-square)](https://packagist.org/packages/virgil/crypto)

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

Generate a key pair with the default algorithm (EC_X25519):
```php
use Virgil\Crypto\VirgilCrypto;

try {
    $crypto = new VirgilCrypto();
    
    $keyPair = $crypto->generateKeyPair();
    
} catch (Exception $e) {
    throw new Exception($e->getMessage(), $e->getCode());
}
```

#### Generate and verify a signature

Generate signature and sign data with a private key:
```php
use Virgil\Crypto\VirgilCrypto;

try {
    $crypto = new VirgilCrypto();
    $senderKeyPair = $crypto->generateKeyPair();

    // prepare a message
    $messageToSign = "Hello, Bob!";

    // generate a signature
    $signature = $crypto->generateSignature($messageToSign, $senderKeyPair->getPrivateKey());

} catch (Exception $e) {
    throw new Exception($e->getMessage(), $e->getCode());
}
```

Verify a signature with a public key:
```php
use Virgil\Crypto\VirgilCrypto;

try {
    $crypto = new VirgilCrypto();
    
    $senderKeyPair = $crypto->generateKeyPair();    
    
    // prepare a message
    $messageToSign = "Hello, Bob!";

    // generate a signature
    $signature = $crypto->generateSignature($messageToSign, $senderKeyPair->getPrivateKey());
    
    // verify a signature
    $verified = $crypto->verifySignature($signature, $messageToSign, $senderKeyPair->getPublicKey());

} catch (Exception $e) {
    throw new Exception($e->getMessage(), $e->getCode());
}
```
#### Encrypt and decrypt data

Encrypt Data on a Public Key:

```php
use Virgil\Crypto\Core\Data;
use Virgil\Crypto\Core\PublicKeyList;
use Virgil\Crypto\VirgilCrypto;

try {
    $crypto = new VirgilCrypto();
    $receiverKeyPair = $crypto->generateKeyPair();

    // prepare a message
    $messageToEncrypt = "Hello, Bob!";

    // encrypt the message
    $encryptedData = $crypto->encrypt(new Data($messageToEncrypt), new PublicKeyList($receiverKeyPair->getPublicKey()));

} catch (Exception $e) {
    throw new Exception($e->getMessage(), $e->getCode());
}
```
Decrypt the encrypted data with a Private Key:
```php
use Virgil\Crypto\Core\Data;
use Virgil\Crypto\Core\PublicKeyList;
use Virgil\Crypto\VirgilCrypto;

try {
    $crypto = new VirgilCrypto();
    $receiverKeyPair = $crypto->generateKeyPair();

    // prepare a message
    $messageToEncrypt = "Hello, Bob!";

    // encrypt the message
    $encryptedData = $crypto->encrypt(new Data($messageToEncrypt), new PublicKeyList($receiverKeyPair->getPublicKey()));

    // prepare data to be decrypted and decrypt the encrypted data using a private key
    $decryptedData = $crypto->decrypt(new Data($encryptedData), $receiverKeyPair->getPrivateKey());

} catch (Exception $e) {
    throw new Exception($e->getMessage(), $e->getCode());
}
```
Need more examples? Visit our [developer documentation](https://developer.virgilsecurity.com/docs/how-to#cryptography).

## Installation

### Requirements

**PHP 7.2 / 7.3 / 7.4**

#### Installation via composer

```bash
composer require virgil/crypto
```

## Additional information

- [Manual adding the crypto extension into your server](https://github.com/VirgilSecurity/virgil-cryptowrapper-php#additional-information)

## Docs
- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto)
- [More usage examples](https://developer.virgilsecurity.com/docs/how-to#cryptography)

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
