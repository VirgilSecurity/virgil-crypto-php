# Virgil Security PHP Crypto Library

[![Build Status](https://api.travis-ci.com/VirgilSecurity/virgil-crypto-php.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-crypto-php/)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/virgil/crypto.svg?style=flat-square)](https://packagist.org/packages/virgil/crypto)
[![Total Downloads](https://img.shields.io/packagist/dt/virgil/crypto.svg?style=flat-square)](https://packagist.org/packages/virgil/crypto)

[Introduction](#introduction) | [Library purposes](#library-purposes) | [Usage examples](#usage-examples) | [Installation](#installation) | [Docs](#docs) | [License](#license) | [Support](#support)

## Introduction

VirgilCrypto is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and an open-source high-level [cryptographic library](https://github.com/VirgilSecurity/virgil-crypto) that allows you to perform all necessary operations for securely storing and transferring data in your digital solutions. Crypto Library is written in C++ and is suitable for mobile and server platforms.

## Library purposes

* Asymmetric Key Generation
* Encryption/Decryption of data and streams
* Generation/Verification of digital signatures
* PFS (Perfect Forward Secrecy)

## Usage examples

#### Generate a key pair

Generate a key pair with the default algorithm (EC_X25519):
```php
$crypto = new VirgilCrypto();
$keyPair = $crypto->generateKeyPair();
```

#### Generate and verify a signature

Generate signature and sign data with a private key:
```php
$crypto = new VirgilCrypto();
$senderKeyPair = $crypto->generateKeyPair();

// prepare a message
$messageToSign = "Hello, Bob!";

// generate a signature
$signature = $crypto->generateSignature($messageToSign, $senderKeyPair->getPrivateKey());
```

Verify a signature with a public key:
```php
$crypto = new VirgilCrypto();
    
$senderKeyPair = $crypto->generateKeyPair();    
    
// prepare a message
$messageToSign = "Hello, Bob!";

// generate a signature
$signature = $crypto->generateSignature($messageToSign, $senderKeyPair->getPrivateKey());
    
// verify a signature
$verified = $crypto->verifySignature($signature, $messageToSign, $senderKeyPair->getPublicKey());
```
#### Encrypt and decrypt data

Encrypt data with a public key:

```php
$crypto = new VirgilCrypto();
$receiverKeyPair = $crypto->generateKeyPair();

// prepare a message
$messageToEncrypt = "Hello, Bob!";

// encrypt the message
$encryptedData = $crypto->encrypt($messageToEncrypt, new VirgilPublicKeyCollection($receiverKeyPair->getPublicKey()));
```
Decrypt the encrypted data with a Private Key:
```php
$crypto = new VirgilCrypto();
$receiverKeyPair = $crypto->generateKeyPair();

// prepare a message
$messageToEncrypt = "Hello, Bob!";

// encrypt the message
$encryptedData = $crypto->encrypt($messageToEncrypt, new VirgilPublicKeyCollection($receiverKeyPair->getPublicKey()));

// prepare data to be decrypted and decrypt the encrypted data using a private key
$decryptedData = $crypto->decrypt($encryptedData, $receiverKeyPair->getPrivateKey());
```

## Installation

### Requirements

**PHP 7.2 / 7.3 / 7.4**

#### Installation via composer

```bash
composer require virgil/crypto
```

## Additional information

- [Manual adding the crypto extension to your server](https://github.com/VirgilSecurity/virgil-cryptowrapper-php#additional-information)

## Docs

- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto)
- [Developer Documentation](https://developer.virgilsecurity.com/)

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
