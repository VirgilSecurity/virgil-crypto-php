# Virgil Crypto Library PHP

[![Build Status](https://api.travis-ci.com/VirgilSecurity/virgil-crypto-php.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-crypto-php/)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/virgil/crypto.svg?style=flat-square)](https://packagist.org/packages/virgil/crypto)
[![Total Downloads](https://img.shields.io/packagist/dt/virgil/crypto.svg?style=flat-square)](https://packagist.org/packages/virgil/crypto)

[Introduction](#introduction) | [Library purposes](#library-purposes) | [Installation](#installation) | [Usage examples](#usage-examples) | [Docs](#docs) | [License](#license) | [Support](#support)

## Introduction

Virgil Crypto Library PHP is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and an open-source high-level [cryptographic library](https://github.com/VirgilSecurity/virgil-crypto) that allows you to perform all necessary operations for securely storing and transferring data in your digital solutions. Crypto Library is written in C++ and is suitable for mobile and server platforms.

## Library purposes

- Asymmetric Key Generation
- Encryption/Decryption of data and streams
- Generation/Verification of digital signatures
- Double Ratchet algorithm support
- **Post-quantum algorithms support**: [Round5](https://round5.org/) (encryption) and [Falcon](https://falcon-sign.info/) (signature)
- Crypto for using [Virgil Core SDK](https://github.com/VirgilSecurity/virgil-sdk-php)

## Installation

**Requirements**:

- PHP 8.2, 8.3

#### Installation via composer

```bash
composer require virgil/crypto
```

## Usage examples

### Generate a key pair

Generate a key pair using the default algorithm (EC_X25519):

```php
$crypto = new VirgilCrypto();
$keyPair = $crypto->generateKeyPair();
```

### Generate and verify a signature

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

### Encrypt and decrypt data

Encrypt data with a public key:

```php
$crypto = new VirgilCrypto();
$receiverKeyPair = $crypto->generateKeyPair();

// prepare a message
$messageToEncrypt = "Hello, Bob!";

// encrypt the message
$encryptedData = $crypto->encrypt($messageToEncrypt, new VirgilPublicKeyCollection($receiverKeyPair->getPublicKey()));
```

Decrypt the encrypted data with a private key:

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

### Import and export keys

Export keys:

```
use Virgil\CryptoImpl\VirgilCrypto;

$crypto = new VirgilCrypto();
$keyPair = $crypto->generateKeys();

// export private key
$privateKeyData = $crypto->exportPrivateKey($keyPair->getPrivateKey(), "YOUR_PASSWORD");
$privateKeyStr = base64_encode($privateKeyData);

// export public key
$publicKeyData = $crypto->exportPublicKey($keyPair->getPrivateKey());
$publicKeyStr = base64_encode($publicKeyData);
```

Import keys:

```
use Virgil\CryptoImpl\VirgilCrypto;

$crypto = new VirgilCrypto();
$privateKeyStr = "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBBtfBoM7VfmWPlvyHuGWvMSAgIZ6zAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEECwaKJKWFNn3OMVoUXEcmqcEQMZ+WWkmPqzwzJXGFrgS/+bEbr2DvreVgEUiLKrggmXL9ZKugPKG0VhNY0omnCNXDzkXi5dCFp25RLqbbSYsCyw=";

$privateKeyData = base64_decode($privateKeyStr);

// import a Private key
$privateKey = $crypto->importPrivateKey($privateKeyData, "YOUR_PASSWORD");

//-----------------------------------------------------

$publicKeyStr = "MCowBQYDK2VwAyEA9IVUzsQENtRVzhzraTiEZZy7YLq5LDQOXGQG/q0t0kE=";

$publicKeyData = base64_decode($publicKeyStr);

// import a Public key
$publicKey = $crypto->importPublicKey($publicKeyData);
```

## Additional information

- [Manually adding the crypto extension to your server](https://github.com/VirgilSecurity/virgil-cryptowrapper-php#additional-information)

## Docs

- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto)
- [Developer Documentation](https://developer.virgilsecurity.com/)

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support

Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
