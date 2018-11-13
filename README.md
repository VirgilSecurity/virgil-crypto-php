# Virgil Security PHP Crypto Library

[![Build Status](https://api.travis-ci.com/VirgilSecurity/crypto-php.svg?branch=master)](https://travis-ci.com/VirgilSecurity/crypto-php/)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

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
#### Encrypt and decrypt files (size: 2Mb+)

Encrypt file:

```php
use Virgil\CryptoImpl\Cryptography\Cipher\VirgilSeqCipher;
        
$seqCipher = new VirgilSeqCipher();

// add recipient`s identity and public key
$seqCipher->addKeyRecipient($recipientId, $publicKey);

// path to input/output (encrypted) file
$inputFilePath = "/path/to/input.extension";
$outputFilePath = "/path/to/output.enc";

// add input/output handlers
$inputHandler = fopen($inputFilePath, "rb");
$outputHandler = fopen($outputFilePath, "w");

// add encryption header to file
fwrite($outputHandler, $seqCipher->startEncryption());

// encrypt each 1024 byts of the file content
while (!feof($inputHandler)) {
    $inputData = fread($inputHandler, 1024);
    $encryptedData = $seqCipher->process($inputData);
    if(!empty($encryptedData))
        fwrite($outputHandler, $encryptedData);
}

// add last encrypted block to the file
$lastBlock = $seqCipher->finish();
if(!empty($lastBlock))
    fwrite($outputHandler, $lastBlock);

// close input/output handlers
fclose($inputHandler);
fclose($outputHandler);
```
Decrypt file:
```php
use Virgil\CryptoImpl\Cryptography\Cipher\VirgilSeqCipher;
        
$seqCipher = new VirgilSeqCipher();

// path to input/output (encrypted) file
$inputFilePath = "/path/to/input.enc";
$outputFilePath = "/path/to/output.extension";

// add input/output handlers
$inputHandler = fopen($inputFilePath, "rb");
$outputHandler = fopen($outputFilePath, "w");

// add decryption header to file and recipient`s identity and private key
fwrite($outputHandler, $seqCipher->startDecryptionWithKey($recipientId, $privateKey));

// decrypt each 1024 byts of the file content
while (!feof($inputHandler)) {
    $inputData = fread($inputHandler, 1024);
    $encryptedData = $seqCipher->process($inputData);
    if(!empty($encryptedData))
        fwrite($outputHandler, $encryptedData);
}

// add last decrypted block to the file
$lastBlock = $seqCipher->finish();
if(!empty($lastBlock))
    fwrite($outputHandler, $lastBlock);

// close input/output handlers
fclose($inputHandler);
fclose($outputHandler);
```
Need more examples? Visit our [developer documentation](https://developer.virgilsecurity.com/docs/how-to#cryptography).

## Installation

### Requirements

* PHP 5.6 and newer
* virgil_crypto_php extension

#### Add virgil_crypto_php extension before install virgil/crypto:

* [Download virgil_crypto_2.6.1 archive from the CDN](https://cdn.virgilsecurity.com/virgil-crypto/php/) according to your server operating system and PHP version
* Place *virgil_crypto_php.so* file from the archive into the directory with extensions
* Add string *extension=virgil_crypto_php.so* to the php.ini file
* Restart your web-service (apache or nginx): *sudo service {apache2 / nginx} restart*

##### Tips:

* PHP version: *phpversion() / php --version*
* OS Version: *PHP_OS*
* php.ini and extensions directory: *phpinfo() / php -i / php-config --extension_dir*

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