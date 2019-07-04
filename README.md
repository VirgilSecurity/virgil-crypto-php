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

#### Installation via composer

Add **virgil_crypto_php** extension before install virgil/crypto! Read more [here](#add-the-crypto-extension-into-your-server).

```bash
composer require virgil/crypto
```

## Additional information

### Add the crypto extension into your server

- [Download](https://github.com/VirgilSecurity/virgil-crypto-php/releases) *virgil-test.zip*, unzip it and execute on your server [virgil-test.php](/_help/virgil-test.php) file.

- [Download](https://github.com/VirgilSecurity/virgil-crypto-php/releases) and unzip *%YOUR_OS%_extension.zip* archive according to your server operating system and PHP version.

- Make sure you have access to edit the php.ini file (for example, use *root* for the Linux/Darwin or run *cmd* under administrator for the Windows).
- Copy extension files to the extensions directory.
    - For Linux/Darwin:
    ```
     $ path="%PATH_TO_EXTENSIONS_DIR%" && cp virgil_crypto_php.so $path
    ```
    - For Windows:
    ```
     $ set path=%PATH_TO_EXTENSIONS_DIR% && copy virgil_crypto_php.dll %path%
    ```
- Add the extensions into the php.ini file 
    ```
    $ echo -e "extension=virgil_crypto_php” >> %PATH_TO_PHP.INI%
    ```
    
- Restart your server or php-fpm service

## Docs
- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto)
- [More usage examples](https://developer.virgilsecurity.com/docs/how-to#cryptography)

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
