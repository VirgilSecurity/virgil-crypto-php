## Native Virgil Crypto Library Bindings

- [Requirements](#requirements)
- [Installation](#installation)
- [Keys generation](#keys-generation)
    - [Generate keypair](#generate-keypair)
    - [Generate keypair with encrypted private key](#generate-keypair-with-encrypted-private-key)
- [Encryption](#encryption)
    - [Encrypt and decrypt](#encrypt-and-decrypt)
    - [Decrypt with encrypted private key](#decrypt-with-encrypted-private-key)
    - [Encrypt data for multiple number of recipients](#encrypt-data-for-multiple-number-of-recipients)
- [Sign and verify data](#sign-and-verify-data)
- [License](#license)
- [Contacts](#contacts)

## Requirements

* PHP 5.6+
* virgil_crypto_php.so extension version 2.2.*

## Installation

```bash
composer require virgil/crypto
```

## Keys generation

### Generate keypair

```php
require_once './vendor/autoload.php';

use Virgil\Crypto\VirgilKeyPair;

$key = VirgilKeyPair::generate(VirgilKeyPair::Type_FAST_EC_ED25519);

file_put_contents('new_public.key', $key->publicKey());
file_put_contents('new_private.key', $key->privateKey());
```

### Generate keypair with encrypted private key

```php
require_once './vendor/autoload.php';

use Virgil\Crypto\VirgilKeyPair;

$password = 'secret password';
$key = VirgilKeyPair::generate(VirgilKeyPair::Type_FAST_EC_ED25519, $password);

if (VirgilKeyPair::isPrivateKeyEncrypted($key->privateKey()) 
    && VirgilKeyPair::checkPrivateKeyPassword($key->privateKey(), $password)
) {
    file_put_contents('new_public.key', $key->publicKey());
    file_put_contents('new_private.key', $key->privateKey());
}
```
## Encryption

### Encrypt and decrypt

The Virgil library allows to encrypt data using several types of recipients such as password recipient and key transport recipient. The following example shows encryption with only one recipient.

```php
require_once './vendor/autoload.php';

use Virgil\Crypto\VirgilKeyPair,
    Virgil\Crypto\VirgilCipher;

$data = 'Encrypt me please';
$publicKeyId = 'AB82FD88-3DAE-420C-BED0-8D47B7DA497F';

$keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_FAST_EC_ED25519);
$cipher  = new VirgilCipher;

$cipher->addKeyRecipient($publicKeyId, $keyPair->publicKey());

$encryptedData = $cipher->encrypt($data);
$decryptedData = $cipher->decryptWithKey($encryptedData, $publicKeyId, $keyPair->privateKey());

try {
    $decryptedData = $cipher->decryptWithKey($encryptedData, "wrong public key id", $keyPair->privateKey());
} catch (Exception $e) {
    //handle
}
```

### Decrypt with encrypted private key

```php
require_once './vendor/autoload.php';

use Virgil\Crypto\VirgilKeyPair,
    Virgil\Crypto\VirgilCipher;

$data = 'Encrypt me please';
$publicKeyId = 'AB82FD88-3DAE-420C-BED0-8D47B7DA497F';
$privateKeyPassword = 'password';

$keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_FAST_EC_ED25519, $privateKeyPassword);
$cipher  = new VirgilCipher;

$cipher->addKeyRecipient($publicKeyId, $keyPair->publicKey());

$encryptedData = $cipher->encrypt($data);
$decryptedData =  $cipher->decryptWithKey($encryptedData, $publicKeyId, $keyPair->privateKey(), $privateKeyPassword);
```

### Encrypt data for multiple number of recipients

```php
require_once './vendor/autoload.php';

use Virgil\Crypto\VirgilKeyPair,
    Virgil\Crypto\VirgilCipher;

$keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_FAST_EC_ED25519);
$cipher  = new VirgilCipher;

$data = 'Encrypt me please';
$publicKeyId = 'AB82FD88-3DAE-420C-BED0-8D47B7DA497F';
$password = 'password';

$cipher->addPasswordRecipient($password);
$cipher->addKeyRecipient($publicKeyId, $keyPair->publicKey());

$encryptedData = $cipher->encrypt($data);

$decryptedData1 = $cipher->decryptWithPassword($encryptedData, $password);
$decryptedData2 = $cipher->decryptWithKey($encryptedData, $publicKeyId, $keyPair->privateKey());
```

## Sign and verify data

In example below used encrypted data for sign/verify, but it can be done for any data chosen by developer.

```php
require_once "vendor/autoload.php";

use Virgil\Crypto\VirgilSigner,
    Virgil\Crypto\VirgilKeyPair;

$signer = new VirgilSigner();
$keyPair = VirgilKeyPair::generate(VirgilKeyPair::Type_FAST_EC_ED25519);

$data = 'Sign me please';

$sign = $signer->sign($data, $keyPair->privateKey());
//true
$isVerified = $signer->verify($data, $sign, $keyPair->publicKey());

try {
    $signer->verify($data, "wrong sign", $keyPair->publicKey());
} catch (Exception $e) {
    //handle wrong sign
}
```

## License

BSD 3-Clause. See LICENSE for details.

## Contacts

Email: support@virgilsecurity.com
