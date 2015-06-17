# Virgil Security PHP library

- [Introduction](#introduction)
- [Build prerequisite](#build-prerequisite)
- [Build](#build)
- [Examples](#examples)
    - [General statements](#general-statements)
    - [Example 1: Generate keys](#example-1)
    - [Example 2: Register user on the PKI service](#example-2)
    - [Example 3: Get user's public key from the PKI service](#example-3)
    - [Example 4: Encrypt data](#example-4)
    - [Example 5: Decrypt data](#example-5)
    - [Example 6: Sign data](#example-6)
    - [Example 7: Verify data](#example-7)
- [License](#license)
- [Contacts](#contacts)

## Introduction

This branch focuses on the PHP library implementation and covers next topics:

  * build prerequisite;
  * build;
  * usage exmaples.

Common library description can be found [here](https://github.com/VirgilSecurity/virgil).

## Build prerequisite

1. [CMake](http://www.cmake.org/).
1. [Git](http://git-scm.com/).
1. [Python](http://python.org/).
1. [Python YAML](http://pyyaml.org/).
1. C/C++ compiler:
    [gcc](https://gcc.gnu.org/),
    [clang](http://clang.llvm.org/),
    [MinGW](http://www.mingw.org/),
    [Microsoft Visual Studio](http://www.visualstudio.com/), or other.
1. [libcurl](http://curl.haxx.se/libcurl/).

## Build

1. Open terminal.
2. Clone project. ``` git clone https://github.com/VirgilSecurity/virgil.git ```
4. Navigate to the project's folder.
5. ``` cd virgil_lib ```
6. Create folder for the build purposes. ``` mkdir build ```
7. Navigate to the "build" folder. ``` cd build ```
8. Configure cmake. Note, replace "../install" path, if you want install library in different location. 
 ``` cmake -DPLATFORM_NAME=PHP -DCMAKE_INSTALL_PREFIX=../install .. ```
10. Build library. ``` make ```
11. Install library. ``` make install ```
12. Add to your php.ini ```extension=path/to/your/virgil_php.so```, replace ``"path/to/your/virgil_php.so"`` to your path where virgil_php.so extension is located

## Examples

This section describes common case library usage scenarios, like

  * encrypt data for user identified by email, phone, etc;
  * sign data with own private key;
  * verify data received via email, file sharing service, etc;
  * decrypt data if verification successful.

### General statements

1. Examples MUST be run from their directory.
1. Before run examples you have to install dependencies (run command ```composer install```)
1. All results are stored in the "data" directory.
2. 1. To produce file `virgil_public.key` run:
    - `get_public_key.php` script - if user is registered;
    - `register_user.php` script - if user is not registered.
1. To produce `test.txt.sign` run `sign.php` script.
1. To produce `text.txt.enc` run `encrypt.php` script.
1. To produce `decrypted_text.txt` run `decrypt.php` script.

### <a name="example-1"></a> Example 1: Generate keys

*Input*:

*Output*: Public Key and Private Key

```php
<?php

require_once './vendor/autoload.php';

echo 'Generate keys with with password: "password"';

$key = new VirgilKeyPair('password');
file_put_contents('data' . DIRECTORY_SEPARATOR . 'new_public.key', $key->publicKey());
file_put_contents('data' . DIRECTORY_SEPARATOR . 'new_private.key', $key->privateKey());
```

### <a name="example-2"></a> Example 2: Register user on the PKI service

*Input*: User ID

*Output*: Virgil Public Key

```php
<?php

use Virgil\PKI\Models\VirgilUserData;
use Virgil\PKI\Models\VirgilUserDataCollection;

require_once './vendor/autoload.php';

const VIRGIL_PKI_URL_BASE = 'https://pki-stg.virgilsecurity.com/v1/';
const USER_ID_TYPE = 'email';
const USER_ID = 'test.php.virgilsecurity-032@mailinator.com';
const USER_DATA_CLASS = 'user_id';
const VIRGIL_APP_TOKEN = '1234567890';


echo 'Read public key file' . PHP_EOL;

$publicKey = file_get_contents('data' . DIRECTORY_SEPARATOR . 'new_public.key');

try {
    $pkiClient = new Virgil\PKI\PkiClient(VIRGIL_APP_TOKEN);

    $userData = new VirgilUserData();
    $userData->class = USER_DATA_CLASS;
    $userData->type  = USER_ID_TYPE;
    $userData->user_data_id = USER_ID;

    $userDataCollection = new VirgilUserDataCollection(array($userData));

    $virgilAccount = $pkiClient->getAccountsClient()->register($userDataCollection, $publicKey);

    echo 'Store virgil public key to the output file...';

    file_put_contents('data' . DIRECTORY_SEPARATOR . 'virgil_public.key', $virgilAccount->public_keys->get(0)->public_key);
} catch (Exception $e) {
    echo $e->getMessage();
}
```

### <a name="example-3"></a> Example 3: Get user's public key from the PKI service

*Input*: User ID

*Output*: Virgil Public Key

```php
<?php

require_once './vendor/autoload.php';

const VIRGIL_PKI_URL_BASE = 'https://pki.virgilsecurity.com/v1/';
const USER_ID_TYPE = 'email';
const USER_ID = 'test.php.virgilsecurity-02@mailinator.com';
const VIRGIL_APP_TOKEN = '1234567890';


try {
    $pkiClient = new Virgil\PKI\PkiClient(VIRGIL_APP_TOKEN);

    echo 'Search by user data type and user data ID' . PHP_EOL;

    $virgilCertificateCollection = $pkiClient->getPublicKeysClient()->searchKey(USER_ID, USER_ID_TYPE);
    $virgilCertificate = $virgilCertificateCollection->get(0);

    echo 'Get public key by id' . PHP_EOL;

    $virgilCertificate = $pkiClient->getPublicKeysClient()->getKey($virgilCertificate->public_key_id);

    file_put_contents('data' . DIRECTORY_SEPARATOR . 'virgil_public.key', $virgilCertificate->toJson());

} catch (Exception $e) {
    echo $e->getMessage();
}
```

### <a name="example-4"></a> Example 4: Encrypt data

*Input*: User ID, Data

*Output*: Encrypted data

```php
<?php

require_once './vendor/autoload.php';

const VIRGIL_PKI_URL_BASE = 'https://pki-stg.virgilsecurity.com/v1/';
const USER_ID_TYPE = 'email';
const USER_ID = 'test.php.virgilsecurity-02@mailinator.com';
const VIRGIL_APP_TOKEN = '1234567890';

try {
    $pkiClient = new Virgil\PKI\PkiClient(VIRGIL_APP_TOKEN);

    echo 'Read source file' . PHP_EOL;

    $source = file_get_contents('data' . DIRECTORY_SEPARATOR . 'test.txt');
    if($source === false) {
        throw new Exception('Unable to get source data');
    }

    echo 'Initialize cipher' . PHP_EOL;

    $cipher = new VirgilCipher();

    echo 'Get recipient ' . USER_ID . ' information from the Virgil PKI service...' . PHP_EOL;

    $virgilCertificateCollection = $pkiClient->getPublicKeysClient()->searchKey(USER_ID, USER_ID_TYPE);
    $virgilCertificate = $virgilCertificateCollection->get(0);

    echo 'Add recipient' . PHP_EOL;

    $cipher->addKeyRecipient($virgilCertificate->public_key_id, $virgilCertificate->public_key);

    echo 'Encrypt and store results' . PHP_EOL;

    $encryptedData = $cipher->encrypt($source, true);

    if(file_put_contents('data' . DIRECTORY_SEPARATOR . 'test.txt.enc', $encryptedData)) {
        echo 'Data successfully encrypted and stored into test.txt.enc' . PHP_EOL;
    }

} catch (Exception $e) {
    echo $e->getMessage();
}
```

### <a name="example-5"></a> Example 5: Decrypt data

*Input*: Encrypted data, Virgil Public Key, Private Key, Private Key password

*Output*: Decrypted data

```php
<?php

require_once './vendor/autoload.php';

try {
    echo 'Read encrypted data' . PHP_EOL;

    $source = file_get_contents('data' . DIRECTORY_SEPARATOR . 'test.txt.enc');
    if($source === false) {
        throw new Exception('Unable to get source data');
    }

    echo 'Initialize cipher' . PHP_EOL;

    $cipher     = new VirgilCipher();
    $privateKey = file_get_contents('data' . DIRECTORY_SEPARATOR . 'new_private.key');

    if($privateKey === false) {
        throw new Exception('Unable to read private key file');
    }

    $virgilCertificate = new VirgilCertificate();
    $virgilCertificate->fromJson(file_get_contents('data' . DIRECTORY_SEPARATOR . 'virgil_public.key'));

    echo 'Decrypt data' . PHP_EOL;

    $decryptedData = $cipher->decryptWithKey($source, $virgilCertificate->id()->certificateId(), $privateKey, 'password');

    echo 'Save decrypted data to file' . PHP_EOL;

    file_put_contents('data' . DIRECTORY_SEPARATOR . 'decrypted.test.txt', $decryptedData);

} catch (Exception $e) {
    echo $e->getMessage();
}
```

### <a name="example-6"></a> Example 6: Sign data

*Input*: Data, Virgil Public Key, Private Key

*Output*: Virgil Sign

```php
<?php

require_once './vendor/autoload.php';

try {
    echo 'Read source file' . PHP_EOL;

    $source = file_get_contents('data' . DIRECTORY_SEPARATOR . 'test.txt');
    if($source === false) {
        throw new Exception('Unable to get source data');
    }

    echo 'Read public key from json' . PHP_EOL;

    $publicKeyJson = file_get_contents('data' . DIRECTORY_SEPARATOR . 'virgil_public.key');
    if($publicKeyJson === false) {
        throw new Exception('Failed to open public key file');
    }

    $virgilCertificate = new VirgilCertificate();
    $virgilCertificate->fromJson($publicKeyJson);

    echo 'Read private key' . PHP_EOL;

    $privateKey = file_get_contents('data' . DIRECTORY_SEPARATOR . 'new_private.key');
    if($privateKey === false) {
        throw new Exception('Failed to open private key file');
    }

    echo 'Initialize signer' . PHP_EOL;

    $signer = new VirgilSigner();

    echo 'Sign data' . PHP_EOL;

    $sign = $signer->sign($source, $virgilCertificate->id()->certificateId(), $privateKey, 'password');

    echo 'Save signed data to file' . PHP_EOL;

    file_put_contents('data' . DIRECTORY_SEPARATOR . 'test.txt.sign', $sign->toJson());

} catch (Exception $e) {
    echo $e->getMessage();
}
```

### <a name="example-7"></a> Example 7: Verify data

*Input*: Data, Sign, Virgil Public Key

*Output*: Verification result

```php
<?php

require_once './vendor/autoload.php';

try {
    echo 'Read source file' . PHP_EOL;

    $source = file_get_contents('data' . DIRECTORY_SEPARATOR . 'test.txt');
    if($source === false) {
        throw new Exception('Unable to get source data');
    }

    echo 'Read sign from json' . PHP_EOL;

    $signJson = file_get_contents('data' . DIRECTORY_SEPARATOR . 'test.txt.sign');
    if($signJson === false) {
        throw new Exception('Filed to open sign file');
    }

    $sign = new VirgilSign();
    $sign->fromJson($signJson);

    echo 'Read public key from json' . PHP_EOL;

    $publicKeyJson = file_get_contents('data' . DIRECTORY_SEPARATOR . 'virgil_public.key');
    if($publicKeyJson === false) {
        throw new Exception('Failed to open public key file');
    }

    $virgilCertificate = new VirgilCertificate();
    $virgilCertificate->fromJson($publicKeyJson);

    echo 'Initialize signer' . PHP_EOL;

    $signer = new VirgilSigner();

    echo 'Verify sign' . PHP_EOL;

    if($signer->verify($source, $sign, $virgilCertificate->publicKey()) == true) {
        echo 'Data is verified';
    } else {
        echo 'Data is not verified';
    }

} catch (Exception $e) {
    echo $e->getMessage();
}
```

## License
BSD 3-Clause. See [LICENSE](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE) for details.

## Contacts
Email: <support@virgilsecurity.com>
