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
8. Configure cmake. '''Note''', replace ''"../install"'' path, if you want install library in different location. 
 ``` cmake -DPLATFORM_NAME=PHP -DCMAKE_INSTALL_PREFIX=../install .. ```
10. Build library. ``` make ```
11. Install library. ``` make install ```

## Examples

This section describes common case library usage scenarios, like

  * encrypt data for user identified by email, phone, etc;
  * sign data with own private key;
  * verify data received via email, file sharing service, etc;
  * decrypt data if verification successful.

### General statements

1. Examples MUST be run from their directory.
1. All results are stored in the "data" directory.

### <a name="example-1"></a> Example 1: Generate keys

*Input*:

*Output*: Public Key and Private Key

```php
<?php

require_once 'lib/virgil_php.php';

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

require_once 'lib/virgil_php.php';

const VIRGIL_PKI_URL_BASE = 'https://pki.virgilsecurity.com/';
const USER_ID_TYPE = 'email';
const USER_ID = 'test.php.virgilsecurity-02@mailinator.com';

function getUrl($endpoint) {
    return VIRGIL_PKI_URL_BASE . $endpoint;
}

function httpPost($url, $data = array()) {
    $result = null;

    try {
        $ch = curl_init($url);

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type:application/json',
            'Accept:application/json'
        ));

        $result = curl_exec($ch);

        if(curl_errno($ch) > 0) {
            throw new Exception('HTTP Request error: ' . curl_error($ch));
        }

        curl_close($ch);
    } catch (Exception $e) {
        echo $e->getMessage();
    }

    return $result;
}

function pkiCreateUser($publicKey, $userIds) {
    $payload = array(
        'public_key' => base64_encode($publicKey),
        'user_data'  => array_map(function($value, $key) {
            return array(
                'class' => 'user_id',
                'type'  => $key,
                'value' => $value
            );
        }, $userIds, array_keys($userIds))
    );

    $response = json_decode(httpPost(getUrl('objects/public-key'), $payload));

    if(empty($response) || !empty($response->error)) {
        throw new Exception('Unable to register user');
    }

    $virgilCertificate = new VirgilCertificate($publicKey);
    $virgilCertificate->id()->setAccountId($response->id->account_id);
    $virgilCertificate->id()->setCertificateId($response->id->public_key_id);

    return $virgilCertificate;
}

echo 'Read public key file' . PHP_EOL;

$publicKey = file_get_contents('data' . DIRECTORY_SEPARATOR . 'new_public.key');

try {
    $virgilCertificate = pkiCreateUser($publicKey, array(
        USER_ID_TYPE => USER_ID
    ));

    echo 'Store virgil public key to the output file...';

    file_put_contents('data' . DIRECTORY_SEPARATOR . 'virgil_public.key', $virgilCertificate->publicKey());
} catch (Exception $e) {
    echo $e->getMessage();
}
```

### <a name="example-3"></a> Example 3: Get user's public key from the PKI service

*Input*: User ID

*Output*: Virgil Public Key

```php
<?php

require_once 'lib/virgil_php.php';

const VIRGIL_PKI_URL_BASE = 'https://pki.virgilsecurity.com/';
const USER_ID_TYPE = 'email';
const USER_ID = 'test.php.virgilsecurity-02@mailinator.com';

function getUrl($endpoint) {
    return VIRGIL_PKI_URL_BASE . $endpoint;
}

function httpPost($url, $data = array()) {
    $result = null;

    try {
        $ch = curl_init($url);

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type:application/json',
            'Accept:application/json'
        ));

        $result = curl_exec($ch);

        if(curl_errno($ch) > 0) {
            throw new Exception('HTTP Request error: ' . curl_error($ch));
        }

        curl_close($ch);
    } catch (Exception $e) {
        echo $e->getMessage();
    }

    return $result;
}

function httpGet($url, $data = array()) {
    $result = null;

    try {
        $ch = curl_init($url . '?' . http_build_query($data));

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type:application/json',
            'Accept:application/json'
        ));

        $result = curl_exec($ch);

        if(curl_errno($ch) > 0) {
            throw new Exception('HTTP Request error: ' . curl_error($ch));
        }

        curl_close($ch);
    } catch (Exception $e) {
        echo $e->getMessage();
    }

    return $result;
}

function searchPublicKey($userDataType, $userDataId) {
    $payload = array(
        $userDataType => $userDataId
    );

    $response = json_decode(httpPost(getUrl('objects/account/actions/search'), $payload));

    if(empty($response) || !empty($response->error)) {
        throw new Exception('Unable to register user');
    }

    $pkiPublicKey = reset($response);

    $virgilCertificate = new VirgilCertificate(reset($pkiPublicKey->public_keys)->public_key);
    $virgilCertificate->id()->setAccountId($pkiPublicKey->id->account_id);
    $virgilCertificate->id()->setCertificateId(reset($pkiPublicKey->public_keys)->id->public_key_id);

    return $virgilCertificate;
}

function getPublicKeyById($publicKeyId) {
    $response = json_decode(httpGet(getUrl('/objects/public-key/' . $publicKeyId)));

    if(empty($response) || !empty($response->error)) {
        throw new Exception('Unable to register user');
    }

    $virgilCertificate = new VirgilCertificate($response->public_key);
    $virgilCertificate->id()->setAccountId($response->id->account_id);
    $virgilCertificate->id()->setCertificateId($response->id->public_key_id);

    return $virgilCertificate;
}


try {
    echo 'Search by user data type and user data ID' . PHP_EOL;

    $virgilCertificate = searchPublicKey(USER_ID_TYPE, USER_ID);

    echo 'Get public key by id' . PHP_EOL;

    $virgilCertificate = getPublicKeyById($virgilCertificate->id()->certificateId());

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

require_once 'lib/virgil_php.php';

const VIRGIL_PKI_URL_BASE = 'https://pki.virgilsecurity.com/';
const USER_ID_TYPE = 'email';
const USER_ID = 'test.php.virgilsecurity-02@mailinator.com';

function getUrl($endpoint) {
    return VIRGIL_PKI_URL_BASE . $endpoint;
}

function httpPost($url, $data = array()) {
    $result = null;

    try {
        $ch = curl_init($url);

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Content-Type:application/json',
            'Accept:application/json'
        ));

        $result = curl_exec($ch);

        if(curl_errno($ch) > 0) {
            throw new Exception('HTTP Request error: ' . curl_error($ch));
        }

        curl_close($ch);
    } catch (Exception $e) {
        echo $e->getMessage();
    }

    return $result;
}

function searchPublicKey($userDataType, $userDataId) {
    $payload = array(
        $userDataType => $userDataId
    );

    $response = json_decode(httpPost(getUrl('objects/account/actions/search'), $payload));

    if(empty($response) || !empty($response->error)) {
        throw new Exception('Unable to register user');
    }

    $pkiPublicKey = reset($response);

    $virgilCertificate = new VirgilCertificate(base64_decode(reset($pkiPublicKey->public_keys)->public_key));
    $virgilCertificate->id()->setAccountId($pkiPublicKey->id->account_id);
    $virgilCertificate->id()->setCertificateId(reset($pkiPublicKey->public_keys)->id->public_key_id);

    return $virgilCertificate;
}



try {
    echo 'Read source file' . PHP_EOL;

    $source = file_get_contents('data' . DIRECTORY_SEPARATOR . 'test.txt');
    if($source === false) {
        throw new Exception('Unable to get source data');
    }

    echo 'Initialize cipher' . PHP_EOL;

    $cipher = new VirgilCipher();

    echo 'Get recipient ' . USER_ID . ' information from the Virgil PKI service...' . PHP_EOL;

    $virgilCertificate = searchPublicKey(USER_ID_TYPE, USER_ID);

    echo 'Add recipient' . PHP_EOL;

    $cipher->addKeyRecipient($virgilCertificate->id()->certificateId(), $virgilCertificate->publicKey());

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

require_once 'lib/virgil_php.php';

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

require_once 'lib/virgil_php.php';

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

require_once 'lib/virgil_php.php';

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
