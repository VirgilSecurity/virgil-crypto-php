<?php
/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

namespace Virgil\CryptoImpl\Cryptography\Core\Crypto;


class VirgilKeyPair
{
    const Type_RSA_256 = 0;
    const Type_RSA_512 = VirgilKeyPair_Type_RSA_512;
    const Type_RSA_1024 = VirgilKeyPair_Type_RSA_1024;
    const Type_RSA_2048 = VirgilKeyPair_Type_RSA_2048;
    const Type_RSA_3072 = VirgilKeyPair_Type_RSA_3072;
    const Type_RSA_4096 = VirgilKeyPair_Type_RSA_4096;
    const Type_RSA_8192 = VirgilKeyPair_Type_RSA_8192;
    const Type_EC_SECP192R1 = VirgilKeyPair_Type_EC_SECP192R1;
    const Type_EC_SECP224R1 = VirgilKeyPair_Type_EC_SECP224R1;
    const Type_EC_SECP256R1 = VirgilKeyPair_Type_EC_SECP256R1;
    const Type_EC_SECP384R1 = VirgilKeyPair_Type_EC_SECP384R1;
    const Type_EC_SECP521R1 = VirgilKeyPair_Type_EC_SECP521R1;
    const Type_EC_BP256R1 = VirgilKeyPair_Type_EC_BP256R1;
    const Type_EC_BP384R1 = VirgilKeyPair_Type_EC_BP384R1;
    const Type_EC_BP512R1 = VirgilKeyPair_Type_EC_BP512R1;
    const Type_EC_SECP192K1 = VirgilKeyPair_Type_EC_SECP192K1;
    const Type_EC_SECP224K1 = VirgilKeyPair_Type_EC_SECP224K1;
    const Type_EC_SECP256K1 = VirgilKeyPair_Type_EC_SECP256K1;
    const Type_EC_CURVE25519 = VirgilKeyPair_Type_EC_CURVE25519;
    const Type_FAST_EC_X25519 = VirgilKeyPair_Type_FAST_EC_X25519;
    const Type_FAST_EC_ED25519 = VirgilKeyPair_Type_FAST_EC_ED25519;
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($publicKey_or_other, $privateKey = null)
    {
        if (is_resource($publicKey_or_other) &&
            get_resource_type($publicKey_or_other) === '_p_virgil__crypto__VirgilKeyPair'
        ) {
            $this->_cPtr = $publicKey_or_other;

            return;
        }
        switch (func_num_args()) {
            case 1:
                $this->_cPtr = new_VirgilKeyPair($publicKey_or_other);
                break;
            default:
                $this->_cPtr = new_VirgilKeyPair($publicKey_or_other, $privateKey);
        }
    }


    static function generate($type, $pwd = null)
    {
        switch (func_num_args()) {
            case 1:
                $r = VirgilKeyPair_generate($type);
                break;
            default:
                $r = VirgilKeyPair_generate($type, $pwd);
        }
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilKeyPair($r);
        }

        return $r;
    }


    static function generateRecommended($pwd = null)
    {
        switch (func_num_args()) {
            case 0:
                $r = VirgilKeyPair_generateRecommended();
                break;
            default:
                $r = VirgilKeyPair_generateRecommended($pwd);
        }
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilKeyPair($r);
        }

        return $r;
    }


    static function generateFrom($donorKeyPair, $donorPrivateKeyPassword = null, $newKeyPairPassword = null)
    {
        switch (func_num_args()) {
            case 1:
                $r = VirgilKeyPair_generateFrom($donorKeyPair);
                break;
            case 2:
                $r = VirgilKeyPair_generateFrom($donorKeyPair, $donorPrivateKeyPassword);
                break;
            default:
                $r = VirgilKeyPair_generateFrom($donorKeyPair, $donorPrivateKeyPassword, $newKeyPairPassword);
        }
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilKeyPair($r);
        }

        return $r;
    }


    static function isKeyPairMatch($publicKey, $privateKey, $privateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 2:
                $r = VirgilKeyPair_isKeyPairMatch($publicKey, $privateKey);
                break;
            default:
                $r = VirgilKeyPair_isKeyPairMatch($publicKey, $privateKey, $privateKeyPassword);
        }

        return $r;
    }


    static function checkPrivateKeyPassword($key, $pwd)
    {
        return VirgilKeyPair_checkPrivateKeyPassword($key, $pwd);
    }


    static function isPrivateKeyEncrypted($privateKey)
    {
        return VirgilKeyPair_isPrivateKeyEncrypted($privateKey);
    }


    static function resetPrivateKeyPassword($privateKey, $oldPassword, $newPassword)
    {
        return VirgilKeyPair_resetPrivateKeyPassword($privateKey, $oldPassword, $newPassword);
    }


    static function encryptPrivateKey($privateKey, $privateKeyPassword)
    {
        return VirgilKeyPair_encryptPrivateKey($privateKey, $privateKeyPassword);
    }


    static function decryptPrivateKey($privateKey, $privateKeyPassword)
    {
        return VirgilKeyPair_decryptPrivateKey($privateKey, $privateKeyPassword);
    }


    static function extractPublicKey($privateKey, $privateKeyPassword)
    {
        return VirgilKeyPair_extractPublicKey($privateKey, $privateKeyPassword);
    }


    static function publicKeyToPEM($publicKey)
    {
        return VirgilKeyPair_publicKeyToPEM($publicKey);
    }


    static function publicKeyToDER($publicKey)
    {
        return VirgilKeyPair_publicKeyToDER($publicKey);
    }


    static function privateKeyToPEM($privateKey, $privateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 1:
                $r = VirgilKeyPair_privateKeyToPEM($privateKey);
                break;
            default:
                $r = VirgilKeyPair_privateKeyToPEM($privateKey, $privateKeyPassword);
        }

        return $r;
    }


    static function privateKeyToDER($privateKey, $privateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 1:
                $r = VirgilKeyPair_privateKeyToDER($privateKey);
                break;
            default:
                $r = VirgilKeyPair_privateKeyToDER($privateKey, $privateKeyPassword);
        }

        return $r;
    }


    function __set($var, $value)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_alter_newobject($this->_cPtr, $value);
        }
        $this->_pData[$var] = $value;
    }


    function __get($var)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        }

        return $this->_pData[$var];
    }


    function __isset($var)
    {
        if ($var === 'thisown') {
            return true;
        }

        return array_key_exists($var, $this->_pData);
    }


    function publicKey()
    {
        return VirgilKeyPair_publicKey($this->_cPtr);
    }


    function privateKey()
    {
        return VirgilKeyPair_privateKey($this->_cPtr);
    }
}
