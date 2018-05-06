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


class VirgilAsymmetricCipher extends VirgilAsn1Compatible
{
    public $_cPtr = null;


    function __construct($res = null)
    {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__foundation__VirgilAsymmetricCipher') {
            $this->_cPtr = $res;

            return;
        }
        $this->_cPtr = new_VirgilAsymmetricCipher();
    }


    static function isKeyPairMatch($publicKey, $privateKey, $privateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 2:
                $r = VirgilAsymmetricCipher_isKeyPairMatch($publicKey, $privateKey);
                break;
            default:
                $r = VirgilAsymmetricCipher_isKeyPairMatch($publicKey, $privateKey, $privateKeyPassword);
        }

        return $r;
    }


    static function isPublicKeyValid($key)
    {
        return VirgilAsymmetricCipher_isPublicKeyValid($key);
    }


    static function checkPublicKey($key)
    {
        VirgilAsymmetricCipher_checkPublicKey($key);
    }


    static function checkPrivateKeyPassword($key, $pwd)
    {
        return VirgilAsymmetricCipher_checkPrivateKeyPassword($key, $pwd);
    }


    static function isPrivateKeyEncrypted($privateKey)
    {
        return VirgilAsymmetricCipher_isPrivateKeyEncrypted($privateKey);
    }


    static function computeShared($publicContext, $privateContext)
    {
        return VirgilAsymmetricCipher_computeShared($publicContext, $privateContext);
    }


    function __set($var, $value)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_alter_newobject($this->_cPtr, $value);
        }
        VirgilAsn1Compatible::__set($var, $value);
    }


    function __get($var)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        }

        return VirgilAsn1Compatible::__get($var);
    }


    function __isset($var)
    {
        if ($var === 'thisown') {
            return true;
        }

        return VirgilAsn1Compatible::__isset($var);
    }


    function keySize()
    {
        return VirgilAsymmetricCipher_keySize($this->_cPtr);
    }


    function keyLength()
    {
        return VirgilAsymmetricCipher_keyLength($this->_cPtr);
    }


    function setPrivateKey($key, $pwd = null)
    {
        switch (func_num_args()) {
            case 1:
                VirgilAsymmetricCipher_setPrivateKey($this->_cPtr, $key);
                break;
            default:
                VirgilAsymmetricCipher_setPrivateKey($this->_cPtr, $key, $pwd);
        }
    }


    function setPublicKey($key)
    {
        VirgilAsymmetricCipher_setPublicKey($this->_cPtr, $key);
    }


    function genKeyPair($type)
    {
        VirgilAsymmetricCipher_genKeyPair($this->_cPtr, $type);
    }


    function genKeyPairFrom($other)
    {
        VirgilAsymmetricCipher_genKeyPairFrom($this->_cPtr, $other);
    }


    function exportPrivateKeyToDER($pwd = null)
    {
        switch (func_num_args()) {
            case 0:
                $r = VirgilAsymmetricCipher_exportPrivateKeyToDER($this->_cPtr);
                break;
            default:
                $r = VirgilAsymmetricCipher_exportPrivateKeyToDER($this->_cPtr, $pwd);
        }

        return $r;
    }


    function exportPublicKeyToDER()
    {
        return VirgilAsymmetricCipher_exportPublicKeyToDER($this->_cPtr);
    }


    function exportPrivateKeyToPEM($pwd = null)
    {
        switch (func_num_args()) {
            case 0:
                $r = VirgilAsymmetricCipher_exportPrivateKeyToPEM($this->_cPtr);
                break;
            default:
                $r = VirgilAsymmetricCipher_exportPrivateKeyToPEM($this->_cPtr, $pwd);
        }

        return $r;
    }


    function exportPublicKeyToPEM()
    {
        return VirgilAsymmetricCipher_exportPublicKeyToPEM($this->_cPtr);
    }


    function getKeyType()
    {
        return VirgilAsymmetricCipher_getKeyType($this->_cPtr);
    }


    function setKeyType($keyType)
    {
        VirgilAsymmetricCipher_setKeyType($this->_cPtr, $keyType);
    }


    function getPublicKeyBits()
    {
        return VirgilAsymmetricCipher_getPublicKeyBits($this->_cPtr);
    }


    function setPublicKeyBits($bits)
    {
        VirgilAsymmetricCipher_setPublicKeyBits($this->_cPtr, $bits);
    }


    function encrypt($in)
    {
        return VirgilAsymmetricCipher_encrypt($this->_cPtr, $in);
    }


    function decrypt($in)
    {
        return VirgilAsymmetricCipher_decrypt($this->_cPtr, $in);
    }


    function sign($digest, $hashType)
    {
        return VirgilAsymmetricCipher_sign($this->_cPtr, $digest, $hashType);
    }


    function verify($digest, $sign, $hashType)
    {
        return VirgilAsymmetricCipher_verify($this->_cPtr, $digest, $sign, $hashType);
    }
}
