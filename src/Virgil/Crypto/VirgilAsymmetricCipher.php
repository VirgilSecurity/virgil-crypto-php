<?php

namespace Virgil\Crypto;


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
