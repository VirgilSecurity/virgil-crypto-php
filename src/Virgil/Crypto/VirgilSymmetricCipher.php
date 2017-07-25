<?php

namespace Virgil\Crypto;


class VirgilSymmetricCipher extends VirgilAsn1Compatible
{
    const Padding_PKCS7 = 0;
    const Padding_OneAndZeros = VirgilSymmetricCipher_Padding_OneAndZeros;
    const Padding_ZerosAndLen = VirgilSymmetricCipher_Padding_ZerosAndLen;
    const Padding_Zeros = VirgilSymmetricCipher_Padding_Zeros;
    const Padding_None = VirgilSymmetricCipher_Padding_None;
    const Algorithm_AES_128_CBC = 0;
    const Algorithm_AES_128_GCM = VirgilSymmetricCipher_Algorithm_AES_128_GCM;
    const Algorithm_AES_256_CBC = VirgilSymmetricCipher_Algorithm_AES_256_CBC;
    const Algorithm_AES_256_GCM = VirgilSymmetricCipher_Algorithm_AES_256_GCM;
    public $_cPtr = null;


    function __construct($algorithm_or_name = null)
    {
        if (is_resource($algorithm_or_name) &&
            get_resource_type($algorithm_or_name) === '_p_virgil__crypto__foundation__VirgilSymmetricCipher'
        ) {
            $this->_cPtr = $algorithm_or_name;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilSymmetricCipher();
                break;
            default:
                $this->_cPtr = new_VirgilSymmetricCipher($algorithm_or_name);
        }
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


    function name()
    {
        return VirgilSymmetricCipher_name($this->_cPtr);
    }


    function blockSize()
    {
        return VirgilSymmetricCipher_blockSize($this->_cPtr);
    }


    function ivSize()
    {
        return VirgilSymmetricCipher_ivSize($this->_cPtr);
    }


    function keySize()
    {
        return VirgilSymmetricCipher_keySize($this->_cPtr);
    }


    function keyLength()
    {
        return VirgilSymmetricCipher_keyLength($this->_cPtr);
    }


    function authTagLength()
    {
        return VirgilSymmetricCipher_authTagLength($this->_cPtr);
    }


    function isEncryptionMode()
    {
        return VirgilSymmetricCipher_isEncryptionMode($this->_cPtr);
    }


    function isDecryptionMode()
    {
        return VirgilSymmetricCipher_isDecryptionMode($this->_cPtr);
    }


    function isAuthMode()
    {
        return VirgilSymmetricCipher_isAuthMode($this->_cPtr);
    }


    function isSupportPadding()
    {
        return VirgilSymmetricCipher_isSupportPadding($this->_cPtr);
    }


    function iv()
    {
        return VirgilSymmetricCipher_iv($this->_cPtr);
    }


    function setEncryptionKey($key)
    {
        VirgilSymmetricCipher_setEncryptionKey($this->_cPtr, $key);
    }


    function setDecryptionKey($key)
    {
        VirgilSymmetricCipher_setDecryptionKey($this->_cPtr, $key);
    }


    function setPadding($padding)
    {
        VirgilSymmetricCipher_setPadding($this->_cPtr, $padding);
    }


    function setIV($iv)
    {
        VirgilSymmetricCipher_setIV($this->_cPtr, $iv);
    }


    function setAuthData($authData)
    {
        VirgilSymmetricCipher_setAuthData($this->_cPtr, $authData);
    }


    function reset()
    {
        VirgilSymmetricCipher_reset($this->_cPtr);
    }


    function clear()
    {
        VirgilSymmetricCipher_clear($this->_cPtr);
    }


    function crypt($input, $iv)
    {
        return VirgilSymmetricCipher_crypt($this->_cPtr, $input, $iv);
    }


    function update($input)
    {
        return VirgilSymmetricCipher_update($this->_cPtr, $input);
    }


    function finish()
    {
        return VirgilSymmetricCipher_finish($this->_cPtr);
    }
}
