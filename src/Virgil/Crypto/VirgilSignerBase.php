<?php

namespace Virgil\Crypto;


class VirgilSignerBase
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($hashAlgorithm = null)
    {
        if (is_resource($hashAlgorithm) &&
            get_resource_type($hashAlgorithm) === '_p_virgil__crypto__VirgilSignerBase'
        ) {
            $this->_cPtr = $hashAlgorithm;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilSignerBase();
                break;
            default:
                $this->_cPtr = new_VirgilSignerBase($hashAlgorithm);
        }
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


    function getHashAlgorithm()
    {
        return VirgilSignerBase_getHashAlgorithm($this->_cPtr);
    }


    function signHash($digest, $privateKey, $privateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 2:
                $r = VirgilSignerBase_signHash($this->_cPtr, $digest, $privateKey);
                break;
            default:
                $r = VirgilSignerBase_signHash($this->_cPtr, $digest, $privateKey, $privateKeyPassword);
        }

        return $r;
    }


    function verifyHash($digest, $signature, $publicKey)
    {
        return VirgilSignerBase_verifyHash($this->_cPtr, $digest, $signature, $publicKey);
    }
}
