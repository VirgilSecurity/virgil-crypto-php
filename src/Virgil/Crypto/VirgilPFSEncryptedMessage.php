<?php

namespace Virgil\Crypto;


class VirgilPFSEncryptedMessage
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($sessionIdentifier, $salt = null, $cipherText = null)
    {
        if (is_resource($sessionIdentifier) &&
            get_resource_type($sessionIdentifier) === '_p_virgil__crypto__pfs__VirgilPFSEncryptedMessage'
        ) {
            $this->_cPtr = $sessionIdentifier;

            return;
        }
        $this->_cPtr = new_VirgilPFSEncryptedMessage($sessionIdentifier, $salt, $cipherText);
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


    function getSessionIdentifier()
    {
        return VirgilPFSEncryptedMessage_getSessionIdentifier($this->_cPtr);
    }


    function getSalt()
    {
        return VirgilPFSEncryptedMessage_getSalt($this->_cPtr);
    }


    function getCipherText()
    {
        return VirgilPFSEncryptedMessage_getCipherText($this->_cPtr);
    }
}
