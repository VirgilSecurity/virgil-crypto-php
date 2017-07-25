<?php

namespace Virgil\Crypto;


class VirgilPFSSession
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct(
        $identifier = null,
        $encryptionSecretKey = null,
        $decryptionSecretKey = null,
        $additionalData = null
    ) {
        if (is_resource($identifier) && get_resource_type($identifier) === '_p_virgil__crypto__pfs__VirgilPFSSession') {
            $this->_cPtr = $identifier;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilPFSSession();
                break;
            case 1:
                $this->_cPtr = new_VirgilPFSSession($identifier);
                break;
            case 2:
                $this->_cPtr = new_VirgilPFSSession($identifier, $encryptionSecretKey);
                break;
            case 3:
                $this->_cPtr = new_VirgilPFSSession($identifier, $encryptionSecretKey, $decryptionSecretKey);
                break;
            default:
                $this->_cPtr = new_VirgilPFSSession(
                    $identifier,
                    $encryptionSecretKey,
                    $decryptionSecretKey,
                    $additionalData
                );
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


    function isEmpty()
    {
        return VirgilPFSSession_isEmpty($this->_cPtr);
    }


    function getIdentifier()
    {
        return VirgilPFSSession_getIdentifier($this->_cPtr);
    }


    function getEncryptionSecretKey()
    {
        return VirgilPFSSession_getEncryptionSecretKey($this->_cPtr);
    }


    function getDecryptionSecretKey()
    {
        return VirgilPFSSession_getDecryptionSecretKey($this->_cPtr);
    }


    function getAdditionalData()
    {
        return VirgilPFSSession_getAdditionalData($this->_cPtr);
    }
}
