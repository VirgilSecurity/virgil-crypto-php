<?php

namespace Virgil\Crypto;


class VirgilPFSPublicKey
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($key = null)
    {
        if (is_resource($key) && get_resource_type($key) === '_p_virgil__crypto__pfs__VirgilPFSPublicKey') {
            $this->_cPtr = $key;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilPFSPublicKey();
                break;
            default:
                $this->_cPtr = new_VirgilPFSPublicKey($key);
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
        return VirgilPFSPublicKey_isEmpty($this->_cPtr);
    }


    function getKey()
    {
        return VirgilPFSPublicKey_getKey($this->_cPtr);
    }
}
