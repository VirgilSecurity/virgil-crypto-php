<?php

namespace Virgil\Crypto;


class VirgilPFSPrivateKey
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($key_or_other = null, $password = null)
    {
        if (is_resource($key_or_other) &&
            get_resource_type($key_or_other) === '_p_virgil__crypto__pfs__VirgilPFSPrivateKey'
        ) {
            $this->_cPtr = $key_or_other;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilPFSPrivateKey();
                break;
            case 1:
                $this->_cPtr = new_VirgilPFSPrivateKey($key_or_other);
                break;
            default:
                $this->_cPtr = new_VirgilPFSPrivateKey($key_or_other, $password);
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
        return VirgilPFSPrivateKey_isEmpty($this->_cPtr);
    }


    function getKey()
    {
        return VirgilPFSPrivateKey_getKey($this->_cPtr);
    }


    function getPassword()
    {
        return VirgilPFSPrivateKey_getPassword($this->_cPtr);
    }
}
