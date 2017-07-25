<?php

namespace Virgil\Crypto;


class VirgilBase64
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($h)
    {
        $this->_cPtr = $h;
    }


    static function encode($data)
    {
        return VirgilBase64_encode($data);
    }


    static function decode($base64str)
    {
        return VirgilBase64_decode($base64str);
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
}
