<?php

namespace Virgil\Crypto;


class VirgilByteArrayUtils
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($h)
    {
        $this->_cPtr = $h;
    }


    static function jsonToBytes($json)
    {
        return VirgilByteArrayUtils_jsonToBytes($json);
    }


    static function stringToBytes($str)
    {
        return VirgilByteArrayUtils_stringToBytes($str);
    }


    static function bytesToString($array)
    {
        return VirgilByteArrayUtils_bytesToString($array);
    }


    static function hexToBytes($hexStr)
    {
        return VirgilByteArrayUtils_hexToBytes($hexStr);
    }


    static function bytesToHex($array, $formatted = false)
    {
        return VirgilByteArrayUtils_bytesToHex($array, $formatted);
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
