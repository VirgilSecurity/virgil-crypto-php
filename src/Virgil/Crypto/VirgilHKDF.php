<?php

namespace Virgil\Crypto;


class VirgilHKDF
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($hashAlgorithm)
    {
        if (is_resource($hashAlgorithm) &&
            get_resource_type($hashAlgorithm) === '_p_virgil__crypto__foundation__VirgilHKDF'
        ) {
            $this->_cPtr = $hashAlgorithm;

            return;
        }
        $this->_cPtr = new_VirgilHKDF($hashAlgorithm);
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


    function derive($in, $salt, $info, $outSize)
    {
        return VirgilHKDF_derive($this->_cPtr, $in, $salt, $info, $outSize);
    }
}
