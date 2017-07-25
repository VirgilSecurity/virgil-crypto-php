<?php

namespace Virgil\Crypto;


class VirgilRandom
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($personalInfo_or_rhs)
    {
        if (is_resource($personalInfo_or_rhs) &&
            get_resource_type($personalInfo_or_rhs) === '_p_virgil__crypto__foundation__VirgilRandom'
        ) {
            $this->_cPtr = $personalInfo_or_rhs;

            return;
        }
        $this->_cPtr = new_VirgilRandom($personalInfo_or_rhs);
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


    function randomize($bytesNum_or_min = null, $max = null)
    {
        switch (func_num_args()) {
            case 0:
                $r = VirgilRandom_randomize($this->_cPtr);
                break;
            case 1:
                $r = VirgilRandom_randomize($this->_cPtr, $bytesNum_or_min);
                break;
            default:
                $r = VirgilRandom_randomize($this->_cPtr, $bytesNum_or_min, $max);
        }

        return $r;
    }
}
