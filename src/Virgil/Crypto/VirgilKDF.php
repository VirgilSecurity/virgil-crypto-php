<?php

namespace Virgil\Crypto;


class VirgilKDF extends VirgilAsn1Compatible
{
    const Algorithm_KDF1 = 0;
    const Algorithm_KDF2 = VirgilKDF_Algorithm_KDF2;
    public $_cPtr = null;


    function __construct($alg_or_name = null)
    {
        if (is_resource($alg_or_name) &&
            get_resource_type($alg_or_name) === '_p_virgil__crypto__foundation__VirgilKDF'
        ) {
            $this->_cPtr = $alg_or_name;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilKDF();
                break;
            default:
                $this->_cPtr = new_VirgilKDF($alg_or_name);
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
        return VirgilKDF_name($this->_cPtr);
    }


    function derive($in, $outSize)
    {
        return VirgilKDF_derive($this->_cPtr, $in, $outSize);
    }
}
