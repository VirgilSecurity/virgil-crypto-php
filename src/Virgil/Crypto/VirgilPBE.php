<?php

namespace Virgil\Crypto;


class VirgilPBE extends VirgilAsn1Compatible
{
    const Algorithm_PKCS5 = 0;
    const Algorithm_PKCS12 = VirgilPBE_Algorithm_PKCS12;
    const kIterationCountMin = VirgilPBE_kIterationCountMin;
    public $_cPtr = null;


    function __construct($alg = null, $salt = null, $iterationCount = null)
    {
        if (is_resource($alg) && get_resource_type($alg) === '_p_virgil__crypto__foundation__VirgilPBE') {
            $this->_cPtr = $alg;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilPBE();
                break;
            case 1:
                $this->_cPtr = new_VirgilPBE($alg);
                break;
            case 2:
                $this->_cPtr = new_VirgilPBE($alg, $salt);
                break;
            default:
                $this->_cPtr = new_VirgilPBE($alg, $salt, $iterationCount);
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


    function encrypt($data, $pwd)
    {
        return VirgilPBE_encrypt($this->_cPtr, $data, $pwd);
    }


    function decrypt($data, $pwd)
    {
        return VirgilPBE_decrypt($this->_cPtr, $data, $pwd);
    }
}
