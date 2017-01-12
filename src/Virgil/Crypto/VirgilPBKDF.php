<?php

namespace Virgil\Crypto;


class VirgilPBKDF extends VirgilAsn1Compatible
{
    const kIterationCount_Default = VirgilPBKDF_kIterationCount_Default;
    const Algorithm_PBKDF2 = 0;
    public $_cPtr = null;


    function __construct($salt = null, $iterationCount = null)
    {
        if (is_resource($salt) && get_resource_type($salt) === '_p_virgil__crypto__foundation__VirgilPBKDF') {
            $this->_cPtr = $salt;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilPBKDF();
                break;
            case 1:
                $this->_cPtr = new_VirgilPBKDF($salt);
                break;
            default:
                $this->_cPtr = new_VirgilPBKDF($salt, $iterationCount);
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


    function getSalt()
    {
        return VirgilPBKDF_getSalt($this->_cPtr);
    }


    function getIterationCount()
    {
        return VirgilPBKDF_getIterationCount($this->_cPtr);
    }


    function setAlgorithm($alg)
    {
        VirgilPBKDF_setAlgorithm($this->_cPtr, $alg);
    }


    function getAlgorithm()
    {
        return VirgilPBKDF_getAlgorithm($this->_cPtr);
    }


    function setHashAlgorithm($hash)
    {
        VirgilPBKDF_setHashAlgorithm($this->_cPtr, $hash);
    }


    function getHashAlgorithm()
    {
        return VirgilPBKDF_getHashAlgorithm($this->_cPtr);
    }


    function enableRecommendationsCheck()
    {
        VirgilPBKDF_enableRecommendationsCheck($this->_cPtr);
    }


    function disableRecommendationsCheck()
    {
        VirgilPBKDF_disableRecommendationsCheck($this->_cPtr);
    }


    function derive($pwd, $outSize = null)
    {
        switch (func_num_args()) {
            case 1:
                $r = VirgilPBKDF_derive($this->_cPtr, $pwd);
                break;
            default:
                $r = VirgilPBKDF_derive($this->_cPtr, $pwd, $outSize);
        }

        return $r;
    }
}
