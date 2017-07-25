<?php

namespace Virgil\Crypto;


class VirgilHash extends VirgilAsn1Compatible
{
    const Algorithm_MD5 = 0;
    const Algorithm_SHA1 = VirgilHash_Algorithm_SHA1;
    const Algorithm_SHA224 = VirgilHash_Algorithm_SHA224;
    const Algorithm_SHA256 = VirgilHash_Algorithm_SHA256;
    const Algorithm_SHA384 = VirgilHash_Algorithm_SHA384;
    const Algorithm_SHA512 = VirgilHash_Algorithm_SHA512;
    public $_cPtr = null;


    function __construct($alg_or_name_or_rhs = null)
    {
        if (is_resource($alg_or_name_or_rhs) &&
            get_resource_type($alg_or_name_or_rhs) === '_p_virgil__crypto__foundation__VirgilHash'
        ) {
            $this->_cPtr = $alg_or_name_or_rhs;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilHash();
                break;
            default:
                $this->_cPtr = new_VirgilHash($alg_or_name_or_rhs);
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
        return VirgilHash_name($this->_cPtr);
    }


    function algorithm()
    {
        return VirgilHash_algorithm($this->_cPtr);
    }


    function type()
    {
        return VirgilHash_type($this->_cPtr);
    }


    function size()
    {
        return VirgilHash_size($this->_cPtr);
    }


    function hash($data)
    {
        return VirgilHash_hash($this->_cPtr, $data);
    }


    function start()
    {
        VirgilHash_start($this->_cPtr);
    }


    function update($data)
    {
        VirgilHash_update($this->_cPtr, $data);
    }


    function finish()
    {
        return VirgilHash_finish($this->_cPtr);
    }


    function hmac($key, $data)
    {
        return VirgilHash_hmac($this->_cPtr, $key, $data);
    }


    function hmacStart($key)
    {
        VirgilHash_hmacStart($this->_cPtr, $key);
    }


    function hmacReset()
    {
        VirgilHash_hmacReset($this->_cPtr);
    }


    function hmacUpdate($data)
    {
        VirgilHash_hmacUpdate($this->_cPtr, $data);
    }


    function hmacFinish()
    {
        return VirgilHash_hmacFinish($this->_cPtr);
    }
}
