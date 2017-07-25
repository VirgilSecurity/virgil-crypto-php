<?php

namespace Virgil\Crypto;


class VirgilSigner extends VirgilSignerBase
{
    public $_cPtr = null;


    function __construct($res = null)
    {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__VirgilSigner') {
            $this->_cPtr = $res;

            return;
        }
        $this->_cPtr = new_VirgilSigner();
    }


    function __set($var, $value)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_alter_newobject($this->_cPtr, $value);
        }
        VirgilSignerBase::__set($var, $value);
    }


    function __get($var)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        }

        return VirgilSignerBase::__get($var);
    }


    function __isset($var)
    {
        if ($var === 'thisown') {
            return true;
        }

        return VirgilSignerBase::__isset($var);
    }


    function sign($data, $privateKey, $privateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 2:
                $r = VirgilSigner_sign($this->_cPtr, $data, $privateKey);
                break;
            default:
                $r = VirgilSigner_sign($this->_cPtr, $data, $privateKey, $privateKeyPassword);
        }

        return $r;
    }


    function verify($data, $sign, $publicKey)
    {
        return VirgilSigner_verify($this->_cPtr, $data, $sign, $publicKey);
    }
}
