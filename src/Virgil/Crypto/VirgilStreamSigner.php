<?php

namespace Virgil\Crypto;


class VirgilStreamSigner extends VirgilSignerBase
{
    public $_cPtr = null;


    function __construct($res = null)
    {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__VirgilStreamSigner') {
            $this->_cPtr = $res;

            return;
        }
        $this->_cPtr = new_VirgilStreamSigner();
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


    function sign($source, $privateKey, $privateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 2:
                $r = VirgilStreamSigner_sign($this->_cPtr, $source, $privateKey);
                break;
            default:
                $r = VirgilStreamSigner_sign($this->_cPtr, $source, $privateKey, $privateKeyPassword);
        }

        return $r;
    }


    function verify($source, $sign, $publicKey)
    {
        return VirgilStreamSigner_verify($this->_cPtr, $source, $sign, $publicKey);
    }
}
