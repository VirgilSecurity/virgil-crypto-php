<?php

namespace Virgil\Crypto;


class VirgilCMSContentInfo extends VirgilAsn1Compatible
{
    public $_cPtr = null;


    function __construct($other = null)
    {
        if (is_resource($other) &&
            get_resource_type($other) === '_p_virgil__crypto__foundation__cms__VirgilCMSContentInfo'
        ) {
            $this->_cPtr = $other;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilCMSContentInfo();
                break;
            default:
                $this->_cPtr = new_VirgilCMSContentInfo($other);
        }
    }


    static function defineSize($data)
    {
        return VirgilCMSContentInfo_defineSize($data);
    }


    function __set($var, $value)
    {
        if ($var === 'cmsContent') {
            return VirgilCMSContentInfo_cmsContent_set($this->_cPtr, $value);
        }
        if ($var === 'customParams') {
            return VirgilCMSContentInfo_customParams_set($this->_cPtr, $value);
        }
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_alter_newobject($this->_cPtr, $value);
        }
        VirgilAsn1Compatible::__set($var, $value);
    }


    function __get($var)
    {
        if ($var === 'cmsContent') {
            return new VirgilCMSContent(VirgilCMSContentInfo_cmsContent_get($this->_cPtr));
        }
        if ($var === 'customParams') {
            return new VirgilCustomParams(VirgilCMSContentInfo_customParams_get($this->_cPtr));
        }
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        }

        return VirgilAsn1Compatible::__get($var);
    }


    function __isset($var)
    {
        if (function_exists('VirgilCMSContentInfo_' . $var . '_get')) {
            return true;
        }
        if ($var === 'thisown') {
            return true;
        }

        return VirgilAsn1Compatible::__isset($var);
    }
}
