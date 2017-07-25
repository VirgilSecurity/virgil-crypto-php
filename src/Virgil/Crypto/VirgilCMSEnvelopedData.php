<?php

namespace Virgil\Crypto;


class VirgilCMSEnvelopedData extends VirgilAsn1Compatible
{
    public $_cPtr = null;


    function __construct($other = null)
    {
        if (is_resource($other) &&
            get_resource_type($other) === '_p_virgil__crypto__foundation__cms__VirgilCMSEnvelopedData'
        ) {
            $this->_cPtr = $other;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilCMSEnvelopedData();
                break;
            default:
                $this->_cPtr = new_VirgilCMSEnvelopedData($other);
        }
    }


    function __set($var, $value)
    {
        $func = 'VirgilCMSEnvelopedData_' . $var . '_set';
        if (function_exists($func)) {
            return call_user_func($func, $this->_cPtr, $value);
        }
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_alter_newobject($this->_cPtr, $value);
        }
        VirgilAsn1Compatible::__set($var, $value);
    }


    function __get($var)
    {
        if ($var === 'encryptedContent') {
            return new VirgilCMSEncryptedContent(VirgilCMSEnvelopedData_encryptedContent_get($this->_cPtr));
        }
        if ($var === 'keyTransRecipients') {
            return VirgilCMSEnvelopedData_keyTransRecipients_get($this->_cPtr);
        }
        if ($var === 'passwordRecipients') {
            return VirgilCMSEnvelopedData_passwordRecipients_get($this->_cPtr);
        }
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        }

        return VirgilAsn1Compatible::__get($var);
    }


    function __isset($var)
    {
        if (function_exists('VirgilCMSEnvelopedData_' . $var . '_get')) {
            return true;
        }
        if ($var === 'thisown') {
            return true;
        }

        return VirgilAsn1Compatible::__isset($var);
    }
}
