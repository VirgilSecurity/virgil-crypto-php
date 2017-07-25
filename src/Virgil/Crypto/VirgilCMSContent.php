<?php

namespace Virgil\Crypto;


class VirgilCMSContent extends VirgilAsn1Compatible
{
    const Type_Data = 0;
    const Type_SignedData = VirgilCMSContent_Type_SignedData;
    const Type_EnvelopedData = VirgilCMSContent_Type_EnvelopedData;
    const Type_DigestedData = VirgilCMSContent_Type_DigestedData;
    const Type_EncryptedData = VirgilCMSContent_Type_EncryptedData;
    const Type_AuthenticatedData = VirgilCMSContent_Type_AuthenticatedData;
    const Type_SignedAndEnvelopedData = VirgilCMSContent_Type_SignedAndEnvelopedData;
    const Type_DataWithAttributes = VirgilCMSContent_Type_DataWithAttributes;
    const Type_EncryptedPrivateKeyInfo = VirgilCMSContent_Type_EncryptedPrivateKeyInfo;
    public $_cPtr = null;


    function __construct($other = null)
    {
        if (is_resource($other) &&
            get_resource_type($other) === '_p_virgil__crypto__foundation__cms__VirgilCMSContent'
        ) {
            $this->_cPtr = $other;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilCMSContent();
                break;
            default:
                $this->_cPtr = new_VirgilCMSContent($other);
        }
    }


    function __set($var, $value)
    {
        if ($var === 'content') {
            return VirgilCMSContent_content_set($this->_cPtr, $value);
        }
        if ($var === 'contentType') {
            return VirgilCMSContent_contentType_set($this->_cPtr, $value);
        }
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_alter_newobject($this->_cPtr, $value);
        }
        VirgilAsn1Compatible::__set($var, $value);
    }


    function __get($var)
    {
        if ($var === 'content') {
            return VirgilCMSContent_content_get($this->_cPtr);
        }
        if ($var === 'contentType') {
            return VirgilCMSContent_contentType_get($this->_cPtr);
        }
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        }

        return VirgilAsn1Compatible::__get($var);
    }


    function __isset($var)
    {
        if (function_exists('VirgilCMSContent_' . $var . '_get')) {
            return true;
        }
        if ($var === 'thisown') {
            return true;
        }

        return VirgilAsn1Compatible::__isset($var);
    }
}
