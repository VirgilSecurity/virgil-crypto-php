<?php

namespace Virgil\Crypto;


class VirgilAsn1Reader
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($data = null)
    {
        if (is_resource($data) &&
            get_resource_type($data) === '_p_virgil__crypto__foundation__asn1__VirgilAsn1Reader'
        ) {
            $this->_cPtr = $data;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilAsn1Reader();
                break;
            default:
                $this->_cPtr = new_VirgilAsn1Reader($data);
        }
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


    function reset($data)
    {
        VirgilAsn1Reader_reset($this->_cPtr, $data);
    }


    function readInteger()
    {
        return VirgilAsn1Reader_readInteger($this->_cPtr);
    }


    function readBool()
    {
        return VirgilAsn1Reader_readBool($this->_cPtr);
    }


    function readNull()
    {
        VirgilAsn1Reader_readNull($this->_cPtr);
    }


    function readOctetString()
    {
        return VirgilAsn1Reader_readOctetString($this->_cPtr);
    }


    function readUTF8String()
    {
        return VirgilAsn1Reader_readUTF8String($this->_cPtr);
    }


    function readData()
    {
        return VirgilAsn1Reader_readData($this->_cPtr);
    }


    function readContextTag($tag)
    {
        return VirgilAsn1Reader_readContextTag($this->_cPtr, $tag);
    }


    function readOID()
    {
        return VirgilAsn1Reader_readOID($this->_cPtr);
    }


    function readSequence()
    {
        return VirgilAsn1Reader_readSequence($this->_cPtr);
    }


    function readSet()
    {
        return VirgilAsn1Reader_readSet($this->_cPtr);
    }
}
