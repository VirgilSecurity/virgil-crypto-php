<?php

namespace Virgil\Crypto;


class VirgilAsn1Writer
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($capacity = null)
    {
        if (is_resource($capacity) &&
            get_resource_type($capacity) === '_p_virgil__crypto__foundation__asn1__VirgilAsn1Writer'
        ) {
            $this->_cPtr = $capacity;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilAsn1Writer();
                break;
            default:
                $this->_cPtr = new_VirgilAsn1Writer($capacity);
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


    function reset($capacity = null)
    {
        switch (func_num_args()) {
            case 0:
                VirgilAsn1Writer_reset($this->_cPtr);
                break;
            default:
                VirgilAsn1Writer_reset($this->_cPtr, $capacity);
        }
    }


    function finish()
    {
        return VirgilAsn1Writer_finish($this->_cPtr);
    }


    function writeInteger($value)
    {
        return VirgilAsn1Writer_writeInteger($this->_cPtr, $value);
    }


    function writeBool($value)
    {
        return VirgilAsn1Writer_writeBool($this->_cPtr, $value);
    }


    function writeNull()
    {
        return VirgilAsn1Writer_writeNull($this->_cPtr);
    }


    function writeOctetString($data)
    {
        return VirgilAsn1Writer_writeOctetString($this->_cPtr, $data);
    }


    function writeUTF8String($data)
    {
        return VirgilAsn1Writer_writeUTF8String($this->_cPtr, $data);
    }


    function writeContextTag($tag, $len)
    {
        return VirgilAsn1Writer_writeContextTag($this->_cPtr, $tag, $len);
    }


    function writeData($data)
    {
        return VirgilAsn1Writer_writeData($this->_cPtr, $data);
    }


    function writeOID($oid)
    {
        return VirgilAsn1Writer_writeOID($this->_cPtr, $oid);
    }


    function writeSequence($len)
    {
        return VirgilAsn1Writer_writeSequence($this->_cPtr, $len);
    }


    function writeSet($set)
    {
        return VirgilAsn1Writer_writeSet($this->_cPtr, $set);
    }
}
