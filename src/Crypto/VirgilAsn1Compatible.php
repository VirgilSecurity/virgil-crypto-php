<?php

namespace Virgil\Crypto;

abstract class VirgilAsn1Compatible {
    public $_cPtr=null;
    protected $_pData=array();

    function __set($var,$value) {
        if ($var === 'thisown') return swig_virgil_php_alter_newobject($this->_cPtr,$value);
        $this->_pData[$var] = $value;
    }

    function __get($var) {
        if ($var === 'thisown') return swig_virgil_php_get_newobject($this->_cPtr);
        return $this->_pData[$var];
    }

    function __isset($var) {
        if ($var === 'thisown') return true;
        return array_key_exists($var, $this->_pData);
    }
    function __construct($h) {
        $this->_cPtr=$h;
    }

    function toAsn1() {
        return VirgilAsn1Compatible_toAsn1($this->_cPtr);
    }

    function fromAsn1($asn1) {
        VirgilAsn1Compatible_fromAsn1($this->_cPtr,$asn1);
    }
}