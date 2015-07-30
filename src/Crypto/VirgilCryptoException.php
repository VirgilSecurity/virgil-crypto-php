<?php

namespace Virgil\Crypto;

class VirgilCryptoException {
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

    function __construct($what) {
        if (is_resource($what) && get_resource_type($what) === '_p_virgil__crypto__VirgilCryptoException') {
            $this->_cPtr=$what;
            return;
        }
        $this->_cPtr=new_VirgilCryptoException($what);
    }
}