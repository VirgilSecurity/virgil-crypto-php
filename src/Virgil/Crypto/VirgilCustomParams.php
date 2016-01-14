<?php

namespace Virgil\Crypto;

class VirgilCustomParams extends VirgilAsn1Compatible {
    public $_cPtr=null;

    function __set($var,$value) {
        if ($var === 'thisown') return swig_virgil_crypto_php_alter_newobject($this->_cPtr,$value);
        VirgilAsn1Compatible::__set($var,$value);
    }

    function __get($var) {
        if ($var === 'thisown') return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        return VirgilAsn1Compatible::__get($var);
    }

    function __isset($var) {
        if ($var === 'thisown') return true;
        return VirgilAsn1Compatible::__isset($var);
    }

    function isEmpty() {
        return VirgilCustomParams_isEmpty($this->_cPtr);
    }

    function setInteger($key,$value) {
        VirgilCustomParams_setInteger($this->_cPtr,$key,$value);
    }

    function getInteger($key) {
        return VirgilCustomParams_getInteger($this->_cPtr,$key);
    }

    function removeInteger($key) {
        VirgilCustomParams_removeInteger($this->_cPtr,$key);
    }

    function setString($key,$value) {
        VirgilCustomParams_setString($this->_cPtr,$key,$value);
    }

    function getString($key) {
        return VirgilCustomParams_getString($this->_cPtr,$key);
    }

    function removeString($key) {
        VirgilCustomParams_removeString($this->_cPtr,$key);
    }

    function setData($key,$value) {
        VirgilCustomParams_setData($this->_cPtr,$key,$value);
    }

    function getData($key) {
        return VirgilCustomParams_getData($this->_cPtr,$key);
    }

    function removeData($key) {
        VirgilCustomParams_removeData($this->_cPtr,$key);
    }

    function clear() {
        VirgilCustomParams_clear($this->_cPtr);
    }

    function __construct($other=null) {
        if (is_resource($other) && get_resource_type($other) === '_p_virgil__crypto__VirgilCustomParams') {
            $this->_cPtr=$other;
            return;
        }
        switch (func_num_args()) {
            case 0: $this->_cPtr=new_VirgilCustomParams(); break;
            default: $this->_cPtr=new_VirgilCustomParams($other);
        }
    }
}