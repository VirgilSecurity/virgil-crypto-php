<?php

namespace Virgil\Crypto;

abstract class VirgilDataSink {
    public $_cPtr=null;
    protected $_pData=array();

    function __set($var,$value) {
        if ($var === 'thisown') return swig_virgil_crypto_php_alter_newobject($this->_cPtr,$value);
        $this->_pData[$var] = $value;
    }

    function __get($var) {
        if ($var === 'thisown') return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        return $this->_pData[$var];
    }

    function __isset($var) {
        if ($var === 'thisown') return true;
        return array_key_exists($var, $this->_pData);
    }

    function isGood() {
        return VirgilDataSink_isGood($this->_cPtr);
    }

    function write($data) {
        VirgilDataSink_write($this->_cPtr,$data);
    }

    function __construct($res=null) {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__VirgilDataSink') {
            $this->_cPtr=$res;
            return;
        }
        if (get_class($this) === 'VirgilDataSink') {
            $_this = null;
        } else {
            $_this = $this;
        }
        $this->_cPtr=new_VirgilDataSink($_this);
    }
}