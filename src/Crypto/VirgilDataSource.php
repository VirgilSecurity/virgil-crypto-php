<?php

namespace Virgil\Crypto;

abstract class VirgilDataSource {
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

    function hasData() {
        return VirgilDataSource_hasData($this->_cPtr);
    }

    function read() {
        return VirgilDataSource_read($this->_cPtr);
    }

    function __construct($res=null) {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__VirgilDataSource') {
            $this->_cPtr=$res;
            return;
        }
        if (get_class($this) === 'VirgilDataSource') {
            $_this = null;
        } else {
            $_this = $this;
        }
        $this->_cPtr=new_VirgilDataSource($_this);
    }
}