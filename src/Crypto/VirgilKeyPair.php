<?php

namespace Virgil\Crypto;

class VirgilKeyPair {
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

    function publicKey() {
        return VirgilKeyPair_publicKey($this->_cPtr);
    }

    function privateKey() {
        return VirgilKeyPair_privateKey($this->_cPtr);
    }

    function __construct($pwd_or_publicKey_or_other=null,$privateKey=null) {
        if (is_resource($pwd_or_publicKey_or_other) && get_resource_type($pwd_or_publicKey_or_other) === '_p_virgil__crypto__VirgilKeyPair') {
            $this->_cPtr=$pwd_or_publicKey_or_other;
            return;
        }
        switch (func_num_args()) {
            case 0: $this->_cPtr=new_VirgilKeyPair(); break;
            case 1: $this->_cPtr=new_VirgilKeyPair($pwd_or_publicKey_or_other); break;
            default: $this->_cPtr=new_VirgilKeyPair($pwd_or_publicKey_or_other,$privateKey);
        }
    }
}