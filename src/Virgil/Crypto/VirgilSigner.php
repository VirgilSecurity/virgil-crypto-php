<?php

namespace Virgil\Crypto;

class VirgilSigner {
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

    function __construct($hash=null) {
        if (is_resource($hash) && get_resource_type($hash) === '_p_virgil__crypto__VirgilSigner') {
            $this->_cPtr=$hash;
            return;
        }
        switch (func_num_args()) {
            case 0: $this->_cPtr=new_VirgilSigner(); break;
            default: $this->_cPtr=new_VirgilSigner($hash);
        }
    }

    function sign($data,$privateKey,$privateKeyPassword=null) {
        switch (func_num_args()) {
            case 2: $r=VirgilSigner_sign($this->_cPtr,$data,$privateKey); break;
            default: $r=VirgilSigner_sign($this->_cPtr,$data,$privateKey,$privateKeyPassword);
        }
        return $r;
    }

    function verify($data,$sign,$publicKey) {
        return VirgilSigner_verify($this->_cPtr,$data,$sign,$publicKey);
    }
}