<?php

namespace Virgil\Crypto;

class VirgilCipher extends VirgilCipherBase {
    public $_cPtr=null;

    function __set($var,$value) {
        if ($var === 'thisown') return swig_virgil_crypto_php_alter_newobject($this->_cPtr,$value);
        VirgilCipherBase::__set($var,$value);
    }

    function __get($var) {
        if ($var === 'thisown') return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        return VirgilCipherBase::__get($var);
    }

    function __isset($var) {
        if ($var === 'thisown') return true;
        return VirgilCipherBase::__isset($var);
    }

    function encrypt($data,$embedContentInfo=false) {
        return VirgilCipher_encrypt($this->_cPtr,$data,$embedContentInfo);
    }

    function decryptWithKey($encryptedData,$recipientId,$privateKey,$privateKeyPassword=null) {
        switch (func_num_args()) {
            case 3: $r=VirgilCipher_decryptWithKey($this->_cPtr,$encryptedData,$recipientId,$privateKey); break;
            default: $r=VirgilCipher_decryptWithKey($this->_cPtr,$encryptedData,$recipientId,$privateKey,$privateKeyPassword);
        }
        return $r;
    }

    function decryptWithPassword($encryptedData,$pwd) {
        return VirgilCipher_decryptWithPassword($this->_cPtr,$encryptedData,$pwd);
    }

    function __construct($res=null) {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__VirgilCipher') {
            $this->_cPtr=$res;
            return;
        }
        $this->_cPtr=new_VirgilCipher();
    }
}