<?php

namespace Virgil\Crypto;

class VirgilChunkCipher extends VirgilCipherBase {
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

    const kPreferredChunkSize = VirgilChunkCipher_kPreferredChunkSize;

    function encrypt($source,$sink,$embedContentInfo=true,$preferredChunkSize=null) {
        switch (func_num_args()) {
            case 2: case 3: VirgilChunkCipher_encrypt($this->_cPtr,$source,$sink,$embedContentInfo); break;
            default: VirgilChunkCipher_encrypt($this->_cPtr,$source,$sink,$embedContentInfo,$preferredChunkSize);
        }
    }

    function decryptWithKey($source,$sink,$recipientId,$privateKey,$privateKeyPassword=null) {
        switch (func_num_args()) {
            case 4: VirgilChunkCipher_decryptWithKey($this->_cPtr,$source,$sink,$recipientId,$privateKey); break;
            default: VirgilChunkCipher_decryptWithKey($this->_cPtr,$source,$sink,$recipientId,$privateKey,$privateKeyPassword);
        }
    }

    function decryptWithPassword($source,$sink,$pwd) {
        VirgilChunkCipher_decryptWithPassword($this->_cPtr,$source,$sink,$pwd);
    }

    function __construct($res=null) {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__VirgilChunkCipher') {
            $this->_cPtr=$res;
            return;
        }
        $this->_cPtr=new_VirgilChunkCipher();
    }
}