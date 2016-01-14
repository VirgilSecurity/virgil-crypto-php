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

    function startEncryption($preferredChunkSize=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilChunkCipher_startEncryption($this->_cPtr); break;
            default: $r=VirgilChunkCipher_startEncryption($this->_cPtr,$preferredChunkSize);
        }
        return $r;
    }

    function startDecryptionWithKey($recipientId,$privateKey,$privateKeyPassword=null) {
        switch (func_num_args()) {
            case 2: $r=VirgilChunkCipher_startDecryptionWithKey($this->_cPtr,$recipientId,$privateKey); break;
            default: $r=VirgilChunkCipher_startDecryptionWithKey($this->_cPtr,$recipientId,$privateKey,$privateKeyPassword);
        }
        return $r;
    }

    function startDecryptionWithPassword($pwd) {
        return VirgilChunkCipher_startDecryptionWithPassword($this->_cPtr,$pwd);
    }

    function process($data) {
        return VirgilChunkCipher_process($this->_cPtr,$data);
    }

    function finish() {
        VirgilChunkCipher_finish($this->_cPtr);
    }

    function __construct($res=null) {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__VirgilChunkCipher') {
            $this->_cPtr=$res;
            return;
        }
        $this->_cPtr=new_VirgilChunkCipher();
    }
}