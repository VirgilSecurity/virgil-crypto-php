<?php

namespace Virgil\Crypto;


class VirgilTinyCipher {
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

    const PackageSize_Min = 113;

    const PackageSize_Short_SMS = 120;

    const PackageSize_Long_SMS = 1200;

    function __construct($packageSize=null) {
        if (is_resource($packageSize) && get_resource_type($packageSize) === '_p_virgil__crypto__VirgilTinyCipher') {
            $this->_cPtr=$packageSize;
            return;
        }
        switch (func_num_args()) {
            case 0: $this->_cPtr=new_VirgilTinyCipher(); break;
            default: $this->_cPtr=new_VirgilTinyCipher($packageSize);
        }
    }

    function reset() {
        VirgilTinyCipher_reset($this->_cPtr);
    }

    function encrypt($data,$recipientPublicKey) {
        VirgilTinyCipher_encrypt($this->_cPtr,$data,$recipientPublicKey);
    }

    function encryptAndSign($data,$recipientPublicKey,$senderPrivateKey,$senderPrivateKeyPassword=null) {
        switch (func_num_args()) {
            case 3: VirgilTinyCipher_encryptAndSign($this->_cPtr,$data,$recipientPublicKey,$senderPrivateKey); break;
            default: VirgilTinyCipher_encryptAndSign($this->_cPtr,$data,$recipientPublicKey,$senderPrivateKey,$senderPrivateKeyPassword);
        }
    }

    function getPackageCount() {
        return VirgilTinyCipher_getPackageCount($this->_cPtr);
    }

    function getPackage($index) {
        return VirgilTinyCipher_getPackage($this->_cPtr,$index);
    }

    function addPackage($package) {
        VirgilTinyCipher_addPackage($this->_cPtr,$package);
    }

    function isPackagesAccumulated() {
        return VirgilTinyCipher_isPackagesAccumulated($this->_cPtr);
    }

    function decrypt($recipientPrivateKey,$recipientPrivateKeyPassword=null) {
        switch (func_num_args()) {
            case 1: $r=VirgilTinyCipher_decrypt($this->_cPtr,$recipientPrivateKey); break;
            default: $r=VirgilTinyCipher_decrypt($this->_cPtr,$recipientPrivateKey,$recipientPrivateKeyPassword);
        }
        return $r;
    }

    function verifyAndDecrypt($senderPublicKey,$recipientPrivateKey,$recipientPrivateKeyPassword=null) {
        switch (func_num_args()) {
            case 2: $r=VirgilTinyCipher_verifyAndDecrypt($this->_cPtr,$senderPublicKey,$recipientPrivateKey); break;
            default: $r=VirgilTinyCipher_verifyAndDecrypt($this->_cPtr,$senderPublicKey,$recipientPrivateKey,$recipientPrivateKeyPassword);
        }
        return $r;
    }
}