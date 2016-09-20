<?php

namespace Virgil\Crypto;

class VirgilKeyPair {
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

    const Type_RSA_256 = 0;

    const Type_RSA_512 = VirgilKeyPair_Type_RSA_512;

    const Type_RSA_1024 = VirgilKeyPair_Type_RSA_1024;

    const Type_RSA_2048 = VirgilKeyPair_Type_RSA_2048;

    const Type_RSA_3072 = VirgilKeyPair_Type_RSA_3072;

    const Type_RSA_4096 = VirgilKeyPair_Type_RSA_4096;

    const Type_RSA_8192 = VirgilKeyPair_Type_RSA_8192;

    const Type_EC_SECP192R1 = VirgilKeyPair_Type_EC_SECP192R1;

    const Type_EC_SECP224R1 = VirgilKeyPair_Type_EC_SECP224R1;

    const Type_EC_SECP256R1 = VirgilKeyPair_Type_EC_SECP256R1;

    const Type_EC_SECP384R1 = VirgilKeyPair_Type_EC_SECP384R1;

    const Type_EC_SECP521R1 = VirgilKeyPair_Type_EC_SECP521R1;

    const Type_EC_BP256R1 = VirgilKeyPair_Type_EC_BP256R1;

    const Type_EC_BP384R1 = VirgilKeyPair_Type_EC_BP384R1;

    const Type_EC_BP512R1 = VirgilKeyPair_Type_EC_BP512R1;

    const Type_EC_SECP192K1 = VirgilKeyPair_Type_EC_SECP192K1;

    const Type_EC_SECP224K1 = VirgilKeyPair_Type_EC_SECP224K1;

    const Type_EC_SECP256K1 = VirgilKeyPair_Type_EC_SECP256K1;

    const Type_EC_CURVE25519 = VirgilKeyPair_Type_EC_CURVE25519;

    const Type_EC_ED25519 = VirgilKeyPair_Type_EC_ED25519;

    static function generate($type,$pwd=null) {
        switch (func_num_args()) {
            case 1: $r=VirgilKeyPair_generate($type); break;
            default: $r=VirgilKeyPair_generate($type,$pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function generateRecommended($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_generateRecommended(); break;
            default: $r=VirgilKeyPair_generateRecommended($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function generateFrom($donorKeyPair,$donorPrivateKeyPassword=null,$newKeyPairPassword=null) {
        switch (func_num_args()) {
            case 1: $r=VirgilKeyPair_generateFrom($donorKeyPair); break;
            case 2: $r=VirgilKeyPair_generateFrom($donorKeyPair,$donorPrivateKeyPassword); break;
            default: $r=VirgilKeyPair_generateFrom($donorKeyPair,$donorPrivateKeyPassword,$newKeyPairPassword);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function isKeyPairMatch($publicKey,$privateKey,$privateKeyPassword=null) {
        switch (func_num_args()) {
            case 2: $r=VirgilKeyPair_isKeyPairMatch($publicKey,$privateKey); break;
            default: $r=VirgilKeyPair_isKeyPairMatch($publicKey,$privateKey,$privateKeyPassword);
        }
        return $r;
    }

    static function checkPrivateKeyPassword($key,$pwd) {
        return VirgilKeyPair_checkPrivateKeyPassword($key,$pwd);
    }

    static function isPrivateKeyEncrypted($privateKey) {
        return VirgilKeyPair_isPrivateKeyEncrypted($privateKey);
    }

    static function resetPrivateKeyPassword($privateKey,$oldPassword,$newPassword) {
        return VirgilKeyPair_resetPrivateKeyPassword($privateKey,$oldPassword,$newPassword);
    }

    static function encryptPrivateKey($privateKey,$privateKeyPassword) {
        return VirgilKeyPair_encryptPrivateKey($privateKey,$privateKeyPassword);
    }

    static function decryptPrivateKey($privateKey,$privateKeyPassword) {
        return VirgilKeyPair_decryptPrivateKey($privateKey,$privateKeyPassword);
    }

    static function extractPublicKey($privateKey,$privateKeyPassword) {
        return VirgilKeyPair_extractPublicKey($privateKey,$privateKeyPassword);
    }

    static function publicKeyToPEM($publicKey) {
        return VirgilKeyPair_publicKeyToPEM($publicKey);
    }

    static function publicKeyToDER($publicKey) {
        return VirgilKeyPair_publicKeyToDER($publicKey);
    }

    static function privateKeyToPEM($privateKey,$privateKeyPassword=null) {
        switch (func_num_args()) {
            case 1: $r=VirgilKeyPair_privateKeyToPEM($privateKey); break;
            default: $r=VirgilKeyPair_privateKeyToPEM($privateKey,$privateKeyPassword);
        }
        return $r;
    }

    static function privateKeyToDER($privateKey,$privateKeyPassword=null) {
        switch (func_num_args()) {
            case 1: $r=VirgilKeyPair_privateKeyToDER($privateKey); break;
            default: $r=VirgilKeyPair_privateKeyToDER($privateKey,$privateKeyPassword);
        }
        return $r;
    }

    function publicKey() {
        return VirgilKeyPair_publicKey($this->_cPtr);
    }

    function privateKey() {
        return VirgilKeyPair_privateKey($this->_cPtr);
    }

    function __construct($publicKey_or_other,$privateKey=null) {
        if (is_resource($publicKey_or_other) && get_resource_type($publicKey_or_other) === '_p_virgil__crypto__VirgilKeyPair') {
            $this->_cPtr=$publicKey_or_other;
            return;
        }
        switch (func_num_args()) {
            case 1: $this->_cPtr=new_VirgilKeyPair($publicKey_or_other); break;
            default: $this->_cPtr=new_VirgilKeyPair($publicKey_or_other,$privateKey);
        }
    }
}