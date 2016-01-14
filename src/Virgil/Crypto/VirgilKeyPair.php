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

    const Type_Default = 0;

    const Type_RSA_256 = VirgilKeyPair_Type_RSA_256;

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

    const Type_EC_M221 = VirgilKeyPair_Type_EC_M221;

    const Type_EC_M255 = VirgilKeyPair_Type_EC_M255;

    const Type_EC_M383 = VirgilKeyPair_Type_EC_M383;

    const Type_EC_M511 = VirgilKeyPair_Type_EC_M511;

    const Type_EC_SECP192K1 = VirgilKeyPair_Type_EC_SECP192K1;

    const Type_EC_SECP224K1 = VirgilKeyPair_Type_EC_SECP224K1;

    const Type_EC_SECP256K1 = VirgilKeyPair_Type_EC_SECP256K1;

    static function generate($type=null,$pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_generate(); break;
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

    static function ecNist192($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_ecNist192(); break;
            default: $r=VirgilKeyPair_ecNist192($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function ecNist224($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_ecNist224(); break;
            default: $r=VirgilKeyPair_ecNist224($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function ecNist256($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_ecNist256(); break;
            default: $r=VirgilKeyPair_ecNist256($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function ecNist384($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_ecNist384(); break;
            default: $r=VirgilKeyPair_ecNist384($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function ecNist521($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_ecNist521(); break;
            default: $r=VirgilKeyPair_ecNist521($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function ecBrainpool256($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_ecBrainpool256(); break;
            default: $r=VirgilKeyPair_ecBrainpool256($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function ecBrainpool384($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_ecBrainpool384(); break;
            default: $r=VirgilKeyPair_ecBrainpool384($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function ecBrainpool512($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_ecBrainpool512(); break;
            default: $r=VirgilKeyPair_ecBrainpool512($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function ecKoblitz192($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_ecKoblitz192(); break;
            default: $r=VirgilKeyPair_ecKoblitz192($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function ecKoblitz224($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_ecKoblitz224(); break;
            default: $r=VirgilKeyPair_ecKoblitz224($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function ecKoblitz256($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_ecKoblitz256(); break;
            default: $r=VirgilKeyPair_ecKoblitz256($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function rsa256($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_rsa256(); break;
            default: $r=VirgilKeyPair_rsa256($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function rsa512($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_rsa512(); break;
            default: $r=VirgilKeyPair_rsa512($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function rsa1024($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_rsa1024(); break;
            default: $r=VirgilKeyPair_rsa1024($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function rsa2048($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_rsa2048(); break;
            default: $r=VirgilKeyPair_rsa2048($pwd);
        }
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilKeyPair($r);
        }
        return $r;
    }

    static function rsa4096($pwd=null) {
        switch (func_num_args()) {
            case 0: $r=VirgilKeyPair_rsa4096(); break;
            default: $r=VirgilKeyPair_rsa4096($pwd);
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