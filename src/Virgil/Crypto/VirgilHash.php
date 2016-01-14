<?php

namespace Virgil\Crypto;

class VirgilHash extends VirgilAsn1Compatible {
    public $_cPtr=null;

    function __set($var,$value) {
        if ($var === 'thisown') return swig_virgil_crypto_php_alter_newobject($this->_cPtr,$value);
        VirgilAsn1Compatible::__set($var,$value);
    }

    function __get($var) {
        if ($var === 'thisown') return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        return VirgilAsn1Compatible::__get($var);
    }

    function __isset($var) {
        if ($var === 'thisown') return true;
        return VirgilAsn1Compatible::__isset($var);
    }

    static function md5() {
        $r=VirgilHash_md5();
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilHash($r);
        }
        return $r;
    }

    static function sha256() {
        $r=VirgilHash_sha256();
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilHash($r);
        }
        return $r;
    }

    static function sha384() {
        $r=VirgilHash_sha384();
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilHash($r);
        }
        return $r;
    }

    static function sha512() {
        $r=VirgilHash_sha512();
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilHash($r);
        }
        return $r;
    }

    static function withName($name) {
        $r=VirgilHash_withName($name);
        if (is_resource($r)) {
            $c=substr(get_resource_type($r), (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3));
            if (class_exists($c)) return new $c($r);
            return new VirgilHash($r);
        }
        return $r;
    }

    function name() {
        return VirgilHash_name($this->_cPtr);
    }

    function hash($bytes) {
        return VirgilHash_hash($this->_cPtr,$bytes);
    }

    function start() {
        VirgilHash_start($this->_cPtr);
    }

    function update($bytes) {
        VirgilHash_update($this->_cPtr,$bytes);
    }

    function finish() {
        return VirgilHash_finish($this->_cPtr);
    }

    function hmac($key,$bytes) {
        return VirgilHash_hmac($this->_cPtr,$key,$bytes);
    }

    function hmacStart($key) {
        VirgilHash_hmacStart($this->_cPtr,$key);
    }

    function hmacReset() {
        VirgilHash_hmacReset($this->_cPtr);
    }

    function hmacUpdate($bytes) {
        VirgilHash_hmacUpdate($this->_cPtr,$bytes);
    }

    function hmacFinish() {
        return VirgilHash_hmacFinish($this->_cPtr);
    }

    function __construct($other=null) {
        if (is_resource($other) && get_resource_type($other) === '_p_virgil__crypto__foundation__VirgilHash') {
            $this->_cPtr=$other;
            return;
        }
        switch (func_num_args()) {
            case 0: $this->_cPtr=new_VirgilHash(); break;
            default: $this->_cPtr=new_VirgilHash($other);
        }
    }
}