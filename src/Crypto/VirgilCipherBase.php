<?php

namespace Virgil\Crypto;

class VirgilCipherBase {
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

    function __construct($res=null) {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__VirgilCipherBase') {
            $this->_cPtr=$res;
            return;
        }
        $this->_cPtr=new_VirgilCipherBase();
    }

    function addKeyRecipient($recipientId,$publicKey) {
        VirgilCipherBase_addKeyRecipient($this->_cPtr,$recipientId,$publicKey);
    }

    function removeKeyRecipient($recipientId) {
        VirgilCipherBase_removeKeyRecipient($this->_cPtr,$recipientId);
    }

    function addPasswordRecipient($pwd) {
        VirgilCipherBase_addPasswordRecipient($this->_cPtr,$pwd);
    }

    function removePasswordRecipient($pwd) {
        VirgilCipherBase_removePasswordRecipient($this->_cPtr,$pwd);
    }

    function removeAllRecipients() {
        VirgilCipherBase_removeAllRecipients($this->_cPtr);
    }

    function getContentInfo() {
        return VirgilCipherBase_getContentInfo($this->_cPtr);
    }

    function setContentInfo($contentInfo) {
        VirgilCipherBase_setContentInfo($this->_cPtr,$contentInfo);
    }

    static function defineContentInfoSize($data) {
        return VirgilCipherBase_defineContentInfoSize($data);
    }

    function customParams() {
        $r=VirgilCipherBase_customParams($this->_cPtr);
        if (!is_resource($r)) return $r;
        return new VirgilCustomParams($r);
    }
}