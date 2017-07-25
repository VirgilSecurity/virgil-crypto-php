<?php

namespace Virgil\Crypto;


class VirgilPFSResponderPublicInfo
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($identityPublicKey, $longTermPublicKey = null, $oneTimePublicKey = null)
    {
        if (is_resource($identityPublicKey) &&
            get_resource_type($identityPublicKey) === '_p_virgil__crypto__pfs__VirgilPFSResponderPublicInfo'
        ) {
            $this->_cPtr = $identityPublicKey;

            return;
        }
        switch (func_num_args()) {
            case 2:
                $this->_cPtr = new_VirgilPFSResponderPublicInfo($identityPublicKey, $longTermPublicKey);
                break;
            default:
                $this->_cPtr = new_VirgilPFSResponderPublicInfo(
                    $identityPublicKey,
                    $longTermPublicKey,
                    $oneTimePublicKey
                );
        }
    }


    function __set($var, $value)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_alter_newobject($this->_cPtr, $value);
        }
        $this->_pData[$var] = $value;
    }


    function __get($var)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        }

        return $this->_pData[$var];
    }


    function __isset($var)
    {
        if ($var === 'thisown') {
            return true;
        }

        return array_key_exists($var, $this->_pData);
    }


    function getIdentityPublicKey()
    {
        $r = VirgilPFSResponderPublicInfo_getIdentityPublicKey($this->_cPtr);
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilPFSPublicKey($r);
        }

        return $r;
    }


    function getLongTermPublicKey()
    {
        $r = VirgilPFSResponderPublicInfo_getLongTermPublicKey($this->_cPtr);
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilPFSPublicKey($r);
        }

        return $r;
    }


    function getOneTimePublicKey()
    {
        $r = VirgilPFSResponderPublicInfo_getOneTimePublicKey($this->_cPtr);
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilPFSPublicKey($r);
        }

        return $r;
    }
}
