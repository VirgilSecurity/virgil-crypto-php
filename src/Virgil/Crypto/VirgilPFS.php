<?php

namespace Virgil\Crypto;


class VirgilPFS
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($res = null)
    {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__pfs__VirgilPFS') {
            $this->_cPtr = $res;

            return;
        }
        $this->_cPtr = new_VirgilPFS();
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


    function startInitiatorSession($initiatorPrivateInfo, $responderPublicInfo, $additionalData = null)
    {
        switch (func_num_args()) {
            case 2:
                $r = VirgilPFS_startInitiatorSession($this->_cPtr, $initiatorPrivateInfo, $responderPublicInfo);
                break;
            default:
                $r = VirgilPFS_startInitiatorSession(
                    $this->_cPtr,
                    $initiatorPrivateInfo,
                    $responderPublicInfo,
                    $additionalData
                );
        }
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilPFSSession($r);
        }

        return $r;
    }


    function startResponderSession($responderPrivateInfo, $initiatorPublicInfo, $additionalData = null)
    {
        switch (func_num_args()) {
            case 2:
                $r = VirgilPFS_startResponderSession($this->_cPtr, $responderPrivateInfo, $initiatorPublicInfo);
                break;
            default:
                $r = VirgilPFS_startResponderSession(
                    $this->_cPtr,
                    $responderPrivateInfo,
                    $initiatorPublicInfo,
                    $additionalData
                );
        }
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilPFSSession($r);
        }

        return $r;
    }


    function encrypt($data)
    {
        $r = VirgilPFS_encrypt($this->_cPtr, $data);
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilPFSEncryptedMessage($r);
        }

        return $r;
    }


    function decrypt($encryptedMessage)
    {
        return VirgilPFS_decrypt($this->_cPtr, $encryptedMessage);
    }


    function getSession()
    {
        $r = VirgilPFS_getSession($this->_cPtr);
        if (is_resource($r)) {
            $c = substr(
                get_resource_type($r),
                (strpos(get_resource_type($r), '__') ? strpos(get_resource_type($r), '__') + 2 : 3)
            );
            if (class_exists($c)) {
                return new $c($r);
            }

            return new VirgilPFSSession($r);
        }

        return $r;
    }


    function setSession($session)
    {
        VirgilPFS_setSession($this->_cPtr, $session);
    }
}
