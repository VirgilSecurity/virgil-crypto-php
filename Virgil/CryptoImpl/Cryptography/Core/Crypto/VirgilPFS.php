<?php
/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

namespace Virgil\CryptoImpl\Cryptography\Core\Crypto;


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
