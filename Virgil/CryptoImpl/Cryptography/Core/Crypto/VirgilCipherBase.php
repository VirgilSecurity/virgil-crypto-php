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


class VirgilCipherBase
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($res = null)
    {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__VirgilCipherBase') {
            $this->_cPtr = $res;

            return;
        }
        $this->_cPtr = new_VirgilCipherBase();
    }


    static function defineContentInfoSize($data)
    {
        return VirgilCipherBase_defineContentInfoSize($data);
    }


    static function computeShared($publicKey, $privateKey, $privateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 2:
                $r = VirgilCipherBase_computeShared($publicKey, $privateKey);
                break;
            default:
                $r = VirgilCipherBase_computeShared($publicKey, $privateKey, $privateKeyPassword);
        }

        return $r;
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


    function addKeyRecipient($recipientId, $publicKey)
    {
        VirgilCipherBase_addKeyRecipient($this->_cPtr, $recipientId, $publicKey);
    }


    function removeKeyRecipient($recipientId)
    {
        VirgilCipherBase_removeKeyRecipient($this->_cPtr, $recipientId);
    }


    function keyRecipientExists($recipientId)
    {
        return VirgilCipherBase_keyRecipientExists($this->_cPtr, $recipientId);
    }


    function addPasswordRecipient($pwd)
    {
        VirgilCipherBase_addPasswordRecipient($this->_cPtr, $pwd);
    }


    function removePasswordRecipient($pwd)
    {
        VirgilCipherBase_removePasswordRecipient($this->_cPtr, $pwd);
    }


    function passwordRecipientExists($password)
    {
        return VirgilCipherBase_passwordRecipientExists($this->_cPtr, $password);
    }


    function removeAllRecipients()
    {
        VirgilCipherBase_removeAllRecipients($this->_cPtr);
    }


    function getContentInfo()
    {
        return VirgilCipherBase_getContentInfo($this->_cPtr);
    }


    function setContentInfo($contentInfo)
    {
        VirgilCipherBase_setContentInfo($this->_cPtr, $contentInfo);
    }


    function customParams()
    {
        $r = VirgilCipherBase_customParams($this->_cPtr);
        if (!is_resource($r)) {
            return $r;
        }

        return new VirgilCustomParams($r);
    }
}
