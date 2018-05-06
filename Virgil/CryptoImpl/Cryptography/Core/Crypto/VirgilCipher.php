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


class VirgilCipher extends VirgilCipherBase
{
    public $_cPtr = null;


    function __construct($res = null)
    {
        if (is_resource($res) && get_resource_type($res) === '_p_virgil__crypto__VirgilCipher') {
            $this->_cPtr = $res;

            return;
        }
        $this->_cPtr = new_VirgilCipher();
    }


    function __set($var, $value)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_alter_newobject($this->_cPtr, $value);
        }
        VirgilCipherBase::__set($var, $value);
    }


    function __get($var)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        }

        return VirgilCipherBase::__get($var);
    }


    function __isset($var)
    {
        if ($var === 'thisown') {
            return true;
        }

        return VirgilCipherBase::__isset($var);
    }


    function encrypt($data, $embedContentInfo = true)
    {
        return VirgilCipher_encrypt($this->_cPtr, $data, $embedContentInfo);
    }


    function decryptWithKey($encryptedData, $recipientId, $privateKey, $privateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 3:
                $r = VirgilCipher_decryptWithKey($this->_cPtr, $encryptedData, $recipientId, $privateKey);
                break;
            default:
                $r = VirgilCipher_decryptWithKey(
                    $this->_cPtr,
                    $encryptedData,
                    $recipientId,
                    $privateKey,
                    $privateKeyPassword
                );
        }

        return $r;
    }


    function decryptWithPassword($encryptedData, $pwd)
    {
        return VirgilCipher_decryptWithPassword($this->_cPtr, $encryptedData, $pwd);
    }
}
