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


class VirgilTinyCipher
{
    const PackageSize_Min = 113;
    const PackageSize_Short_SMS = 120;
    const PackageSize_Long_SMS = 1200;
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($packageSize = null)
    {
        if (is_resource($packageSize) && get_resource_type($packageSize) === '_p_virgil__crypto__VirgilTinyCipher') {
            $this->_cPtr = $packageSize;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilTinyCipher();
                break;
            default:
                $this->_cPtr = new_VirgilTinyCipher($packageSize);
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


    function reset()
    {
        VirgilTinyCipher_reset($this->_cPtr);
    }


    function encrypt($data, $recipientPublicKey)
    {
        VirgilTinyCipher_encrypt($this->_cPtr, $data, $recipientPublicKey);
    }


    function encryptAndSign($data, $recipientPublicKey, $senderPrivateKey, $senderPrivateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 3:
                VirgilTinyCipher_encryptAndSign($this->_cPtr, $data, $recipientPublicKey, $senderPrivateKey);
                break;
            default:
                VirgilTinyCipher_encryptAndSign(
                    $this->_cPtr,
                    $data,
                    $recipientPublicKey,
                    $senderPrivateKey,
                    $senderPrivateKeyPassword
                );
        }
    }


    function getPackageCount()
    {
        return VirgilTinyCipher_getPackageCount($this->_cPtr);
    }


    function getPackage($index)
    {
        return VirgilTinyCipher_getPackage($this->_cPtr, $index);
    }


    function addPackage($package)
    {
        VirgilTinyCipher_addPackage($this->_cPtr, $package);
    }


    function isPackagesAccumulated()
    {
        return VirgilTinyCipher_isPackagesAccumulated($this->_cPtr);
    }


    function decrypt($recipientPrivateKey, $recipientPrivateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 1:
                $r = VirgilTinyCipher_decrypt($this->_cPtr, $recipientPrivateKey);
                break;
            default:
                $r = VirgilTinyCipher_decrypt($this->_cPtr, $recipientPrivateKey, $recipientPrivateKeyPassword);
        }

        return $r;
    }


    function verifyAndDecrypt($senderPublicKey, $recipientPrivateKey, $recipientPrivateKeyPassword = null)
    {
        switch (func_num_args()) {
            case 2:
                $r = VirgilTinyCipher_verifyAndDecrypt($this->_cPtr, $senderPublicKey, $recipientPrivateKey);
                break;
            default:
                $r = VirgilTinyCipher_verifyAndDecrypt(
                    $this->_cPtr,
                    $senderPublicKey,
                    $recipientPrivateKey,
                    $recipientPrivateKeyPassword
                );
        }

        return $r;
    }
}
