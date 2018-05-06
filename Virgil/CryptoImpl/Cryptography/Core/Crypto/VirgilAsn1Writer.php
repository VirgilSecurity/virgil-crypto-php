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


class VirgilAsn1Writer
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($capacity = null)
    {
        if (is_resource($capacity) &&
            get_resource_type($capacity) === '_p_virgil__crypto__foundation__asn1__VirgilAsn1Writer'
        ) {
            $this->_cPtr = $capacity;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilAsn1Writer();
                break;
            default:
                $this->_cPtr = new_VirgilAsn1Writer($capacity);
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


    function reset($capacity = null)
    {
        switch (func_num_args()) {
            case 0:
                VirgilAsn1Writer_reset($this->_cPtr);
                break;
            default:
                VirgilAsn1Writer_reset($this->_cPtr, $capacity);
        }
    }


    function finish()
    {
        return VirgilAsn1Writer_finish($this->_cPtr);
    }


    function writeInteger($value)
    {
        return VirgilAsn1Writer_writeInteger($this->_cPtr, $value);
    }


    function writeBool($value)
    {
        return VirgilAsn1Writer_writeBool($this->_cPtr, $value);
    }


    function writeNull()
    {
        return VirgilAsn1Writer_writeNull($this->_cPtr);
    }


    function writeOctetString($data)
    {
        return VirgilAsn1Writer_writeOctetString($this->_cPtr, $data);
    }


    function writeUTF8String($data)
    {
        return VirgilAsn1Writer_writeUTF8String($this->_cPtr, $data);
    }


    function writeContextTag($tag, $len)
    {
        return VirgilAsn1Writer_writeContextTag($this->_cPtr, $tag, $len);
    }


    function writeData($data)
    {
        return VirgilAsn1Writer_writeData($this->_cPtr, $data);
    }


    function writeOID($oid)
    {
        return VirgilAsn1Writer_writeOID($this->_cPtr, $oid);
    }


    function writeSequence($len)
    {
        return VirgilAsn1Writer_writeSequence($this->_cPtr, $len);
    }


    function writeSet($set)
    {
        return VirgilAsn1Writer_writeSet($this->_cPtr, $set);
    }
}
