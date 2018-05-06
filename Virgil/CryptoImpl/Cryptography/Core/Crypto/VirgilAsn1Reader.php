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


class VirgilAsn1Reader
{
    public $_cPtr = null;
    protected $_pData = [];


    function __construct($data = null)
    {
        if (is_resource($data) &&
            get_resource_type($data) === '_p_virgil__crypto__foundation__asn1__VirgilAsn1Reader'
        ) {
            $this->_cPtr = $data;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilAsn1Reader();
                break;
            default:
                $this->_cPtr = new_VirgilAsn1Reader($data);
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


    function reset($data)
    {
        VirgilAsn1Reader_reset($this->_cPtr, $data);
    }


    function readInteger()
    {
        return VirgilAsn1Reader_readInteger($this->_cPtr);
    }


    function readBool()
    {
        return VirgilAsn1Reader_readBool($this->_cPtr);
    }


    function readNull()
    {
        VirgilAsn1Reader_readNull($this->_cPtr);
    }


    function readOctetString()
    {
        return VirgilAsn1Reader_readOctetString($this->_cPtr);
    }


    function readUTF8String()
    {
        return VirgilAsn1Reader_readUTF8String($this->_cPtr);
    }


    function readData()
    {
        return VirgilAsn1Reader_readData($this->_cPtr);
    }


    function readContextTag($tag)
    {
        return VirgilAsn1Reader_readContextTag($this->_cPtr, $tag);
    }


    function readOID()
    {
        return VirgilAsn1Reader_readOID($this->_cPtr);
    }


    function readSequence()
    {
        return VirgilAsn1Reader_readSequence($this->_cPtr);
    }


    function readSet()
    {
        return VirgilAsn1Reader_readSet($this->_cPtr);
    }
}
