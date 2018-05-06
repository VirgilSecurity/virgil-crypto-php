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


class VirgilHash extends VirgilAsn1Compatible
{
    const Algorithm_MD5 = 0;
    const Algorithm_SHA1 = VirgilHash_Algorithm_SHA1;
    const Algorithm_SHA224 = VirgilHash_Algorithm_SHA224;
    const Algorithm_SHA256 = VirgilHash_Algorithm_SHA256;
    const Algorithm_SHA384 = VirgilHash_Algorithm_SHA384;
    const Algorithm_SHA512 = VirgilHash_Algorithm_SHA512;
    public $_cPtr = null;


    function __construct($alg_or_name_or_rhs = null)
    {
        if (is_resource($alg_or_name_or_rhs) &&
            get_resource_type($alg_or_name_or_rhs) === '_p_virgil__crypto__foundation__VirgilHash'
        ) {
            $this->_cPtr = $alg_or_name_or_rhs;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilHash();
                break;
            default:
                $this->_cPtr = new_VirgilHash($alg_or_name_or_rhs);
        }
    }


    function __set($var, $value)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_alter_newobject($this->_cPtr, $value);
        }
        VirgilAsn1Compatible::__set($var, $value);
    }


    function __get($var)
    {
        if ($var === 'thisown') {
            return swig_virgil_crypto_php_get_newobject($this->_cPtr);
        }

        return VirgilAsn1Compatible::__get($var);
    }


    function __isset($var)
    {
        if ($var === 'thisown') {
            return true;
        }

        return VirgilAsn1Compatible::__isset($var);
    }


    function name()
    {
        return VirgilHash_name($this->_cPtr);
    }


    function algorithm()
    {
        return VirgilHash_algorithm($this->_cPtr);
    }


    function type()
    {
        return VirgilHash_type($this->_cPtr);
    }


    function size()
    {
        return VirgilHash_size($this->_cPtr);
    }


    function hash($data)
    {
        return VirgilHash_hash($this->_cPtr, $data);
    }


    function start()
    {
        VirgilHash_start($this->_cPtr);
    }


    function update($data)
    {
        VirgilHash_update($this->_cPtr, $data);
    }


    function finish()
    {
        return VirgilHash_finish($this->_cPtr);
    }


    function hmac($key, $data)
    {
        return VirgilHash_hmac($this->_cPtr, $key, $data);
    }


    function hmacStart($key)
    {
        VirgilHash_hmacStart($this->_cPtr, $key);
    }


    function hmacReset()
    {
        VirgilHash_hmacReset($this->_cPtr);
    }


    function hmacUpdate($data)
    {
        VirgilHash_hmacUpdate($this->_cPtr, $data);
    }


    function hmacFinish()
    {
        return VirgilHash_hmacFinish($this->_cPtr);
    }
}
