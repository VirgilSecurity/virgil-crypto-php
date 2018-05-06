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


class VirgilPBKDF extends VirgilAsn1Compatible
{
    const kIterationCount_Default = VirgilPBKDF_kIterationCount_Default;
    const Algorithm_PBKDF2 = 0;
    public $_cPtr = null;


    function __construct($salt = null, $iterationCount = null)
    {
        if (is_resource($salt) && get_resource_type($salt) === '_p_virgil__crypto__foundation__VirgilPBKDF') {
            $this->_cPtr = $salt;

            return;
        }
        switch (func_num_args()) {
            case 0:
                $this->_cPtr = new_VirgilPBKDF();
                break;
            case 1:
                $this->_cPtr = new_VirgilPBKDF($salt);
                break;
            default:
                $this->_cPtr = new_VirgilPBKDF($salt, $iterationCount);
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


    function getSalt()
    {
        return VirgilPBKDF_getSalt($this->_cPtr);
    }


    function getIterationCount()
    {
        return VirgilPBKDF_getIterationCount($this->_cPtr);
    }


    function setAlgorithm($alg)
    {
        VirgilPBKDF_setAlgorithm($this->_cPtr, $alg);
    }


    function getAlgorithm()
    {
        return VirgilPBKDF_getAlgorithm($this->_cPtr);
    }


    function setHashAlgorithm($hash)
    {
        VirgilPBKDF_setHashAlgorithm($this->_cPtr, $hash);
    }


    function getHashAlgorithm()
    {
        return VirgilPBKDF_getHashAlgorithm($this->_cPtr);
    }


    function enableRecommendationsCheck()
    {
        VirgilPBKDF_enableRecommendationsCheck($this->_cPtr);
    }


    function disableRecommendationsCheck()
    {
        VirgilPBKDF_disableRecommendationsCheck($this->_cPtr);
    }


    function derive($pwd, $outSize = null)
    {
        switch (func_num_args()) {
            case 1:
                $r = VirgilPBKDF_derive($this->_cPtr, $pwd);
                break;
            default:
                $r = VirgilPBKDF_derive($this->_cPtr, $pwd, $outSize);
        }

        return $r;
    }
}
