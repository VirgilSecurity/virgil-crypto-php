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

namespace Virgil\CryptoImpl;

use Virgil\CryptoImpl\Exceptions\UnknownTypeException;
use VirgilCrypto\Foundation\AlgId;

/**
 * Class keeps list of key pair types constants.
 */
class VirgilKeyPairType
{
    /**
     * @var VirgilKeyType
     */
    private $CURVE25519;

    /**
     * @var VirgilKeyType
     */
    private $ED25519;

    /**
     * @var VirgilKeyType
     */
    private $SECP256R1;

    /**
     * @var VirgilKeyType
     */
    private $RSA_2048;

    /**
     * @var VirgilKeyType
     */
    private $RSA_4096;

    /**
     * @var VirgilKeyType
     */
    private $RSA_8192;

    /**
     * KeyPairType constructor.
     */
    public function __construct()
    {
        $this->CURVE25519 = new VirgilKeyType(AlgId::CURVE25519());
        $this->ED25519 = new VirgilKeyType(AlgId::ED25519());
        $this->SECP256R1 = new VirgilKeyType(AlgId::SECP256R1());
        $this->RSA_2048 = new VirgilKeyType(AlgId::RSA(), 2048);
        $this->RSA_4096 = new VirgilKeyType(AlgId::RSA(), 4096);
        $this->RSA_8192 = new VirgilKeyType(AlgId::RSA(), 8192);
    }

    /**
     * @param $name
     * @throws UnknownTypeException
     */
    public function __get($name)
    {
        throw new UnknownTypeException("KeyPairType not found: $name");
    }

    /**
     * @return VirgilKeyType
     */
    public function getCURVE25519()
    {
        return $this->CURVE25519;
    }

    /**
     * @return VirgilKeyType
     */
    public function getED25519()
    {
        return $this->ED25519;
    }

    /**
     * @return VirgilKeyType
     */
    public function getSECP256R1()
    {
        return $this->SECP256R1;
    }

}
