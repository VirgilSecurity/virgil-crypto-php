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


use Virgil\CryptoApi\AccessTokenSigner;
use Virgil\CryptoApi\PrivateKey;
use Virgil\CryptoApi\PublicKey;

/**
 * Class VirgilAccessTokenSigner
 * @package Virgil\CryptoImpl
 */
class VirgilAccessTokenSigner implements AccessTokenSigner
{
    /**
     * @var VirgilCrypto
     */
    protected $virgilCrypto;


    /**
     * VirgilAccessTokenSigner constructor.
     */
    public function __construct()
    {
        $this->virgilCrypto = new VirgilCrypto();
    }


    /**
     * @param string     $data
     * @param PrivateKey $privateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateTokenSignature($data, PrivateKey $privateKey)
    {
        if (!$privateKey instanceof VirgilPrivateKey) {
            throw new VirgilCryptoException("instance of VirgilPrivateKey expected");
        }

        return $this->virgilCrypto->generateSignature($data, $privateKey);
    }


    /**
     * @param string    $signature
     *
     * @param string    $data
     * @param PublicKey $publicKey
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    public function verifyTokenSignature($signature, $data, PublicKey $publicKey)
    {
        if (!$publicKey instanceof VirgilPublicKey) {
            throw new VirgilCryptoException("instance of VirgilPublicKey expected");
        }

        return $this->virgilCrypto->verifySignature($data, $signature, $publicKey);
    }


    /**
     * @return string
     */
    public function getAlgorithm()
    {
        return "VEDS512";
    }
}
