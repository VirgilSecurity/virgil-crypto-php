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

use MyCLabs\Enum\Enum;
use Virgil\CryptoImpl\Exceptions\VirgilCryptoException;

/**
 * Class keeps list of key pair types constants.
 */
class KeyPairType extends Enum
{
    private const ED25519 = "ED25519";
    private const CURVE25519 = "CURVE25519";
    private const SECP256R1 = "SECP256R1";
    private const RSA2048 = "RSA2048";
    private const RSA4096 = "RSA4096";
    private const RSA8192 = "RSA8192";

    /**
     * @param KeyPairType $keyPairType
     *
     * @return int
     */
    public function getRsaBitLen(KeyPairType $keyPairType): int
    {
        switch ($keyPairType)
        {
            case $keyPairType::RSA2048():
                return 2048;
                break;
            case $keyPairType::RSA4096():
                return 4096;
                break;
            case $keyPairType::RSA8192():
                return 8192;
                break;
            default:
                return null;
        }
    }

    public function getRsaKeyType(int $bitLen): KeyPairType
    {
        switch ($bitLen)
        {
            case 2048:
                return KeyPairType::RSA2048();
                break;
            case 4096:
                return KeyPairType::RSA4096();
                break;
            case 8192:
                return KeyPairType::RSA8192();
                break;
            default:
                throw new VirgilCryptoException();
        }
    }

}
