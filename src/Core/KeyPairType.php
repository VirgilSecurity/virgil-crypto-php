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

namespace Virgil\CryptoImpl\Core;

use MyCLabs\Enum\Enum;
use Virgil\CryptoImpl\Exceptions\VirgilCryptoException;
use VirgilCrypto\Foundation\AlgId;

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
     * @return null|int
     */
    public function getRsaBitLen(KeyPairType $keyPairType): ?int
    {
        switch ($keyPairType) {
            case $keyPairType::RSA2048():
                $res = 2048;
                break;
            case $keyPairType::RSA4096():
                $res = 4096;
                break;
            case $keyPairType::RSA8192():
                $res = 8192;
                break;
            default:
                $res =  null;
        }

        return $res;
    }

    /**
     * @param int $bitLen
     *
     * @return KeyPairType
     * @throws VirgilCryptoException
     */
    public static function getRsaKeyType(int $bitLen): KeyPairType
    {
        switch ($bitLen) {
            case 2048:
                $res = KeyPairType::RSA2048();
                break;
            case 4096:
                $res = KeyPairType::RSA4096();
                break;
            case 8192:
                $res =  KeyPairType::RSA8192();
                break;
            default:
                throw new VirgilCryptoException(VirgilCryptoError::UNSUPPORTED_RSA_LENGTH());
        }

        return $res;
    }

    /**
     * @param AlgId $algId
     *
     * @return KeyPairType
     * @throws VirgilCryptoException
     */
    public static function getFromAlgId(AlgId $algId): KeyPairType
    {
        switch ($algId) {
            case $algId::ED25519():
                $res = KeyPairType::ED25519();
                break;
            case $algId::CURVE25519():
                $res = KeyPairType::CURVE25519();
                break;
            case $algId::SECP256R1():
                $res = KeyPairType::SECP256R1();
                break;
            case $algId::RSA():
                throw new VirgilCryptoException(VirgilCryptoError::RSA_SHOULD_BE_CONSTRUCTED_DIRECTLY());
            default:
                throw new VirgilCryptoException(VirgilCryptoError::UNKNOWN_ALG_ID());
        }

        return $res;
    }

    /**
     * @param KeyPairType $keyPairType
     *
     * @return AlgId
     * @throws VirgilCryptoException
     */
    public function getAlgId(KeyPairType $keyPairType): AlgId
    {
        switch ($keyPairType) {
            case $keyPairType::ED25519():
                $res = AlgId::ED25519();
                break;
            case $keyPairType::CURVE25519():
                $res = AlgId::CURVE25519();
                break;
            case $keyPairType::SECP256R1():
                $res = AlgId::SECP256R1();
                break;
            case $keyPairType::RSA2048():
                $res = AlgId::RSA();
                break;
            case $keyPairType::RSA4096():
                $res = AlgId::RSA();
                break;
            case $keyPairType::RSA8192():
                $res = AlgId::RSA();
                break;
            default:
                throw new VirgilCryptoException(VirgilCryptoError::UNKNOWN_ALG_ID());
        }

        return $res;
    }

}
