<?php
/**
 * Copyright (C) 2015-2019 Virgil Security Inc.
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

namespace Virgil\Tests;

use PHPUnit\Framework\TestCase;
use Virgil\CryptoImpl\Core\KeyPairType;
use Virgil\CryptoImpl\VirgilCrypto;

/**
 * Class CryptoTests
 *
 * @package Virgil\Tests
 */
class CryptoTests extends TestCase
{
    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
     */
    private function checkKeyGeneration(VirgilCrypto $crypto, KeyPairType $keyPairType)
    {
        $keyPair = $crypto->generateKeyPair($keyPairType);

        $a1 = $keyPair->getPrivateKey()->getIdentifier();
        $a2 = $keyPair->getPublicKey()->getIdentifier();

        self::assertEquals($a1, $a2);
    }

    /**
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
     */
    public function test01KeyGenerationGenerateOneKeyShouldSucceed()
    {
        $crypto = new VirgilCrypto();

        $keyTypes = [KeyPairType::CURVE25519(), KeyPairType::ED25519(), KeyPairType::SECP256R1(),
            KeyPairType::RSA2048()];

        foreach ($keyTypes as $keyType) {
            $this->checkKeyGeneration($crypto, $keyType);
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
     */
    private function checkKeyImport(VirgilCrypto $crypto, KeyPairType $keyPairType)
    {
        $keyPair = $crypto->generateKeyPair($keyPairType);
        $data1 = $crypto->exportPrivateKey($keyPair->getPrivateKey());
        $privateKey = $crypto->importPrivateKey($data1);

        $a1 = $keyPair->getPrivateKey()->getIdentifier();
        $a2 = $privateKey->getIdentifier();

        self::assertEquals($a1, $a2);

        $data2 = $crypto->exportPublicKey($keyPair->getPublicKey());
        $publicKey = $crypto->importPublicKey($data2);

        $b1 = $keyPair->getPublicKey()->getIdentifier();
        $b2 = $publicKey->getIdentifier();

        self::assertEquals($b1, $b2);
    }

    /**
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
     */
    public function test02KeyImportAllKeysShouldMatch()
    {
        $crypto = new VirgilCrypto();

        $keyTypes = [KeyPairType::CURVE25519(), KeyPairType::ED25519(), KeyPairType::SECP256R1(),
            KeyPairType::RSA2048()];

        foreach ($keyTypes as $keyType) {
            $this->checkKeyImport($crypto, $keyType);
        }
    }
}