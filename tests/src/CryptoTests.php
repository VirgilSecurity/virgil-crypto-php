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

use Exception;
use PHPUnit\Framework\TestCase;
use Virgil\CryptoImpl\Core\KeyPairType;
use Virgil\CryptoImpl\Exceptions\VirgilCryptoException;
use Virgil\CryptoImpl\Services\InputOutputService;
use Virgil\CryptoImpl\VirgilCrypto;
use VirgilCrypto\Foundation\CtrDrbg;

/**
 * Class CryptoTests
 *
 * @package Virgil\Tests
 */
class CryptoTests extends TestCase
{
    private function getIOService(): InputOutputService
    {
        return new InputOutputService();
    }

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

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
     */
    private function checkEncryption(VirgilCrypto $crypto, KeyPairType $keyPairType)
    {
        $keyPair1 = $crypto->generateKeyPair($keyPairType);
        $keyPair2 = $crypto->generateKeyPair($keyPairType);

        $rawData = "test1";
        $data = $this->getIOService()->convertStringToData($rawData);

        $encryptedData = $crypto->encrypt($data, [$keyPair1->getPublicKey()]);
        $encryptedData = $this->getIOService()->convertStringToData($encryptedData);

        $decryptedData = $crypto->decrypt($encryptedData, $keyPair1->getPrivateKey());

        self::assertEquals($rawData, $decryptedData);

        try {
            $crypto->decrypt($encryptedData, $keyPair2->getPrivateKey());
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }
    }

    /**
     *
     */
    public function test03EncryptionSomeDataShouldMatch()
    {
        $crypto = new VirgilCrypto();

        $keyTypes = [KeyPairType::CURVE25519(), KeyPairType::ED25519(), KeyPairType::SECP256R1(),
            KeyPairType::RSA2048()];

        foreach ($keyTypes as $keyType) {
            $this->checkEncryption($crypto, $keyType);
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkSignature(VirgilCrypto $crypto, KeyPairType $keyPairType)
    {
        $keyPair1 = $crypto->generateKeyPair($keyPairType);
        $keyPair2 = $crypto->generateKeyPair($keyPairType);

        $rawData = "test2";

        $signature = $crypto->generateSignature($rawData, $keyPair1->getPrivateKey());

        $res1 = $crypto->verifySignature($signature, $rawData, $keyPair1->getPublicKey());
        self::assertTrue($res1);

        try {
            $crypto->verifySignature($signature, $rawData, $keyPair2->getPublicKey());
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }
    }

    /**
     * @throws VirgilCryptoException
     */
    public function test04SignatureSomeDataShouldVerify()
    {
        $crypto = new VirgilCrypto();

        $keyTypes = [KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

        foreach ($keyTypes as $keyType) {
            $this->checkSignature($crypto, $keyType);
        }
    }
}