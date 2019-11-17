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
use Virgil\CryptoImpl\Core\Data;
use Virgil\CryptoImpl\Core\KeyPairType;
use Virgil\CryptoImpl\Core\OutputStream;
use Virgil\CryptoImpl\Core\PublicKeyList;
use Virgil\CryptoImpl\Core\Stream;
use Virgil\CryptoImpl\Core\InputStream;
use Virgil\CryptoImpl\Exceptions\VirgilCryptoException;
use Virgil\CryptoImpl\Exceptions\VirgilCryptoServiceException;
use Virgil\CryptoImpl\Services\InputOutputService;
use Virgil\CryptoImpl\VirgilCrypto;

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

        $pkl = new PublicKeyList($keyPair1->getPublicKey());

        $encryptedData = $crypto->encrypt($data, $pkl);
        $encryptedData = $this->getIOService()->convertStringToData($encryptedData);

        $decryptedData = $crypto->decrypt($encryptedData, $keyPair1->getPrivateKey());

        self::assertEquals($rawData, $decryptedData);

        try {
            $tempRes = $crypto->decrypt($encryptedData, $keyPair2->getPrivateKey());
            self::assertTrue(empty($tempRes));
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
            $res2 = $crypto->verifySignature($signature, $rawData, $keyPair2->getPublicKey());
            self::assertTrue(empty($res2));
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

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkSignAndEncrypt(VirgilCrypto $crypto, KeyPairType $keyPairType)
    {
        $rawData = "test3";
        $data = $this->getIOService()->convertStringToData($rawData);

        $keyPair1 = $crypto->generateKeyPair($keyPairType);
        $keyPair2 = $crypto->generateKeyPair($keyPairType);
        $keyPair3 = $crypto->generateKeyPair($keyPairType);

        $pkl = new PublicKeyList($keyPair1->getPublicKey(), $keyPair2->getPublicKey());

        $encrypted = $crypto->signAndEncrypt($data, $keyPair1->getPrivateKey(), $pkl);

        $encrypted = $this->getIOService()->convertStringToData($encrypted);

        $pkl1 = new PublicKeyList($keyPair1->getPublicKey(), $keyPair2->getPublicKey());
        $pkl2 = new PublicKeyList($keyPair3->getPublicKey());

        $decrypted = $crypto->decryptAndVerify($encrypted, $keyPair2->getPrivateKey(), $pkl1);

        self::assertEquals($rawData, $decrypted);

        try {
            $res1 = $crypto->decryptAndVerify($encrypted, $keyPair3->getPrivateKey(), $pkl1);
            self::assertTrue(empty($res1));
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }

        try {
            $res2 = $crypto->decryptAndVerify($encrypted, $keyPair2->getPrivateKey(), $pkl2);
            self::assertTrue(empty($res2));
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }
    }

    /**
     * @throws VirgilCryptoException
     */
    public function test05SignAndEncryptSomeDataShouldDecryptAndVerify()
    {
        $crypto = new VirgilCrypto();

        $keyTypes = [KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

        foreach ($keyTypes as $keyType) {
            $this->checkSignAndEncrypt($crypto, $keyType);
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkStreamSign(VirgilCrypto $crypto, KeyPairType $keyPairType)
    {
        try {
            $keyPair1 = $crypto->generateKeyPair($keyPairType);
            $keyPair2 = $crypto->generateKeyPair($keyPairType);

            $testFileUrl = __DIR__."/../data/testData.txt";
            $inputStream = new InputStream($testFileUrl);

            $signature = $crypto->generateStreamSignature($inputStream, $keyPair1->getPrivateKey());

            $verifyStream1 = new InputStream($testFileUrl);
            $verifyStream2 = new InputStream($testFileUrl);

            $res1 = $crypto->verifyStreamSignature($signature, $verifyStream1, $keyPair1->getPublicKey());
            self::assertTrue($res1);

            try {
                $res2 = $crypto->verifyStreamSignature($signature, $verifyStream2, $keyPair2->getPublicKey());
                self::assertTrue(empty($res2));
            } catch (Exception $e) {
                self::assertTrue($e instanceof VirgilCryptoException);
            }

        }
        catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    public function test06SignStreamFileShouldVerify()
    {
        $crypto = new VirgilCrypto();

        $keyTypes = [KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

        foreach ($keyTypes as $keyType) {
            $this->checkStreamSign($crypto, $keyType);
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkStreamEncryption(VirgilCrypto $crypto, KeyPairType $keyPairType)
    {
        try {
            $keyPair1 = $crypto->generateKeyPair($keyPairType);
            $keyPair2 = $crypto->generateKeyPair($keyPairType);

            $testFileUrl = __DIR__."/../data/testData.txt";
            $inputStream = new InputStream($testFileUrl);
            $outputStream = new OutputStream("", true);
            $rawData = file_get_contents($testFileUrl);

            $stream = new Stream($inputStream, $outputStream, $crypto->getChunkSize());

            $pkl = new PublicKeyList($keyPair1->getPublicKey());

            $encrypt = $crypto->encrypt($stream, $pkl);

            // TODO!
            $encryptedData = "";
            //let encryptedData = outputStream.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey) as! Data

            $inputStream1 = new InputStream($encryptedData);
            $inputStream2 = new InputStream($encryptedData);

            $outputStream1 = new OutputStream("", true);
            $outputStream2 = new OutputStream("", true);

            $stream1 = new Stream($inputStream1, $outputStream1, $crypto->getChunkSize());
            $decrypt = $crypto->decrypt($stream1, $keyPair1->getPrivateKey());

            // TODO!
            $decryptedData = "";
            //let decrtyptedData = outputStream1.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey) as! Data

            self::assertEquals($rawData, $decryptedData);

            $stream2 = new Stream($inputStream2, $outputStream2, $crypto->getChunkSize());

            try {
                $res = $crypto->decrypt($stream2, $keyPair2->getPrivateKey());
                self::assertTrue(empty($res));
            } catch (Exception $e) {
                self::assertTrue($e instanceof VirgilCryptoException);
            }

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @throws VirgilCryptoException
     */
    public function test07EncryptStreamFileShouldDecrypt()
    {
        self::markTestSkipped("Skipped");

        $crypto = new VirgilCrypto();

        $keyTypes = [KeyPairType::CURVE25519(), KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

        foreach ($keyTypes as $keyType) {
            $this->checkStreamEncryption($crypto, $keyType);
        }
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkGenerateKeyUsingSeed(VirgilCrypto $crypto, KeyPairType $keyPairType)
    {
        try {
            $seed = $crypto->generateRandomData(32);

            $keyId = $crypto->generateKeyPairUsingSeed($seed)->getIdentifier();

            for ($i = 0; $i < 5; $i++)
            {
                $keyPair = $crypto->generateKeyPairUsingSeed($seed);

                $a1 = $keyPair->getPrivateKey()->getIdentifier();
                self::assertEquals($a1, $keyId);

                $a2 = $keyPair->getPublicKey()->getIdentifier();
                self::assertEquals($a1, $a2);
            }

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @throws VirgilCryptoException
     */
    public function test08GenerateKeyUsingSeedFixedSeedShouldMatch()
    {
        $crypto = new VirgilCrypto();

        $keyTypes = [KeyPairType::CURVE25519(), KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

        foreach ($keyTypes as $keyType) {
            $this->checkGenerateKeyUsingSeed($crypto, $keyType);
        }
    }

    /**
     *
     */
    public function test09MultithreadSignAndEncryptSameKeyShouldWork()
    {
        self::markTestSkipped("Skipped");
    }

    /**
     * @param VirgilCrypto $crypto
     * @param KeyPairType $keyPairType
     *
     * @throws VirgilCryptoException
     */
    private function checkKeyExportImport(VirgilCrypto $crypto, KeyPairType $keyPairType)
    {
        try {
            $keyPair = $crypto->generateKeyPair($keyPairType);

            $publicKeyData = $crypto->exportPublicKey($keyPair->getPublicKey());
            $privateKeyData = $crypto->exportPrivateKey($keyPair->getPrivateKey());

            $publicKey = $crypto->importPublicKey($publicKeyData);
            $privateKey = $crypto->importPrivateKey($privateKeyData)->getPrivateKey();

            $pkl = new PublicKeyList($publicKey);

            $data = new Data("");

            $res = $crypto->signAndEncrypt($data, $privateKey, $pkl);

            self::assertTrue(!is_null($res));
            self::assertTrue(is_string($res));

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    public function test10ImprortExportKeyRandomKeyShouldMatch()
    {
        $crypto = new VirgilCrypto();

        $keyTypes = [KeyPairType::ED25519(), KeyPairType::SECP256R1(), KeyPairType::RSA2048()];

        foreach ($keyTypes as $keyType) {
            $this->checkKeyExportImport($crypto, $keyType);
        }
    }
}