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
use Virgil\Crypto\Core\HashAlgorithms;
use Virgil\Crypto\Core\PublicKeyList;
use Virgil\Crypto\Exceptions\VirgilCryptoException;
use Virgil\Crypto\Services\InputOutputService;
use Virgil\Crypto\VirgilCrypto;
use Virgil\Tests\_\CompatibilityDataProvider;

/**
 * Class CryptoCompatibilityTests
 *
 * @package Virgil\Tests
 */
class CryptoCompatibilityTests extends TestCase
{
    /**
     *
     */
    const JSON_DATA = "/data/crypto_compatibility_data.json";

    /**
     * @return VirgilCrypto
     * @throws Exception
     */
    private function getCrypto(): VirgilCrypto
    {
        return new VirgilCrypto(null,true);
    }

    /**
     * @return CompatibilityDataProvider
     */
    private function getDataProvider(): CompatibilityDataProvider
    {
        return new CompatibilityDataProvider(__DIR__.self::JSON_DATA);
    }

    /**
     * @return InputOutputService
     */
    private function getIOService(): InputOutputService
    {
        return new InputOutputService();
    }

    /**
     *
     */
    public function test001CheckNumberOfTestsInJSON()
    {
        self::assertEquals($this->getDataProvider()->getNumberOfTests(), 8);
    }

    /**
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function test002DecryptFromSingleRecipientShouldDecrypt()
    {
        $dict = $this->getDataProvider()->getTestData("encrypt_single_recipient");

        $privateKeyStr = $dict["private_key"];
        $privateKeyData = base64_decode($privateKeyStr);

        $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

        $originalDataStr = $dict["original_data"];

        $cipherDataStr = $dict["cipher_data"];
        $cipherData = base64_decode($cipherDataStr);

        $cipherData = $this->getIOService()->convertStringToData($cipherData);

        $decryptedData = $this->getCrypto()->decrypt($cipherData, $privateKey);
        $decryptedDataStr = base64_encode($decryptedData);

        self::assertEquals($decryptedDataStr, $originalDataStr);
    }

    /**
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function test003DecryptFromMultipleRecipientsShouldDecypt()
    {
        $dict = $this->getDataProvider()->getTestData("encrypt_multiple_recipients");

        $privateKeys = [];

        foreach ($dict["private_keys"] as $privateKeyStr)
        {
            $privateKeyData = base64_decode($privateKeyStr);
            $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

            $privateKeys[] = $privateKey;
        }

        self::assertTrue(count($privateKeys) > 0);

        $originalDataStr = $dict["original_data"];

        $cipherDataStr = $dict["cipher_data"];
        $cipherData = base64_decode($cipherDataStr);
        $cipherData = $this->getIOService()->convertStringToData($cipherData);

        foreach ($privateKeys as $privateKey)
        {
            $decryptedData = $this->getCrypto()->decrypt($cipherData, $privateKey);
            $decryptedDataStr = base64_encode($decryptedData);

            self::assertEquals($decryptedDataStr, $originalDataStr);
        }
    }

    /**
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function test004DecryptAndVerifySingleRecipientShouldDecryptAndVerify()
    {
        $dict = $this->getDataProvider()->getTestData("sign_and_encrypt_single_recipient");

        $privateKeyStr = $dict["private_key"];
        $privateKeyData = base64_decode($privateKeyStr);

        $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

        $publicKey = $this->getCrypto()->extractPublicKey($privateKey);
        $pkl = new PublicKeyList($publicKey);

        $originalDataStr = $dict["original_data"];
        $originalData = base64_decode($originalDataStr);

        $cipherDataStr = $dict["cipher_data"];
        $cipherData = base64_decode($cipherDataStr);
        $cipherData = $this->getIOService()->convertStringToData($cipherData);

        $decryptedData = $this->getCrypto()->decryptAndVerify($cipherData, $privateKey, $pkl);

        self::assertEquals($originalData, $decryptedData);
    }

    /**
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function test005DecryptAndVerifyMultipleRecipientsShouldDecryptAndVerify()
    {
        $dict = $this->getDataProvider()->getTestData("sign_and_encrypt_multiple_recipients");

        $privateKeys = [];

        foreach ($dict["private_keys"] as $privateKeyStr)
        {
            $privateKeyData = base64_decode($privateKeyStr);
            $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

            $privateKeys[] = $privateKey;
        }

        self::assertTrue(count($privateKeys) > 0);

        $originalDataStr = $dict["original_data"];

        $cipherDataStr = $dict["cipher_data"];
        $cipherData = base64_decode($cipherDataStr);
        $cipherData = $this->getIOService()->convertStringToData($cipherData);

        $signerPublicKey = $this->getCrypto()->extractPublicKey($privateKeys[0]);
        $pkl = new PublicKeyList($signerPublicKey);

        foreach ($privateKeys as $privateKey)
        {
            $decryptedData = $this->getCrypto()->decryptAndVerify($cipherData, $privateKey, $pkl);
            $decryptedDataStr = base64_encode($decryptedData);

            self::assertEquals($decryptedDataStr, $originalDataStr);
        }
    }

    /**
     * @throws VirgilCryptoException
     */
    public function test006GenerateSignatureShouldBeEqual()
    {
        $dict = $this->getDataProvider()->getTestData("generate_signature");

        $privateKeyStr = $dict["private_key"];
        $privateKeyData = base64_decode($privateKeyStr);

        $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

        $publicKey = $this->getCrypto()->extractPublicKey($privateKey);

        $originalDataStr = $dict["original_data"];
        $originalData = base64_decode($originalDataStr);

        $signature = $this->getCrypto()->generateSignature($originalData, $privateKey);
        $signatureStr = base64_encode($signature);

        $originalSignatureStr = $dict["signature"];
        $originalSignature = base64_decode($originalSignatureStr);

        $res = $this->getCrypto()->verifySignature($originalSignature, $originalData, $publicKey);

        self::assertTrue($res);
        self::assertEquals($originalSignatureStr, $signatureStr);
    }

    /**
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function test007DecryptAndVerifyMultipleSignersShouldDecryptAndVerify()
    {
        $dict = $this->getDataProvider()->getTestData("sign_and_encrypt_multiple_signers");

        $privateKeyStr = $dict["private_key"];
        $privateKeyData = base64_decode($privateKeyStr);

        $privateKey = $this->getCrypto()->importPrivateKey($privateKeyData)->getPrivateKey();

        $pkl = new PublicKeyList();

        foreach ($dict["public_keys"] as $publicKeyStr)
        {
            $publicKeyData = base64_decode($publicKeyStr);
            $publicKey = $this->getCrypto()->importPublicKey($publicKeyData);

            $pkl->addPublicKey($publicKey);
        }

        $originalDataStr = $dict["original_data"];

        $cipherDataStr = $dict["cipher_data"];
        $cipherData = base64_decode($cipherDataStr);
        $cipherData = $this->getIOService()->convertStringToData($cipherData);

        $decryptedData = $this->getCrypto()->decryptAndVerify($cipherData, $privateKey, $pkl);
        $decryptedDataStr = base64_encode($decryptedData);

        self::assertEquals($decryptedDataStr, $originalDataStr);
    }

    /**
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function test008GenerateEd25519UsingSeedShouldMatch()
    {
        $dict = $this->getDataProvider()->getTestData("generate_ed25519_using_seed");

        $seedStr = $dict["seed"];
        $seed = base64_decode($seedStr);

        $keyPair = $this->getCrypto()->generateKeyPairUsingSeed($seed);

        $privateKeyStr = $dict["private_key"];
        $publicKeyStr = $dict["public_key"];
        $privateKeyData = base64_decode($privateKeyStr);
        $publicKeyData = base64_decode($publicKeyStr);

        $a1 = $this->getCrypto()->exportPrivateKey($keyPair->getPrivateKey());
        self::assertEquals($a1, $privateKeyData);

        $b1 = $this->getCrypto()->exportPublicKey($keyPair->getPublicKey());
        self::assertEquals($b1, $publicKeyData);
    }

    /**
     * @throws VirgilCryptoException
     */
    public function test009SignThenEncryptShouldMatch()
    {
        $dict = $this->getDataProvider()->getTestData("auth_encrypt");

        $privateKey1Str = $dict["private_key1"];
        $privateKey2Str = $dict["private_key2"];
        $publicKeyStr = $dict["public_key"];
        $dataSha512Str = $dict["data_sha512"];
        $cipherDataStr = $dict["cipher_data"];

        $privateKey1 = $this->getCrypto()->importPrivateKey(base64_decode($privateKey1Str))->getPrivateKey();
        $keyPair2 = $this->getCrypto()->importPrivateKey(base64_decode($privateKey2Str));
        $publicKey = $this->getCrypto()->importPublicKey(base64_decode($publicKeyStr));
        $pkl = new PublicKeyList($publicKey);
        $pkl2 = new PublicKeyList($keyPair2->getPublicKey());

        $dataSha512 = base64_decode($dataSha512Str);
        $cipherData = base64_decode($cipherDataStr);
        $cipherData = $this->getIOService()->convertStringToData($cipherData);

        $data = $this->getCrypto()->authDecrypt($cipherData, $privateKey1, $pkl);

        $a1 = $this->getCrypto()->computeHash($data, HashAlgorithms::SHA512());

        self::assertEquals($a1, $dataSha512);

        try {
            $res1 = $this->getCrypto()->authDecrypt($cipherData, $keyPair2->getPrivateKey(), $pkl);
            self::assertTrue(empty($res1));
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }

        try {
            $res2 = $this->getCrypto()->authDecrypt($cipherData, $privateKey1, $pkl2);
            self::assertTrue(empty($res2));
        } catch (Exception $e) {
            self::assertTrue($e instanceof VirgilCryptoException);
        }
    }
}