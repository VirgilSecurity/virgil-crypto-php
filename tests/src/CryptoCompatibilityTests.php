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
use Virgil\CryptoImpl\Core\PublicKeyList;
use Virgil\CryptoImpl\Services\InputOutputService;
use Virgil\CryptoImpl\VirgilCrypto;
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
    const JSON_DATA = "/../data/crypto_compatibility_data.json";

    /**
     * @return VirgilCrypto
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
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
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
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
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
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
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
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
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
     * @throws \Virgil\CryptoImpl\Exceptions\VirgilCryptoException
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
}