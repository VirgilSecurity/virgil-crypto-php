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

namespace Tests\Unit\Virgil\VirgilImpl;


use PHPUnit\Framework\TestCase;

use Virgil\CryptoImpl\KeyPairTypes;
use Virgil\CryptoImpl\VirgilPublicKey;

use Virgil\Tests\CompatibilityDataProvider;

use Virgil\CryptoImpl\VirgilCrypto;

class VirgilCryptoCompatibilityTest extends TestCase
{
    const COMPATIBILITY_FILE_NAME = 'crypto_compatibility_data.json';


    /**
     * @dataProvider getEncryptedContentWithValidRecipientPrivateKeyDataProvider
     *
     * @param $private_key
     * @param $original_data
     * @param $cipher_data
     *
     * @test
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function decrypt__withValidRecipientPrivateKey__returnsOriginalData(
        $private_key,
        $original_data,
        $cipher_data
    ) {
        $virgilCrypto = $this->createVirgilCrypto();
        $recipientPrivateKey = $virgilCrypto->importPrivateKey(base64_decode($private_key));
        $expectedOriginalData = base64_decode($original_data);


        $actualDecryptedData = $virgilCrypto->decrypt(base64_decode($cipher_data), $recipientPrivateKey);


        $this->assertEquals($expectedOriginalData, $actualDecryptedData);
    }


    /**
     * @dataProvider getEncryptedContentWithValidRecipientAndSignerPrivateKeyDataProvider
     *
     * @param $private_key
     * @param $original_data
     * @param $cipher_data
     *
     * @param $signer_private_key
     *
     * @throws \Virgil\CryptoImpl\SignatureIsNotValidException
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     * @test
     */
    public function decryptThenVerify__withValidArguments__returnsVerifiedOriginalData(
        $private_key,
        $original_data,
        $cipher_data,
        $signer_private_key
    ) {
        $virgilCrypto = $this->createVirgilCrypto();
        $expectedOriginalData = base64_decode($original_data);
        $recipientPrivateKey = $virgilCrypto->importPrivateKey(base64_decode($private_key));
        $signerPrivateKey = $virgilCrypto->importPrivateKey(base64_decode($signer_private_key));
        $signerPublicKey = $virgilCrypto->extractPublicKey($signerPrivateKey);


        $actualDecryptedData = $virgilCrypto->decryptThenVerify(
            base64_decode($cipher_data),
            $recipientPrivateKey,
            [$signerPublicKey]
        );


        $this->assertEquals($expectedOriginalData, $actualDecryptedData);
    }


    /**
     * @dataProvider  decryptThenVerifyMultipleSignersDataProvider
     *
     * @test
     *
     * @param string            $private_key
     * @param VirgilPublicKey[] $public_keys
     * @param string            $original_data
     * @param string            $cipher_data
     *
     * @throws \Virgil\CryptoImpl\SignatureIsNotValidException
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function decryptThenVerify__MultipleSigners_ShouldDecryptThenVerify(
        $private_key,
        array $public_keys,
        $original_data,
        $cipher_data
    ) {
        $virgilCrypto = $this->createVirgilCrypto();
        $expectedOriginalData = base64_decode($original_data);
        $recipientPrivateKey = $virgilCrypto->importPrivateKey(base64_decode($private_key));

        $publicKeys = [];
        foreach ($public_keys as $public_key) {
            $publicKeys[] = $virgilCrypto->importPublicKey(base64_decode($public_key));
        }


        $actualDecryptedData = $virgilCrypto->decryptThenVerify(
            base64_decode($cipher_data),
            $recipientPrivateKey,
            $publicKeys
        );


        $this->assertEquals($expectedOriginalData, $actualDecryptedData);
    }


    /**
     * @dataProvider getSignatureForOriginalContentAndSignerPrivateKeyDataProvider
     *
     * @param $private_key
     * @param $original_data
     * @param $signature
     *
     * @test
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function sign__withValidSignerPrivateKey__returnsCorrectSignature($private_key, $original_data, $signature)
    {
        $virgilCrypto = $this->createVirgilCrypto();
        $signerPrivateKey = $virgilCrypto->importPrivateKey(base64_decode($private_key));
        $expectedSignature = base64_decode($signature);
        $expectedOriginalData = base64_decode($original_data);


        $actualSignature = $virgilCrypto->generateSignature($expectedOriginalData, $signerPrivateKey);


        $this->assertEquals($expectedSignature, $actualSignature);
    }


    public function decryptThenVerifyMultipleSignersDataProvider()
    {
        return $this->createCompatibilityDataProvider()
                    ->getDecryptThenVerifyMultipleSigners()
            ;
    }


    public function getEncryptedContentWithValidRecipientPrivateKeyDataProvider()
    {
        return $this->createCompatibilityDataProvider()
                    ->getEncryptArgumentsSetWithOriginalContent()
            ;
    }


    public function getEncryptedContentWithValidRecipientAndSignerPrivateKeyDataProvider()
    {
        return $this->createCompatibilityDataProvider()
                    ->getSignThenEncryptRecipientsData()
            ;
    }


    public function getSignatureForOriginalContentAndSignerPrivateKeyDataProvider()
    {
        return $this->createCompatibilityDataProvider()
                    ->getGenerateSignatureData()
            ;
    }


    private function createVirgilCrypto()
    {
        return new VirgilCrypto(KeyPairTypes::FAST_EC_ED25519, true);
    }


    private function createCompatibilityDataProvider()
    {
        return new CompatibilityDataProvider(
            VIRGIL_FIXTURE_PATH . DIRECTORY_SEPARATOR . self::COMPATIBILITY_FILE_NAME
        );
    }
}
