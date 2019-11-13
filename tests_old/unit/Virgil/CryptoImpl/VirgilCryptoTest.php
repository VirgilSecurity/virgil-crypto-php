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

use Virgil\CryptoImpl\VirgilCrypto;


class VirgilCryptoTest extends TestCase
{

    /**
     * @test
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function encryptThenDecrypt__withValidKeys__returnsValidResult()
    {
        $data = 'data_to_encrypt';
        $virgilCrypto = new VirgilCrypto();

        $aliceKeyPair = $virgilCrypto->generateKeys();
        $bobKeyPair = $virgilCrypto->generateKeys();


        $encryptedData = $virgilCrypto->encrypt(
            $data,
            [$aliceKeyPair->getPublicKey(), $bobKeyPair->getPublicKey()]
        );
        $decryptedDataByAlice = $virgilCrypto->decrypt($encryptedData, $aliceKeyPair->getPrivateKey());
        $decryptedDataByBob = $virgilCrypto->decrypt($encryptedData, $bobKeyPair->getPrivateKey());


        $this->assertEquals($data, $decryptedDataByAlice);
        $this->assertEquals($data, $decryptedDataByBob);
    }


    /**
     * @test
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function encryptThenDecryptStream__withValidKeys__returnsValidResult()
    {
        $data = 'data_to_encrypt';
        $source = fopen('php://memory', 'r+');
        $sin = fopen('php://memory', 'r+');
        fwrite($source, $data);
        $virgilCrypto = new VirgilCrypto();
        $keys = $virgilCrypto->generateKeys();
        $keys2 = $virgilCrypto->generateKeys();


        $virgilCrypto->encryptStream($source, $sin, [$keys->getPublicKey(), $keys2->getPublicKey()]);


        rewind($sin);
        $this->assertNotEquals($data, stream_get_contents($sin));

        $source = fopen('php://memory', 'w');
        $virgilCrypto->decryptStream($sin, $source, $keys->getPrivateKey());
        rewind($source);
        $this->assertEquals($data, stream_get_contents($source));

        $source = fopen('php://memory', 'w');
        $virgilCrypto->decryptStream($sin, $source, $keys2->getPrivateKey());
        rewind($source);
        $this->assertEquals($data, stream_get_contents($source));
    }


    /**
     * @test
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function signThenVerify__withContent__returnsValidResult()
    {
        $content = 'data_to_sign';

        $virgilCrypto = new VirgilCrypto();

        $privateKey = base64_decode('MC4CAQAwBQYDK2VwBCIEIB4bj3f9XEvvM6Z8F42oJr7nHpuBEIxm42Y2CqPtCng5');
        $publicKey = base64_decode('MCowBQYDK2VwAyEAX9FREHNOfQ7b1W9b+iSc2rdMhTrZ/HxmHvMuhYiRd9g=');

        $privateKeyReference = $virgilCrypto->importPrivateKey($privateKey);
        $publicKeyReference = $virgilCrypto->importPublicKey($publicKey);


        $signature = $virgilCrypto->generateSignature($content, $privateKeyReference);
        $isValid = $virgilCrypto->verifySignature($content, $signature, $publicKeyReference);


        $this->assertTrue($isValid);
    }


    /**
     * @test
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function signThenVerifyStream__withContent__returnsValidResult()
    {
        $content = 'data_to_encrypt';
        $source = fopen('php://memory', 'r');
        fwrite($source, $content);

        $virgilCrypto = new VirgilCrypto();


        $privateKey = base64_decode('MC4CAQAwBQYDK2VwBCIEIB4bj3f9XEvvM6Z8F42oJr7nHpuBEIxm42Y2CqPtCng5');
        $publicKey = base64_decode('MCowBQYDK2VwAyEAX9FREHNOfQ7b1W9b+iSc2rdMhTrZ/HxmHvMuhYiRd9g=');


        $privateKeyReference = $virgilCrypto->importPrivateKey($privateKey);
        $publicKeyReference = $virgilCrypto->importPublicKey($publicKey);


        $signature = $virgilCrypto->generateStreamSignature($source, $privateKeyReference);
        $isValid = $virgilCrypto->verifyStreamSignature($source, $signature, $publicKeyReference);


        $this->assertTrue($isValid);
    }


    /**
     * @test
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function extractPublicKey__fromPrivateKey__returnsValidPublicKey()
    {
        $virgilCrypto = new VirgilCrypto();

        $keys = $virgilCrypto->generateKeys();


        $extractedPublicKey = $virgilCrypto->extractPublicKey($keys->getPrivateKey());


        $this->assertEquals($keys->getPublicKey(), $extractedPublicKey);
    }


    /**
     * @test
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function importThenExportPrivateKey__withPrivateKeys__returnsValidResult()
    {
        $virgilCrypto = new VirgilCrypto();

        $expectedPrivateKey = base64_decode('MC4CAQAwBQYDK2VwBCIEIIZcCzLErF1EscqmXnBauI5GSIcIisbEmGwp+R9MRWW+');


        $importedKeyReference = $virgilCrypto->importPrivateKey($expectedPrivateKey);
        $exportedPrivateKey = $virgilCrypto->exportPrivateKey($importedKeyReference);


        $this->assertEquals($expectedPrivateKey, $exportedPrivateKey);
    }


    /**
     * @test
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function importThenExportPrivateKey__withPrivateKeysAndPassword__returnsValidResult()
    {
        $password = 'secure_password';


        $virgilCrypto = new VirgilCrypto();


        $exportedKeyWithPassword = base64_decode(
            'MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBCz/65j81rtPqETLglLsfNkAgIQ7jAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEEMNHmKo5iiy8rHpTDcx2gGMEQAbMHw2wKtL+1Ie1Ij7Ar/52o+bnVCzyXPjfxh91V0eN0Z4mn6NfiNwyYq8HI+khp/xvRYMLQWUTOrgvGhGJ/yk='
        );
        $expectedPrivateKey = base64_decode('MC4CAQAwBQYDK2VwBCIEIIZcCzLErF1EscqmXnBauI5GSIcIisbEmGwp+R9MRWW+');


        $importedKeyReference = $virgilCrypto->importPrivateKey($exportedKeyWithPassword, $password);
        $exportedPrivateKey = $virgilCrypto->exportPrivateKey($importedKeyReference);


        $this->assertEquals($expectedPrivateKey, $exportedPrivateKey);
    }


    /**
     * @test
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function importThenExportPublicKey__withPublicKeysAndPassword__returnsValidResult()
    {
        $virgilCrypto = new VirgilCrypto();

        $expectedPublicKey = base64_decode('MCowBQYDK2VwAyEA9cZXjjONZguBy94+59RMQ1xSIE9es2cbCGLsNFM8yls=');


        $keyReference = $virgilCrypto->importPublicKey($expectedPublicKey);
        $exportedPublicKey = $virgilCrypto->exportPublicKey($keyReference);


        $this->assertEquals($expectedPublicKey, $exportedPublicKey);
    }


    /**
     * @test
     * @throws \Virgil\CryptoImpl\VirgilCryptoException
     */
    public function decryptThenVerify__withKeyPairAndCipherData__returnsOriginalData()
    {
        $content = 'data_to_encrypt';
        $virgilCrypto = new VirgilCrypto();
        $aliceKeys = $virgilCrypto->generateKeys();
        $bobKeys = $virgilCrypto->generateKeys();


        $cipherData = $virgilCrypto->signThenEncrypt($content, $aliceKeys->getPrivateKey(), [$bobKeys->getPublicKey()]);
        $decryptedContent = $virgilCrypto->decryptThenVerify(
            $cipherData,
            $bobKeys->getPrivateKey(),
            [$aliceKeys->getPublicKey()]
        );


        $this->assertEquals($content, $decryptedContent);
    }
}
