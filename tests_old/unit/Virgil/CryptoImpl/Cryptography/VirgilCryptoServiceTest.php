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

namespace Tests\Unit\Virgil\VirgilImpl\Cryptography;


use PHPUnit\Framework\TestCase;

use Virgil\CryptoImpl\Cryptography\VirgilCryptoService;
use Virgil\CryptoImpl\KeyPairTypes;
use Virgil\CryptoImpl\VirgilKeyPair;


class VirgilCryptoServiceTest extends TestCase
{
    /** @var VirgilCryptoService */
    private $cryptoService;


    public function setUp()
    {
        $this->cryptoService = new VirgilCryptoService();
    }


    /**
     * @test
     *
     * @return array
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\KeyPairGenerationException
     */
    public function generateKeyPair__withOneOfKeyPairTypes__returnsValidKeyPair()
    {
        $keyPairType = KeyPairTypes::FAST_EC_ED25519;


        $aliceKeyPair = $this->cryptoService->generateKeyPair($keyPairType);
        $bobKeyPair = $this->cryptoService->generateKeyPair($keyPairType);

        $this->assertCount(2, $aliceKeyPair);
        $this->assertCount(2, $bobKeyPair);

        return [$aliceKeyPair, $bobKeyPair];
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\KeyPairGenerationException
     *
     * @test
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\KeyPairGenerationException
     */
    public function generateKeyPair__withWrongKeyPairType__throwsException()
    {
        $invalidKeyPairType = 21;


        $this->cryptoService->generateKeyPair($invalidKeyPairType);


        //expected exception
    }


    /**
     * @depends  generateKeyPair__withOneOfKeyPairTypes__returnsValidKeyPair
     *
     * @param array $keyPairs
     *
     * @test
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\InvalidKeyPairException
     */
    public function isKeyPair__forSameKeyPair__returnsTrue(
        array $keyPairs
    ) {
        list($aliceKeyPair, $bobKeyPair) = $keyPairs;


        $isSameKeyPair = $this->cryptoService->isKeyPair($aliceKeyPair[0], $aliceKeyPair[1]);


        $this->assertTrue($isSameKeyPair);
    }


    /**
     * @depends  generateKeyPair__withOneOfKeyPairTypes__returnsValidKeyPair
     *
     * @param array $keyPairs
     *
     * @test
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\InvalidKeyPairException
     */
    public function isKeyPair__forDifferentKeyPairs__returnsFalse(
        array $keyPairs
    ) {
        list($aliceKeyPair, $bobKeyPair) = $keyPairs;


        $isSameKeyPair = $this->cryptoService->isKeyPair($bobKeyPair[0], $aliceKeyPair[1]);


        $this->assertFalse($isSameKeyPair);
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\PublicKeyToDerConvertingException
     *
     * @test
     */
    public function publicKeyToDer__withInvalidPublicKey__throwsException()
    {
        $invalidPublicKey = 'wrong key';


        $this->cryptoService->publicKeyToDer($invalidPublicKey);


        //expected exception
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\PrivateKeyToDerConvertingException
     *
     * @test
     */
    public function privateKeyToDer__withInvalidPublicKey__throwsException()
    {
        $invalidPrivateKey = 'wrong key';


        $this->cryptoService->privateKeyToDer($invalidPrivateKey);


        //expected exception
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\PublicKeyHashComputationException
     *
     * @test
     */
    public function computeHash__withInvalidArguments__throwsException()
    {
        $invalidPublicKey = 'wrong key';
        $invalidHashAlgorithm = 'wrong algorithm';


        $this->cryptoService->computeHash($invalidPublicKey, $invalidHashAlgorithm);


        //expected exception
    }


    /**
     * @depends generateKeyPair__withOneOfKeyPairTypes__returnsValidKeyPair
     *
     * @param array $keyPairs
     *
     * @test
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\PublicKeyExtractionException
     */
    public function extractPublicKey__fromPrivateKey__returnsPublicKey(
        array $keyPairs
    ) {
        list($aliceKeyPair, $bobKeyPair) = $keyPairs;

        $extractPassword = '';


        $extractedAlicePublicKey = $this->cryptoService->extractPublicKey(
            $aliceKeyPair[1],
            $extractPassword
        );


        $this->assertEquals($aliceKeyPair[0], $extractedAlicePublicKey);
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\PublicKeyExtractionException
     *
     * @test
     */
    public function extractPublicKey__fromInvalidPrivateKey__throwsException()
    {
        $invalidPrivateKey = 'wrong private key';
        $encryptPassword = '';


        $this->cryptoService->extractPublicKey($invalidPrivateKey, $encryptPassword);


        //expected exception
    }


    /**
     * @depends generateKeyPair__withOneOfKeyPairTypes__returnsValidKeyPair
     *
     * @param VirgilKeyPair[] $keyPairs
     *
     * @test
     *
     * @return array
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\PrivateKeyEncryptionException
     */
    public function encryptPrivateKey__withPrivateKeyAndPassword__returnsEncryptedPrivateKey(
        array $keyPairs
    ) {
        list($aliceKeyPair, $bobKeyPair) = $keyPairs;

        $encryptPassword = 'qwerty';
        $alicePrivateKey = $aliceKeyPair[1];


        $encryptedPrivateKey = $this->cryptoService->encryptPrivateKey($alicePrivateKey, $encryptPassword);


        $this->assertNotEquals($alicePrivateKey, $encryptedPrivateKey);


        return [$alicePrivateKey, $encryptedPrivateKey, $encryptPassword];
    }


    /**
     * @depends encryptPrivateKey__withPrivateKeyAndPassword__returnsEncryptedPrivateKey
     *
     * @param $encryptPrivateKeyWithPrivateKeyAndPasswordData
     *
     * @test
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\PrivateKeyDecryptionException
     */
    public function decryptPrivateKey__withEncryptedPrivateKeyAndPassword__returnsOriginalPrivateKey(
        $encryptPrivateKeyWithPrivateKeyAndPasswordData
    ) {
        list($alicePrivateKey, $encryptedPrivateKey, $encryptPassword) = $encryptPrivateKeyWithPrivateKeyAndPasswordData;


        $decryptedPrivateKey = $this->cryptoService->decryptPrivateKey($encryptedPrivateKey, $encryptPassword);


        $this->assertEquals($alicePrivateKey, $decryptedPrivateKey);
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\PrivateKeyEncryptionException
     *
     * @test
     */
    public function encryptPrivateKey__withInvalidPrivateKeyAndPassword__throwsException()
    {
        $invalidPrivateKey = 'wrong private key';
        $encryptPassword = '';


        $this->cryptoService->encryptPrivateKey($invalidPrivateKey, $encryptPassword);


        //expected exception
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\PrivateKeyDecryptionException
     *
     * @test
     */
    public function decryptPrivateKey__withInvalidEncryptedPrivateKeyAndPassword__throwsException()
    {
        $invalidEncryptedPrivateKey = 'wrong private key';
        $encryptPassword = '';


        $this->cryptoService->decryptPrivateKey($invalidEncryptedPrivateKey, $encryptPassword);


        //expected exception
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\ContentVerificationException
     *
     * @test
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\KeyPairGenerationException
     */
    public function verify__withInvalidSignatureFormat__throwsException()
    {
        $content = 'data';
        $invalidSignatureFormat = 'wrong signature';

        $aliceKeyPair = $this->cryptoService->generateKeyPair(KeyPairTypes::FAST_EC_ED25519);


        $this->cryptoService->verify($content, $invalidSignatureFormat, $aliceKeyPair[0]);


        //expected exception
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\ContentVerificationException
     *
     * @test
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\KeyPairGenerationException
     */
    public function verifyStream__withInvalidSignatureFormat__throwsException()
    {
        $sourceStream = fopen('php://memory', 'r+');
        $content = 'data';
        fwrite($sourceStream, $content);
        $invalidSignatureFormat = 'wrong signature';

        $aliceKeyPair = $this->cryptoService->generateKeyPair(KeyPairTypes::FAST_EC_ED25519);


        $this->cryptoService->verifyStream($sourceStream, $invalidSignatureFormat, $aliceKeyPair[0]);


        //expected exception
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\ContentSigningException
     *
     * @test
     */
    public function sign__withInvalidPrivateKey__throwsException()
    {
        $invalidPrivateKey = 'wrong private key';
        $content = 'data';


        $this->cryptoService->sign($content, $invalidPrivateKey);


        //expected exception
    }


    /**
     * @depends generateKeyPair__withOneOfKeyPairTypes__returnsValidKeyPair
     *
     * @param VirgilKeyPair[] $keyPairs
     *
     * @test
     *
     * @return array
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\ContentSigningException
     */
    public function sign__withPrivateKey__returnsSignature(
        array $keyPairs
    ) {
        list($aliceKeyPair, $bobKeyPair) = $keyPairs;

        $content = 'data';
        $alicePrivateKey = $aliceKeyPair[1];
        $alicePublicKey = $aliceKeyPair[0];
        $bobPublicKey = $bobKeyPair[0];


        $contentSignature = $this->cryptoService->sign($content, $alicePrivateKey);


        $this->assertNotEmpty($contentSignature);


        return [$content, $contentSignature, $alicePublicKey, $bobPublicKey];
    }


    /**
     * @depends sign__withPrivateKey__returnsSignature
     *
     * @param array $signWithPrivateKeyData
     *
     * @test
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\ContentVerificationException
     */
    public function verify__withPublicKeys__returnsValidationResult(
        array $signWithPrivateKeyData
    ) {
        list($content, $contentSignature, $signerPublicKey, $invalidPublicKey) = $signWithPrivateKeyData;


        $isValid = $this->cryptoService->verify($content, $contentSignature, $signerPublicKey);
        $isInvalid = $this->cryptoService->verify($content, $contentSignature, $invalidPublicKey);


        $this->assertTrue($isValid);
        $this->assertFalse($isInvalid);
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\ContentSigningException
     *
     * @test
     */
    public function signStream__withInvalidPrivateKey__throwsException()
    {
        $invalidPrivateKey = 'wrong private key';
        $streamSource = fopen('php://memory', 'r+');


        $this->cryptoService->signStream($streamSource, $invalidPrivateKey);


        //expected exception
    }


    /**
     * @depends generateKeyPair__withOneOfKeyPairTypes__returnsValidKeyPair
     *
     * @param VirgilKeyPair[] $keyPairs
     *
     * @test
     *
     * @return array
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\ContentSigningException
     */
    public function signStream__withPrivateKey__returnsSignature(
        array $keyPairs
    ) {
        list($aliceKeyPair, $bobKeyPair) = $keyPairs;

        $sourceStream = fopen('php://memory', 'r+');
        $data = 'data';
        fwrite($sourceStream, $data);

        $alicePrivateKey = $aliceKeyPair[1];
        $alicePublicKey = $aliceKeyPair[0];
        $bobPublicKey = $bobKeyPair[0];


        $contentSignature = $this->cryptoService->signStream($sourceStream, $alicePrivateKey);


        $this->assertNotEmpty($contentSignature);


        return [$sourceStream, $contentSignature, $alicePublicKey, $bobPublicKey];
    }


    /**
     * @depends signStream__withPrivateKey__returnsSignature
     *
     * @param array $signStreamWithPrivateKeyData
     *
     * @test
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\ContentVerificationException
     */
    public function verifyStream__withPublicKeys__returnsValidationResult(
        array $signStreamWithPrivateKeyData
    ) {
        list($sourceStream, $contentSignature, $signerPublicKey, $invalidPublicKey) = $signStreamWithPrivateKeyData;


        $isValid = $this->cryptoService->verifyStream($sourceStream, $contentSignature, $signerPublicKey);
        $isInvalid = $this->cryptoService->verifyStream($sourceStream, $contentSignature, $invalidPublicKey);


        $this->assertTrue($isValid);
        $this->assertFalse($isInvalid);
    }


    /**
     * @test
     */
    public function encrypt__withoutRecipients__returnsEncryptedData()
    {
        $content = 'data';
        $receiverId = 'SALGH&';
        $cipher = $this->cryptoService->createCipher();


        $encryptedContent = $cipher->encrypt($cipher->createInputOutput($content));


        $this->assertNotEquals($content, $encryptedContent);


        return [$encryptedContent, $cipher, $receiverId];
    }


    /**
     * @expectedException \Virgil\CryptoImpl\Cryptography\Exceptions\CipherException
     *
     * @depends generateKeyPair__withOneOfKeyPairTypes__returnsValidKeyPair
     * @depends encrypt__withoutRecipients__returnsEncryptedData
     *
     * @param array $keyPairs
     * @param array $encryptWithoutRecipientsData
     *
     * @test
     */
    public function decryptWithKey__withoutRecipients__throwsException(
        array $keyPairs,
        array $encryptWithoutRecipientsData
    ) {
        list($aliceKeyPair, $bobKeyPair) = $keyPairs;
        list($encryptedContent, $cipher, $receiverId) = $encryptWithoutRecipientsData;


        $cipher->decryptWithKey(
            $cipher->createInputOutput($encryptedContent),
            $receiverId,
            $aliceKeyPair[1]
        );


        //expected exception
    }


    /**
     * @depends generateKeyPair__withOneOfKeyPairTypes__returnsValidKeyPair
     *
     * @param VirgilKeyPair[] $keyPairs
     *
     * @test
     *
     * @return array
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\CipherException
     */
    public function encrypt__withRecipients__returnsEncryptedData(
        array $keyPairs
    ) {
        list($aliceKeyPair, $bobKeyPair) = $keyPairs;

        $content = 'data';
        $aliceReceiverId = 'SALGH&';
        $bobReceiverId = 'ZLKG&';

        $cipher = $this->cryptoService->createCipher();

        $cipher->addKeyRecipient($aliceReceiverId, $aliceKeyPair[0]);
        $cipher->addKeyRecipient($bobReceiverId, $bobKeyPair[0]);


        $encryptedContent = $cipher->encrypt($cipher->createInputOutput($content));


        $this->assertNotEquals($content, $encryptedContent);


        return [
            $content,
            $encryptedContent,
            $cipher,
            [
                $aliceReceiverId,
                $aliceKeyPair[1],
            ],
            [
                $bobReceiverId,
                $bobKeyPair[1],
            ],
        ];
    }


    /**
     * @depends encrypt__withRecipients__returnsEncryptedData
     *
     * @param array $encryptWithRecipientsData
     *
     * @test
     */
    public function decryptWithKey__withRecipients__returnsOriginalData(
        array $encryptWithRecipientsData
    ) {
        list($originalContent, $encryptedContent, $cipher, $alicePrivateKeyWithId, $bobPrivateKeyWithId) = $encryptWithRecipientsData;
        list($aliceReceiverId, $alicePrivateKey) = $alicePrivateKeyWithId;
        list($bobReceiverId, $bobPrivateKey) = $bobPrivateKeyWithId;

        $cipherInputOutput = $cipher->createInputOutput($encryptedContent);


        $decryptedContentByAlice = $cipher->decryptWithKey(
            $cipherInputOutput,
            $aliceReceiverId,
            $alicePrivateKey
        );

        $decryptedContentByBob = $cipher->decryptWithKey(
            $cipherInputOutput,
            $bobReceiverId,
            $bobPrivateKey
        );


        $this->assertEquals($originalContent, $decryptedContentByAlice);
        $this->assertEquals($originalContent, $decryptedContentByBob);
    }


    /**
     * @depends generateKeyPair__withOneOfKeyPairTypes__returnsValidKeyPair
     *
     * @param VirgilKeyPair[] $keyPairs
     *
     * @test
     *
     * @return array
     * @throws \Virgil\CryptoImpl\Cryptography\Exceptions\CipherException
     */
    public function encryptStream__withRecipients__encryptsDataFromInputStreamToOutputStream(
        array $keyPairs
    ) {
        list($aliceKeyPair, $bobKeyPair) = $keyPairs;

        $content = 'data_to_encrypt';
        $source = fopen('php://memory', 'r+');
        $sin = fopen('php://memory', 'r+');

        fwrite($source, $content);

        $aliceReceiverId = 'SALGH&';
        $bobReceiverId = 'ZLKG&';

        $streamCipher = $this->cryptoService->createStreamCipher();

        $streamCipher->addKeyRecipient($aliceReceiverId, $aliceKeyPair[0]);
        $streamCipher->addKeyRecipient($bobReceiverId, $bobKeyPair[0]);
        $streamInputOutput = $streamCipher->createInputOutput($source, $sin);


        $streamCipher->encrypt($streamInputOutput);


        rewind($sin);
        $encryptedContent = stream_get_contents($sin);
        $this->assertNotEmpty($encryptedContent);


        return [
            $content,
            $encryptedContent,
            $streamCipher,
            [
                $aliceReceiverId,
                $aliceKeyPair[1],
            ],
            [
                $bobReceiverId,
                $bobKeyPair[1],
            ],
        ];
    }


    /**
     * @depends encryptStream__withRecipients__encryptsDataFromInputStreamToOutputStream
     *
     * @param array $encryptWithRecipientsData
     *
     * @test
     */
    public function decryptWithKeyStream__withRecipients__decryptsEncryptedDataFromInputStreamToOutputStream(
        array $encryptWithRecipientsData
    ) {
        list($content, $encryptedContent, $streamCipher, $alicePrivateKeyWithId, $bobPrivateKeyWithId) = $encryptWithRecipientsData;
        list($aliceReceiverId, $alicePrivateKey) = $alicePrivateKeyWithId;
        list($bobReceiverId, $bobPrivateKey) = $bobPrivateKeyWithId;

        $source = fopen('php://memory', 'r+');
        fwrite($source, $encryptedContent);


        $sin = fopen('php://memory', 'r+');
        $streamCipher->decryptWithKey(
            $streamCipher->createInputOutput($source, $sin),
            $aliceReceiverId,
            $alicePrivateKey
        );

        rewind($sin);
        $decryptedContentByAlice = stream_get_contents($sin);

        $sin = fopen('php://memory', 'r+');
        $streamCipher->decryptWithKey(
            $streamCipher->createInputOutput($source, $sin),
            $bobReceiverId,
            $bobPrivateKey
        );

        rewind($sin);
        $decryptedContentByBob = stream_get_contents($sin);


        $this->assertEquals($content, $decryptedContentByAlice);
        $this->assertEquals($content, $decryptedContentByBob);
    }
}
