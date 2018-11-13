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

namespace Tests\Unit\Virgil\VirgilImpl\Cryptography\Cipher;

use PHPUnit\Framework\TestCase;
use Virgil\CryptoImpl\Cryptography\Cipher\VirgilSeqCipher;
use Exception;
use Virgil\CryptoImpl\KeyPairTypes;
use Virgil\CryptoImpl\VirgilCrypto;

/**
 * Class VirgilSeqCipherTestWithPassword
 * @package Tests\Unit\Virgil\VirgilImpl\Cryptography\Cipher
 */
class VirgilSeqCipherTestWithPassword extends TestCase
{
    /**
     * @var
     */
    private $virgilSeqCipher, $pathToFileFolder, $testFileName, $testFileExtension, $password,
$testFile, $inputHandler, $outputHandler, $encFileExtension, $encFile, $decFile;

    /**
     *
     */
    public function setUp()
    {
        $this->virgilSeqCipher = new VirgilSeqCipher();

        $this->pathToFileFolder = __DIR__ . "/../../../../../src/";
        $this->testFileName = "test-password";
        $this->testFileExtension = "pdf";
        $this->encFileExtension = "enc";

        $this->password = "password";

        $this->testFile = $this->pathToFileFolder . $this->testFileName . "." . $this->testFileExtension;
        $this->encFile = $this->pathToFileFolder . $this->testFileName . "." . $this->encFileExtension;
        $this->decFile = $this->pathToFileFolder . "decr_" . $this->testFileName . "." . $this->testFileExtension;
    }

    /**
     *
     */
    public function tearDown()
    {
        $this->virgilSeqCipher = null;
    }

    /**
     * @test
     */
    public function testFileExists()
    {
        $this->assertFileExists($this->testFile);
    }

    /**
     * @throws Exception
     * @test
     */
    public function testFileEncryptionWithPassword()
    {
        if (!($this->inputHandler = fopen($this->testFile, "rb")))
            throw new Exception("Cannot open input file");

        if (!($this->outputHandler = fopen($this->encFile, "w")))
            throw new Exception("Cannot open output file");

        $this->virgilSeqCipher->addPasswordRecipient($this->password);

        fwrite($this->outputHandler, $this->virgilSeqCipher->startEncryption());

        while (!feof($this->inputHandler)) {
            $inputData = fread($this->inputHandler, 1024);
            $encryptedData = $this->virgilSeqCipher->process($inputData);
            if(!empty($encryptedData))
                fwrite($this->outputHandler, $encryptedData);
        }
        fclose($this->inputHandler);
        $lastBlock = $this->virgilSeqCipher->finish();
        if(!empty($lastBlock))
            fwrite($this->outputHandler, $lastBlock);
        fclose($this->outputHandler);

        $this->assertFileExists($this->encFile);
    }

    /**
     * @throws Exception
     */
    public function testFileDecryptionWithCorrectPassword()
    {
        if (!($this->inputHandler = fopen($this->encFile, "rb")))
            throw new Exception("Cannot open input file");

        if (!($this->outputHandler = fopen($this->decFile, "w")))
            throw new Exception("Cannot open output file");

        fwrite($this->outputHandler, $this->virgilSeqCipher->startDecryptionWithPassword($this->password));

        while (!feof($this->inputHandler)) {
            $inputData = fread($this->inputHandler, 1024);
            $decryptedData = $this->virgilSeqCipher->process($inputData);
            if(!empty($decryptedData))
                fwrite($this->outputHandler, $decryptedData);
        }
        fclose($this->inputHandler);
        $lastBlock = $this->virgilSeqCipher->finish();
            fwrite($this->outputHandler, $lastBlock);
        fclose($this->outputHandler);

        $this->assertFileExists($this->decFile);
        $this->assertFileEquals($this->decFile, $this->testFile);
    }
}
