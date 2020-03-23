<?php
/**
 * Copyright (C) 2015-2020 Virgil Security Inc.
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

namespace Virgil\CryptoTests;

use PHPUnit\Framework\TestCase;
use Virgil\Crypto\Core\HashAlgorithms;
use Virgil\Crypto\VirgilCrypto;

/**
 * Class СryptoFormatsTests
 *
 * @package Virgil\Tests
 */
class CryptoFormatsTest extends TestCase
{
    /**
     * @group
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function test001SignatureHash()
    {
        $crypto = new VirgilCrypto();
        $keyPair = $crypto->generateKeyPair();
        $signature = $crypto->generateSignature("test", $keyPair->getPrivateKey());

        self::assertEquals(substr($signature, 0, 17), base64_decode("MFEwDQYJYIZIAWUDBAIDBQA="));
    }

    /**
     * @group
     * @throws \Virgil\Crypto\Exceptions\VirgilCryptoException
     */
    public function test004KeyIdentifierIsCorrect()
    {
        $crypto1 = new VirgilCrypto();
        $keyPair1 = $crypto1->generateKeyPair();

        self::assertEquals($keyPair1->getPrivateKey()->getIdentifier(), $keyPair1->getPublicKey()->getIdentifier());

        $a1 = substr($crypto1->computeHash($crypto1->exportPublicKey($keyPair1->getPublicKey()), HashAlgorithms::SHA512()),0, 8);
        $a2 = $keyPair1->getPrivateKey()->getIdentifier();

        self::assertEquals(strlen($a1), 8);
        self::assertEquals(strlen($a2), 8);
        self::assertEquals($a1, $a2);

        $crypto2 = new VirgilCrypto(null, true);
        $keyPair2 = $crypto2->generateKeyPair();

        $b1 = $crypto1->computeHash($crypto1->exportPublicKey($keyPair2->getPublicKey()), HashAlgorithms::SHA256());
        $b2 = $keyPair2->getPrivateKey()->getIdentifier();

        self::assertEquals(strlen($b1), 32);
        self::assertEquals(strlen($b2), 32);
        self::assertEquals($b1, $b2);
    }
}