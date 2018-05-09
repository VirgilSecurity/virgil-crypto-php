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

namespace Virgil\CryptoImpl\Cryptography\Core;


use Exception;

use Virgil\CryptoImpl\Cryptography\Core\Crypto as VirgilCrypto;

use Virgil\CryptoImpl\Cryptography\Core\Cipher\VirgilCipher;
use Virgil\CryptoImpl\Cryptography\Core\Cipher\VirgilStreamCipher;
use Virgil\CryptoImpl\Cryptography\Core\Cipher\VirgilStreamDataSource;

use Virgil\CryptoImpl\Cryptography\Core\Exceptions\ContentSigningException;
use Virgil\CryptoImpl\Cryptography\Core\Exceptions\ContentVerificationException;
use Virgil\CryptoImpl\Cryptography\Core\Exceptions\InvalidKeyPairException;
use Virgil\CryptoImpl\Cryptography\Core\Exceptions\KeyPairGenerationException;
use Virgil\CryptoImpl\Cryptography\Core\Exceptions\PrivateKeyDecryptionException;
use Virgil\CryptoImpl\Cryptography\Core\Exceptions\PrivateKeyEncryptionException;
use Virgil\CryptoImpl\Cryptography\Core\Exceptions\PrivateKeyToDerConvertingException;
use Virgil\CryptoImpl\Cryptography\Core\Exceptions\PublicKeyExtractionException;
use Virgil\CryptoImpl\Cryptography\Core\Exceptions\PublicKeyHashComputationException;
use Virgil\CryptoImpl\Cryptography\Core\Exceptions\PublicKeyToDerConvertingException;

/**
 * Class aims to wrap native crypto library and provides cryptographic operations.
 */
class VirgilCryptoService
{
    /**
     * @var Crypto\VirgilHash
     */
    protected $hashAlgorithm;


    public function __construct($hashAlgorithm = VirgilCrypto\VirgilHash::Algorithm_SHA512)
    {
        $this->hashAlgorithm = new VirgilCrypto\VirgilHash($hashAlgorithm);
    }


    /**
     * Generate public/private key pair.
     *
     * @param integer $keyPairType
     *
     * @return array
     *
     * @throws KeyPairGenerationException
     */
    public function generateKeyPair($keyPairType)
    {
        try {
            $keyPair = VirgilCrypto\VirgilKeyPair::generate($keyPairType);

            return [$keyPair->publicKey(), $keyPair->privateKey()];
        } catch (Exception $exception) {
            throw new KeyPairGenerationException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * Converts private key to DER format.
     *
     * @param string $privateKey
     * @param string $privateKyePassword
     *
     * @return string
     *
     * @throws PrivateKeyToDerConvertingException
     */
    public function privateKeyToDer($privateKey, $privateKyePassword = '')
    {
        try {
            if (strlen($privateKyePassword) === 0) {
                return VirgilCrypto\VirgilKeyPair::privateKeyToDER($privateKey);
            }

            return VirgilCrypto\VirgilKeyPair::privateKeyToDER(
                $this->encryptPrivateKey($privateKey, $privateKyePassword),
                $privateKyePassword
            );
        } catch (Exception $exception) {
            throw new PrivateKeyToDerConvertingException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * Converts public key to DER format.
     *
     * @param string $publicKey
     *
     * @return string
     *
     * @throws PublicKeyToDerConvertingException
     */
    public function publicKeyToDer($publicKey)
    {
        try {
            return VirgilCrypto\VirgilKeyPair::publicKeyToDER($publicKey);
        } catch (Exception $exception) {
            throw new PublicKeyToDerConvertingException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * Checks if given keys are parts of the same key pair.
     *
     * @param string $publicKey
     * @param string $privateKey
     *
     * @return bool
     *
     * @throws InvalidKeyPairException
     */
    public function isKeyPair($publicKey, $privateKey)
    {
        try {
            return VirgilCrypto\VirgilKeyPair::isKeyPairMatch($publicKey, $privateKey);
        } catch (Exception $exception) {
            throw new InvalidKeyPairException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * Calculates key hash by the hash algorithm.
     *
     * @param string  $publicKeyDER  DER public key value
     * @param integer $hashAlgorithm Hash algorithm
     *
     * @return string
     *
     * @throws PublicKeyHashComputationException
     */
    public function computeHash($publicKeyDER, $hashAlgorithm)
    {
        try {
            return (new VirgilCrypto\VirgilHash($hashAlgorithm))->hash($publicKeyDER);
        } catch (Exception $exception) {
            throw new PublicKeyHashComputationException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * Extracts public key from a private key.
     *
     * @param string $privateKey
     * @param string $privateKeyPassword
     *
     * @return string
     *
     * @throws PublicKeyExtractionException
     */
    public function extractPublicKey($privateKey, $privateKeyPassword)
    {
        try {
            return VirgilCrypto\VirgilKeyPair::extractPublicKey($privateKey, $privateKeyPassword);
        } catch (Exception $exception) {
            throw new PublicKeyExtractionException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * Encrypts private key with a password.
     *
     * @param string $privateKey
     * @param string $password
     *
     * @return string
     *
     * @throws PrivateKeyEncryptionException
     */
    public function encryptPrivateKey($privateKey, $password)
    {
        try {
            return VirgilCrypto\VirgilKeyPair::encryptPrivateKey($privateKey, $password);
        } catch (Exception $exception) {
            throw new PrivateKeyEncryptionException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * Decrypts private key with a password.
     *
     * @param string $privateKey
     * @param string $privateKeyPassword
     *
     * @return string
     *
     * @throws PrivateKeyDecryptionException
     */
    public function decryptPrivateKey($privateKey, $privateKeyPassword)
    {
        try {
            return VirgilCrypto\VirgilKeyPair::decryptPrivateKey($privateKey, $privateKeyPassword);
        } catch (Exception $exception) {
            throw new PrivateKeyDecryptionException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * Sign content with a private key.
     *
     * @param string $content
     * @param string $privateKey
     *
     * @return string
     *
     * @throws ContentSigningException
     */
    public function sign($content, $privateKey)
    {
        try {
            return (new VirgilCrypto\VirgilSigner($this->hashAlgorithm))->sign($content, $privateKey);
        } catch (Exception $exception) {
            throw new ContentSigningException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * Verify content with a public key and signature.
     *
     * @param string $content
     * @param string $signature
     * @param string $publicKey
     *
     * @return bool
     *
     * @throws ContentVerificationException
     */
    public function verify($content, $signature, $publicKey)
    {
        try {
            return (new VirgilCrypto\VirgilSigner($this->hashAlgorithm))->verify($content, $signature, $publicKey);
        } catch (Exception $exception) {
            throw new ContentVerificationException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * Creates cipher for encrypt\decrypt content.
     *
     * @return VirgilCipher
     */
    public function createCipher()
    {
        return new VirgilCipher(new VirgilCrypto\VirgilCipher());
    }


    /**
     * Creates cipher for encrypt\decrypt content stream.
     *
     * @return VirgilStreamCipher
     */
    public function createStreamCipher()
    {
        return new VirgilStreamCipher(new VirgilCrypto\VirgilChunkCipher());
    }


    /**
     * Sign stream with a private key
     *
     * @param resource $stream
     * @param string   $privateKey
     *
     * @return string
     *
     * @throws ContentSigningException
     */
    public function signStream($stream, $privateKey)
    {
        try {
            $virgilSourceStream = new VirgilStreamDataSource($stream);
            $virgilSourceStream->reset();

            return (new VirgilCrypto\VirgilStreamSigner($this->hashAlgorithm))->sign(
                $virgilSourceStream,
                $privateKey
            );
        } catch (Exception $exception) {
            throw new ContentSigningException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * Verify stream with a public key and signature.
     *
     * @param resource $stream
     * @param string   $signature
     * @param string   $publicKey
     *
     * @return bool
     *
     * @throws ContentVerificationException
     */
    public function verifyStream($stream, $signature, $publicKey)
    {
        try {
            $virgilSourceStream = new VirgilStreamDataSource($stream);

            return (new VirgilCrypto\VirgilStreamSigner($this->hashAlgorithm))->verify(
                $virgilSourceStream,
                $signature,
                $publicKey
            );
        } catch (Exception $exception) {
            throw new ContentVerificationException($exception->getMessage(), $exception->getCode());
        }
    }
}
