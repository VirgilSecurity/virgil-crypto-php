<?php
/**
 * Copyright (C) 2015-2019 Virgil Security Inc.
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

namespace Virgil\CryptoImpl;

use Virgil\CryptoImpl\Exceptions\VirgilCryptoException;
use VirgilCrypto\Foundation\CtrDrbg;
use VirgilCrypto\Foundation\KeyProvider;
use VirgilCrypto\Foundation\PublicKey;
use VirgilCrypto\Foundation\RsaPublicKey;
use VirgilCrypto\Foundation\Sha512;
use VirgilCrypto\Foundation\Signer;
use VirgilCrypto\Foundation\Verifier;
use \Exception;


/**
 *
 * Wrapper for cryptographic operations.
 * Class provides a cryptographic operations in applications, such as hashing,
 * signature generation and verification, and encryption and decryption
 *
 * Class VirgilCrypto
 * @package Virgil\CryptoImpl
 */
class VirgilCrypto
{
    const CUSTOM_PARAM_KEY_SIGNATURE = "VIRGIL-DATA-SIGNATURE";
    const CUSTOM_PARAM_KEY_SIGNER_ID = "VIRGIL-DATA-SIGNER-ID";

    /**
     * @var null|VirgilKeyPairType|VirgilKeyType
     */
    protected $vKeyPairType;

    /**
     * @var bool
     */
    private $useSHA256Fingerprints;

    /**
     * @var CtrDrbg
     */
    private $rng;

    /**
     * @var int
     */
    private $chunkSize = 1024;

    /**
     * VirgilCrypto constructor.
     *
     * @param VirgilKeyPairType|null $vKeyPairType
     * @param bool $useSHA256Fingerprints
     *
     * @throws Exception
     */
    public function __construct(VirgilKeyPairType $vKeyPairType = null, bool $useSHA256Fingerprints = false) {
        $this->vKeyPairType = is_null($vKeyPairType) ? (new VirgilKeyPairType())->getED25519() : $vKeyPairType;
        $this->useSHA256Fingerprints = $useSHA256Fingerprints;

        $rng = new CtrDrbg();
        $rng->setupDefaults();
        $this->rng = $rng;
    }

    /**
     * Generates digital signature of data using private key
     *
     * @param string $data
     * @param VirgilPrivateKey $vPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public static function generateSignature(string $data, VirgilPrivateKey $vPrivateKey): string
    {
        try {
            $signer = new Signer();

            $random = new CtrDrbg();

            $random->setupDefaults();
            $hash = new Sha512();

            $signer->useHash($hash);
            $signer->useRandom($random);
            $signer->reset();
            $signer->appendData($data);

            $signature = $signer->sign($vPrivateKey->getPrivateKey());

            return $signature;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Verifies the specified signature using original data and signer's public key.
     *
     * @param string $data
     * @param string $signature
     * @param VirgilPublicKey $vPublicKey
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    public static function verifySignature(string $data, string $signature, VirgilPublicKey $vPublicKey)
    {
        try {
            $verifier = new Verifier();
            $verifier->reset($signature);
            $verifier->appendData($data);

            $res = $verifier->verify($vPublicKey->getPublicKey());

            return $res;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Exports the Public key into material representation.
     *
     * @param VirgilPublicKey $vPublicKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public static function exportPublicKey(VirgilPublicKey $vPublicKey)
    {
        try {
            $keyProvider = new KeyProvider();
            $rand = new CtrDrbg();

            $keyProvider->useRandom($rand);
            $keyProvider->setupDefaults();

            $res = $keyProvider->exportPublicKey($vPublicKey->getPublicKey());

            return $res;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Imports the Public key from material representation.
     *
     * @param string $keyData
     *
     * @return VirgilPublicKey
     * @throws Exception
     */
    public function importPublicKey(string $keyData)
    {
        try {
            $keyProvider = new KeyProvider();
            $keyProvider->useRandom($this->rng);
            $keyProvider->setupDefaults();

            $publicKey = $keyProvider->importPublicKey($keyData);

            $bitLen = null;
            if($publicKey instanceof RsaPublicKey)
                $bitLen = $publicKey->bitlen();

            $keyType = new VirgilKeyType($publicKey->algId(), $bitLen);

            $keyId = $this->computePublicKeyIdentifier($publicKey);

            $vPublicKey = new VirgilPublicKey($keyId, $publicKey, $keyType);

            return $vPublicKey;
        } catch (\Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Computes public key identifier.
     * Note: Takes first 8 bytes of SHA512 of public key DER if use_sha256_fingerprints=false
     * and SHA256 of public key der if use_sha256_fingerprints=true
     *
     * @param PublicKey $publicKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    private function computePublicKeyIdentifier(PublicKey $publicKey): string
    {
        try {
            $keyProvider = new KeyProvider();
            $keyProvider->setupDefaults();

            $publicKeyData = $keyProvider->exportPublicKey($publicKey);

            if ($this->useSHA256Fingerprints) {
                $res = $this->computeHash($publicKeyData, VirgilHashAlgorithms::SHA256());
            } else {
                $res = $this->computeHash($publicKeyData);
                $res = substr($res, 0, 8);
            }

            return $res;
        } catch (\Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Computes the hash of specified data.
     *
     * @param string $data
     * @param VirgilHashAlgorithms|null $vHashAlgorithm
     *
     * @return string
     */
    private function computeHash(string $data, VirgilHashAlgorithms $vHashAlgorithm = null): string
    {
        $vHashAlgorithm = is_null($vHashAlgorithm) ? VirgilHashAlgorithms::SHA512() : $vHashAlgorithm;
        $nativeAlgorithm = VirgilHashAlgorithms::convertToNative($vHashAlgorithm);
        // TODO! Need to be fixed ASAP! Only for POC!
        $nativeHasher = new $nativeAlgorithm();
        $hash = $nativeHasher->hash($data);

        return $hash;
    }
}
