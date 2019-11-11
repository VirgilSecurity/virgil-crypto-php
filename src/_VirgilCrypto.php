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

#namespace Virgil\CryptoImpl;

use Virgil\CryptoImpl\Exceptions\VirgilCryptoException;
use VirgilCrypto\Foundation\Aes256Gcm;
use VirgilCrypto\Foundation\KeyMaterialRng;
use VirgilCrypto\Foundation\PublicKey;
use VirgilCrypto\Foundation\RecipientCipher;
use VirgilCrypto\Foundation\RsaPrivateKey;
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
     * @var null|KeyPairType|VirgilKeyType
     */
    protected $vKeyPairType;

    /**
     * @var bool
     */
    private $useSHA256Fingerprints;

    /**
     * @var int
     */
    private $chunkSize = 1024;

    /**
     * @var VirgilCryptoService
     */
    private $vCryptoService;

    /**
     * VirgilCrypto constructor.
     *
     * @param KeyPairType|null $vKeyPairType
     * @param bool $useSHA256Fingerprints
     *
     * @throws Exception
     */
    public function __construct(KeyPairType $vKeyPairType = null, bool $useSHA256Fingerprints = false) {
        $this->vKeyPairType = is_null($vKeyPairType) ? (new KeyPairType())->getED25519() : $vKeyPairType;
        $this->useSHA256Fingerprints = $useSHA256Fingerprints;

        $this->vCryptoService = new VirgilCryptoService();
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
    public function generateSignature(string $data, VirgilPrivateKey $vPrivateKey): string
    {
        try {
            $signer = new Signer();
            $hash = new Sha512();

            $random = $this->vCryptoService->getCtrDrbg();

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
    public function verifySignature(string $data, string $signature, VirgilPublicKey $vPublicKey)
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
    public function exportPublicKey(VirgilPublicKey $vPublicKey)
    {
        try {
            $random = $this->vCryptoService->getCtrDrbg(false);
            $keyProvider = $this->vCryptoService->getKeyProvider($random);

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
            $random = $this->vCryptoService->getCtrDrbg();
            $keyProvider = $this->vCryptoService->getKeyProvider($random);
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
            $keyProvider = $this->vCryptoService->getKeyProvider();
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

    /**
     * Exports private key to DER format
     *
     * @param VirgilPrivateKey $vPrivateKey
     * @param string $password
     *
     * @return string
     * @throws VirgilCryptoException
     */
    // TODO! password?
    public function exportPrivateKey(VirgilPrivateKey $vPrivateKey, string $password): string
    {
        try {
            $random = $this->vCryptoService->getCtrDrbg(false);
            $keyProvider = $this->vCryptoService->getKeyProvider($random);

            $res = $keyProvider->exportPrivateKey($vPrivateKey->getPrivateKey());

            return $res;
        } catch (\Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Imports private key from DER or PEM format
     *
     * @param string $data
     * @param string $password
     *
     * @return VirgilKeyPair
     * @throws VirgilCryptoException
     */
    // TODO! password?
    public function importPrivateKey(string $data, string $password): VirgilKeyPair
    {
        try {
            $random = $this->vCryptoService->getCtrDrbg();
            $keyProvider = $this->vCryptoService->getKeyProvider($random);

            $privateKey = $keyProvider->importPrivateKey($data);

            $bitLen = null;
            if($privateKey instanceof RsaPrivateKey)
                $bitLen = $privateKey->bitlen();

            $keyType = new VirgilKeyType($privateKey->algId(), $bitLen);

            $publicKey = $privateKey->extractPublicKey();

            $keyId = $this->computePublicKeyIdentifier($publicKey);

            $vPublicKey = new VirgilPublicKey($keyId, $publicKey, $keyType);
            $vPrivateKey = new VirgilPrivateKey($keyId, $privateKey, $keyType);

            $vKeyPair = new VirgilKeyPair($vPublicKey, $vPrivateKey);

            return $vKeyPair;
        } catch (\Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Encrypts the specified data using recipients Public keys.
     *
     * @param string $data
     * @param array $vPublicKeys
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function encrypt(string $data, array $vPublicKeys): string
    {
        try {
            $random = $this->vCryptoService->getCtrDrbg();

            $aesGcm = new Aes256Gcm();
            $cipher = new RecipientCipher();
            $cipher->useEncryptionCipher($aesGcm);
            $cipher->useRandom($random);

            foreach ($vPublicKeys as $vPublicKey) {
                if(!$vPublicKey instanceof VirgilPublicKey)
                    throw new VirgilCryptoException("Invalid type of the VirgilPublicKey");

                $cipher->addKeyRecipient($vPublicKey->getIdentifier(), $vPublicKey->getPublicKey());
            }

            $cipher->startEncryption();
            $res = $cipher->packMessageInfo();
            $res .= $cipher->processEncryption($data);
            $res .= $cipher->finishEncryption();

            return $res;

        } catch (\Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Decrypts the specified data using Private key.
     *
     * @param string $data
     * @param VirgilPrivateKey $vPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function decrypt(string $data, VirgilPrivateKey $vPrivateKey): string
    {
        try {
            $messageInfo = "";

            $random = $this->vCryptoService->getCtrDrbg();
            $cipher = new RecipientCipher();
            $cipher->useRandom($random);
            $cipher->startDecryptionWithKey($vPrivateKey->getIdentifier(), $vPrivateKey->getPrivateKey(), $messageInfo);

            $res = $messageInfo;
            $res .= $cipher->processDecryption($data);
            $res .= $cipher->finishDecryption();

            return $res;

        } catch (\Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Encrypts the specified stream using recipients Public keys.
     *
     * @param StreamInput $streamInput
     * @param StreamOutput $streamOutput
     * @param array $vPublicKeys
     *
     * @return StreamOutput
     * @throws VirgilCryptoException
     */
    public function encryptStream(StreamInput $streamInput, StreamOutput $streamOutput, array $vPublicKeys): StreamOutput
    {
        try {
            $random = $this->vCryptoService->getCtrDrbg();
            $aesGcm = new Aes256Gcm();
            $cipher = new RecipientCipher();
            $cipher->useEncryptionCipher($aesGcm);
            $cipher->useRandom($random);

            foreach ($vPublicKeys as $vPublicKey) {
                if(!$vPublicKey instanceof VirgilPublicKey)
                    throw new VirgilCryptoException("Invalid type of the VirgilPublicKey");

                $cipher->addKeyRecipient($vPublicKey->getIdentifier(), $vPublicKey->getPublicKey());
            }

            $cipher->startEncryption();
            $messageInfo = $cipher->packMessageInfo();

            $cipher->startEncryption();

            // TODO! Need to be implemented!

            $finish = $cipher->finishEncryption();

            return $streamOutput;

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Decrypts the specified stream using Private key.
     *
     * @param StreamInput $streamInput
     * @param StreamOutput $streamOutput
     * @param VirgilPrivateKey $vPrivateKey
     *
     * @return StreamOutput
     * @throws Exception
     */
    public function decryptStream(StreamInput $streamInput, StreamOutput $streamOutput, VirgilPrivateKey $vPrivateKey): StreamOutput
    {
        $messageInfo = "";
        $cipher = new RecipientCipher();
        $cipher->startDecryptionWithKey($vPrivateKey->getIdentifier(), $vPrivateKey->getPrivateKey(), $messageInfo);

        // TODO!
        $finish = $cipher->finishDecryption();

        return $streamOutput;
    }

    /**
     * Signs the specified stream using Private key.
     *
     * @param StreamInput $streamInput
     * @param VirgilPrivateKey $vPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateStreamSignature(StreamInput $streamInput, VirgilPrivateKey $vPrivateKey): string
    {
        try {
            $random = $this->vCryptoService->getCtrDrbg();
            $signer = new Signer();
            $signer->useRandom($random);
            $hash = new Sha512();
            $signer->useHash($hash);
            $signer->reset();

            // TODO!
            // foreach $streamInput->getChunk()
            // $signer->appendData($chunkData);

            $signature = $signer->sign($vPrivateKey->getPrivateKey());

            return $signature;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Verifies the specified signature using original stream and signer's Public key.
     *
     * @param StreamInput $streamInput
     * @param string $signature
     * @param VirgilPublicKey $vPublicKey
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    public function verifyStreamSignature(string $signature, StreamInput $streamInput, VirgilPublicKey $vPublicKey): bool
    {
        try {
            $verifier = new Verifier();
            $verifier->reset($signature);

            // TODO!
            // foreach $streamInput->getChunk()
            // $signer->appendData($chunkData);

            $res = $verifier->verify($vPublicKey->getPublicKey());

            return $res;

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Signs then encrypts the data.
     *
     * @param string $data
     * @param VirgilPrivateKey $vPrivateKey
     * @param array $vPublicKeys
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function signThenEncrypt(string $data, VirgilPrivateKey $vPrivateKey, array $vPublicKeys): string
    {
        try {
            $random = $this->vCryptoService->getCtrDrbg();
            $signature = $this->generateSignature($data, $vPrivateKey);
            $aes256Gcm = new Aes256Gcm();

            $cipher = new RecipientCipher();
            $cipher->useEncryptionCipher($aes256Gcm);
            $cipher->useRandom($random);

            foreach ($vPublicKeys as $vPublicKey) {
                if(!$vPublicKey instanceof VirgilPublicKey)
                    throw new VirgilCryptoException("Invalid type of the VirgilPublicKey");

                $cipher->addKeyRecipient($vPublicKey->getIdentifier(), $vPublicKey->getPublicKey());
            }

            $customParams = $cipher->customParams();
            $customParams->addData(self::CUSTOM_PARAM_KEY_SIGNATURE, $signature);
            $customParams->addData(self::CUSTOM_PARAM_KEY_SIGNER_ID, $vPrivateKey->getIdentifier());

            $cipher->startEncryption();

            $res = $cipher->packMessageInfo();
            $res .= $cipher->processEncryption($data);
            $res .= $cipher->finishEncryption();

            return $res;

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Decrypts and verifies the data.
     *
     * @param string $data
     * @param VirgilPrivateKey $vPrivateKey
     * @param VirgilPublicKey $vPublicKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function decryptThenVefiry(string $data, VirgilPrivateKey $vPrivateKey, VirgilPublicKey $vPublicKey): string
    {
        try {
            $messageInfo = "";
            $cipher = new RecipientCipher();
            $cipher->startDecryptionWithKey($vPrivateKey->getIdentifier(), $vPrivateKey->getPrivateKey(), $messageInfo);

            $res = "";
            $res .= $cipher->processDecryption($data);
            $res .= $cipher->finishDecryption();

            $customParams = $cipher->customParams();
            $signature = $customParams->findData(self::CUSTOM_PARAM_KEY_SIGNATURE);

            $isValid = $this->verifySignature($res, $signature, $vPublicKey);

            if(!$isValid)
                throw new VirgilCryptoException("Signature not verified");

            return $res;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Generates asymmetric key pair that is comprised of both public and private keys by specified type.
     *
     * @param KeyPairType|null $vKeyPairType
     * @param string|null $seed
     *
     * @return VirgilKeyPair
     * @throws VirgilCryptoException
     */
    public function generateKeys(KeyPairType $vKeyPairType = null, string $seed = null): VirgilKeyPair
    {
        try {
            $this->vKeyPairType = is_null($vKeyPairType) ? (new KeyPairType())->getED25519() : $vKeyPairType;

            if($seed) {
                if (KeyMaterialRng::KEY_MATERIAL_LEN_MIN > strlen($seed) | strlen($seed) > KeyMaterialRng::KEY_MATERIAL_LEN_MAX)
                    throw new VirgilCryptoException("Invalid seed size");

                $keyMaterialRng = new KeyMaterialRng();
                $keyMaterialRng->resetKeyMaterial($seed);

                $random = $keyMaterialRng;
            } else {
                $random = $this->vCryptoService->getCtrDrbg();
            }

            $vKeyType = null;
            if($this->vKeyPairType->getRsaBitLen())
                $vKeyType = $this->vKeyPairType;

            $keyProvider = $this->vCryptoService->getKeyProvider($random, $vKeyType);

            $privateKey = $keyProvider->generatePrivateKey($this->vKeyPairType->getAlgId());
            $publicKey = $privateKey->extractPublicKey();

            $keyId = $this->computePublicKeyIdentifier($publicKey);

            $keyType = new VirgilKeyType($privateKey->algId());

            $vPublicKey = new VirgilPublicKey($keyId, $publicKey, $keyType);
            $vPrivateKey = new VirgilPrivateKey($keyId, $privateKey, $keyType);

            $res = new VirgilKeyPair($vPublicKey, $vPrivateKey);

            return $res;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }
}
