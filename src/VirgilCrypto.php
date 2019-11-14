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

namespace Virgil\CryptoImpl;

use Virgil\CryptoImpl\Core\DataInterface;
use Virgil\CryptoImpl\Core\HashAlgorithms;
use Virgil\CryptoImpl\Core\InputOutput;
use Virgil\CryptoImpl\Core\PublicKeyList;
use Virgil\CryptoImpl\Core\SigningMode;
use Virgil\CryptoImpl\Core\InputStream;
use Virgil\CryptoImpl\Core\VerifyingMode;
use Virgil\CryptoImpl\Core\VirgilKeyPair;
use Virgil\CryptoImpl\Exceptions\VirgilCryptoException;
use Virgil\CryptoImpl\Core\KeyPairType;
use Virgil\CryptoImpl\Core\SigningOptions;
use Virgil\CryptoImpl\Core\VerifyingOptions;
use Virgil\CryptoImpl\Services\VirgilCryptoService;
use Virgil\CryptoImpl\Core\VirgilPrivateKey;
use Virgil\CryptoImpl\Core\VirgilPublicKey;
use VirgilCrypto\Foundation\Random;

/**
 * Wrapper for cryptographic operations.
 * Class provides a cryptographic operations in applications, such as hashing,
 * signature generation and verification, and encryption and decryption
 * Class VirgilCrypto
 *
 * @package Virgil\CryptoImpl
 */
class VirgilCrypto
{
    /**
     * @var KeyPairType
     */
    private $defaultKeyType;

    /**
     * @var bool
     */
    private $useSHA256Fingerprints;

    /**
     * @var int
     */
    private $chunkSize = 1024;

    /**
     * VirgilCrypto constructor.
     *
     * @param KeyPairType|null $defaultKeyType
     * @param bool $useSHA256Fingerprints
     *
     */
    public function __construct(KeyPairType $defaultKeyType = null, bool $useSHA256Fingerprints = false)
    {
        $this->defaultKeyType = is_null($defaultKeyType) ? KeyPairType::ED25519() : $defaultKeyType;
        $this->useSHA256Fingerprints = $useSHA256Fingerprints;
    }

    /**
     * @return VirgilCryptoService
     */
    private function getCryptoService(): VirgilCryptoService
    {
        return new VirgilCryptoService($this->defaultKeyType, $this->useSHA256Fingerprints);
    }

    /**
     * @param KeyPairType|null $type
     * @param Random|null $rng
     *
     * @return VirgilKeyPair
     * @throws VirgilCryptoException
     */
    public function generateKeyPair(KeyPairType $type = null, Random $rng = null): VirgilKeyPair
    {
        return $this->getCryptoService()->generateKeyPair($type, $rng);
    }

    /**
     * @param string $data
     * @param VirgilPrivateKey $virgilPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateSignature(string $data, VirgilPrivateKey $virgilPrivateKey): string
    {
        return $this->getCryptoService()->generateSignature($data, $virgilPrivateKey);
    }

    /**
     * Verifies digital signature of data
     * - Note: Verification algorithm depends on PublicKey type. Default: EdDSA for ed25519 key
     *
     * @param string $signature
     * @param string $data
     * @param VirgilPublicKey $virgilPublicKey
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    public function verifySignature(string $signature, string $data, VirgilPublicKey $virgilPublicKey): bool
    {
        return $this->getCryptoService()->verifySignature($signature, $data, $virgilPublicKey);
    }

    /**
     *
     * Encrypts data (or stream data) for passed PublicKeys
     *
     * 1. Generates random AES-256 KEY1
     * 2. Encrypts data with KEY1 using AES-256-GCM
     * 3. Generates ephemeral key pair for each recipient
     * 4. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key
     * 5. Computes KDF to obtain AES-256 key from shared secret for each recipient
     * 6. Encrypts KEY1 with this key using AES-256-CBC for each recipient
     *
     * @param InputOutput $inputOutput
     * @param PublicKeyList $recipients
     * @param SigningOptions|null $signingOptions
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    public function encrypt(InputOutput $inputOutput, PublicKeyList $recipients, SigningOptions $signingOptions = null): ?string
    {
        return $this->getCryptoService()->encrypt($inputOutput, $recipients, $signingOptions);
    }

    /**
     *  Decrypts data using passed PrivateKey
     *
     * 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
     * 2. Computes KDF to obtain AES-256 KEY2 from shared secret
     * 3. Decrypts KEY1 using AES-256-CBC
     * 4. Decrypts data using KEY1 and AES-256-GCM
     *
     * ============================================
     *
     * Decrypts data stream using passed PrivateKey
     *
     * - Note: Decrypted stream should not be used until decryption of whole InputStream completed due to security
     * reasons
     *
     * 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
     * 2. Computes KDF to obtain AES-256 KEY2 from shared secret
     * 3. Decrypts KEY1 using AES-256-CBC
     * 4. Decrypts data using KEY1 and AES-256-GCM
     *
     * @param InputOutput $inputOutput
     * @param VirgilPrivateKey $privateKey
     * @param VerifyingOptions|null $verifyingOptions
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function decrypt(InputOutput $inputOutput, VirgilPrivateKey $privateKey, VerifyingOptions $verifyingOptions = null): string
    {
        return $this->getCryptoService()->decrypt($inputOutput, $privateKey, $verifyingOptions);
    }

    /**
     * @param string $data
     * @param HashAlgorithms $algorithm
     *
     * @return null|string
     */
    public function computeHash(string $data, HashAlgorithms $algorithm): ?string
    {
        return $this->getCryptoService()->computeHash($data, $algorithm);
    }

    /**
     * @param VirgilPublicKey $publicKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function exportPublicKey(VirgilPublicKey $publicKey) :string
    {
        return $this->getCryptoService()->exportPublicKey($publicKey);
    }

    /**
     * @param string $data
     *
     * @return VirgilKeyPair
     * @throws VirgilCryptoException
     */
    public function importPrivateKey(string $data): VirgilKeyPair
    {
        return $this->getCryptoService()->importPrivateKey($data);
    }

    /**
     * Imports public key from DER or PEM format
     *
     * @param string $data
     *
     * @return VirgilPublicKey
     * @throws VirgilCryptoException
     */
    public function importPublicKey(string $data): VirgilPublicKey
    {
        return $this->getCryptoService()->importPublicKey($data);
    }

    /**
     * Export private key
     *
     * @param VirgilPrivateKey $privateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function exportPrivateKey(VirgilPrivateKey $privateKey): string
    {
        return $this->getCryptoService()->exportPrivateKey($privateKey);
    }

    /**
     * @param DataInterface $data
     * @param PublicKeyList $recipients
     * @param VirgilPrivateKey $privateKey
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    public function signAndEncrypt(DataInterface $data, VirgilPrivateKey $privateKey, PublicKeyList $recipients): ?string
    {
        return $this->getCryptoService()->encrypt($data, $recipients, new SigningOptions($privateKey, SigningMode::SIGN_AND_ENCRYPT()));
    }

    /**
     * @param DataInterface $data
     * @param VirgilPrivateKey $privateKey
     * @param PublicKeyList $signersPublicKeys
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function decryptAndVerify(DataInterface $data, VirgilPrivateKey $privateKey, PublicKeyList $signersPublicKeys)
    {
        return $this->getCryptoService()->decrypt($data, $privateKey, new VerifyingOptions($signersPublicKeys,
            VerifyingMode::DECRYPT_AND_VERIFY()));
    }

    /**
     * @param InputStream $inputStream
     * @param VirgilPrivateKey $virgilPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateStreamSignature(InputStream $inputStream, VirgilPrivateKey $virgilPrivateKey): string
    {
        return $this->getCryptoService()->generateStreamSignature($inputStream, $virgilPrivateKey);
    }
}
