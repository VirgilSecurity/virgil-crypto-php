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

namespace Virgil\CryptoImpl;


use Virgil\CryptoImpl\Cryptography\Core\Cipher\CipherInterface;
use Virgil\CryptoImpl\Cryptography\Core\Cipher\InputOutputInterface;
use Virgil\CryptoImpl\Cryptography\Core\VirgilCryptoService;


/**
 * Class VirgilCrypto
 * @package Virgil\CryptoImpl
 */
class VirgilCrypto
{
    /**
     * @var string
     */
    protected $keyPairType;

    /**
     * @var VirgilCryptoService
     */
    protected $cryptoService;

    /**
     * @var bool
     */
    private $userSHA256Fingerprints;


    /**
     * Class constructor.
     *
     * @param string $keyPairType
     * @param bool   $userSHA256Fingerprints
     */
    public function __construct(
        $keyPairType = KeyPairTypes::FAST_EC_ED25519,
        $userSHA256Fingerprints = false
    ) {
        $this->keyPairType = $keyPairType;
        $this->userSHA256Fingerprints = $userSHA256Fingerprints;

        $this->cryptoService = new VirgilCryptoService();
    }


    /**
     * @param integer $keyPairType
     *
     * @return VirgilKeyPair
     * @throws Cryptography\Core\Exceptions\KeyPairGenerationException
     * @throws Cryptography\Core\Exceptions\PrivateKeyToDerConvertingException
     * @throws Cryptography\Core\Exceptions\PublicKeyHashComputationException
     * @throws Cryptography\Core\Exceptions\PublicKeyToDerConvertingException
     */
    public function generateKeys($keyPairType = null)
    {
        if ($keyPairType == null) {
            $keyPairType = $this->keyPairType;
        }
        $keyPair = $this->cryptoService->generateKeyPair($keyPairType);

        $publicKeyDerEncoded = $this->cryptoService->publicKeyToDer($keyPair[0]);
        $privateKeyDerEncoded = $this->cryptoService->privateKeyToDer($keyPair[1]);

        $receiverID = $this->calculateFingerprint($publicKeyDerEncoded);

        $virgilPublicKey = new VirgilPublicKey($receiverID, $publicKeyDerEncoded);
        $virgilPrivateKey = new VirgilPrivateKey($receiverID, $privateKeyDerEncoded);

        return new VirgilKeyPair($virgilPublicKey, $virgilPrivateKey);
    }


    /**
     * @param string           $encryptedAndSignedContent
     * @param VirgilPrivateKey $recipientPrivateKey
     * @param VirgilPublicKey  $signerPublicKey
     *
     * @return string
     */
    public function decryptThenVerify(
        $encryptedAndSignedContent,
        VirgilPrivateKey $recipientPrivateKey,
        VirgilPublicKey $signerPublicKey
    ) {
        return "";
    }


    /**
     * @param string            $content
     * @param VirgilPrivateKey  $signerPrivateKey
     * @param VirgilPublicKey[] $recipientsPublicKeys
     *
     * @return string
     */
    public function signThenEncrypt($content, VirgilPrivateKey $signerPrivateKey, array $recipientsPublicKeys)
    {
        return "";
    }


    /**
     * @param string          $content
     * @param string          $signature
     * @param VirgilPublicKey $signerPublicKey
     *
     * @return bool
     */
    public function verifySignature($content, $signature, VirgilPublicKey $signerPublicKey)
    {
        return false;
    }


    /**
     * @param resource        $source
     * @param string          $signature
     * @param VirgilPublicKey $signerPublicKey
     *
     * @return bool
     */
    public function verifyStreamSignature($source, $signature, VirgilPublicKey $signerPublicKey)
    {
        return false;
    }


    /**
     * @param string           $content
     * @param VirgilPrivateKey $signerPrivateKey
     *
     * @return string
     */
    public function generateSignature($content, VirgilPrivateKey $signerPrivateKey)
    {
        return "";
    }


    /**
     * @param resource         $content
     * @param VirgilPrivateKey $signerPrivateKey
     *
     * @return string
     */
    public function generateStreamSignature($content, VirgilPrivateKey $signerPrivateKey)
    {
        return "";
    }


    /**
     * @param string           $encryptedContent
     * @param VirgilPrivateKey $recipientPrivateKey
     *
     * @return string
     * @throws Cryptography\Core\Exceptions\CipherException
     */
    public function decrypt($encryptedContent, VirgilPrivateKey $recipientPrivateKey)
    {
        $cipher = $this->cryptoService->createCipher();
        $cipherInputOutput = $cipher->createInputOutput($encryptedContent);

        return $cipher->decryptWithKey(
            $cipherInputOutput,
            $recipientPrivateKey->getReceiverID(),
            $recipientPrivateKey->getValue()
        );
    }


    /**
     * @param resource         $source
     * @param VirgilPrivateKey $recipientPrivateKey
     *
     * @return resource
     */
    public function decryptStream($source, VirgilPrivateKey $recipientPrivateKey)
    {
        return "";
    }


    /**
     * @param string            $content
     * @param VirgilPublicKey[] $recipientsPublicKeys
     *
     * @return string
     * @throws Cryptography\Core\Exceptions\CipherException
     */
    public function encrypt($content, array $recipientsPublicKeys)
    {
        $cipher = $this->cryptoService->createCipher();
        $cipherInputOutput = $cipher->createInputOutput($content);

        foreach ($recipientsPublicKeys as $recipientPublicKey) {
            $cipher->addKeyRecipient(
                $recipientPublicKey->getReceiverID(),
                $recipientPublicKey->getValue()
            );
        }

        return $cipher->encrypt($cipherInputOutput);
    }


    /**
     * @param resource          $source
     * @param VirgilPublicKey[] $recipientsPublicKeys
     *
     * @return resource
     */
    public function encryptStream($source, array $recipientsPublicKeys)
    {
        return "";
    }


    /**
     * @param string $content
     * @param string $algorithm
     *
     * @return string
     */
    public function generateHash($content, $algorithm)
    {
        return "";
    }


    /**
     * @param string $exportedPublicKey
     *
     * @return VirgilPublicKey
     */
    public function importPublicKey($exportedPublicKey)
    {
        return new VirgilPublicKey();
    }


    /**
     * @param string $exportedPrivateKey
     * @param string $password
     *
     * @return VirgilPrivateKey
     */
    public function importPrivateKey($exportedPrivateKey, $password = '')
    {
        return new VirgilPrivateKey();
    }


    /**
     * @param VirgilPublicKey $publicKey
     *
     * @return string
     */
    public function exportPublicKey(VirgilPublicKey $publicKey)
    {
        return "";
    }


    /**
     * @param VirgilPrivateKey $privateKey
     * @param string           $password
     *
     * @return string
     */
    public function exportPrivateKey(VirgilPrivateKey $privateKey, $password = '')
    {
        return "";
    }


    /**
     * @param $content
     *
     * @return string
     * @throws Cryptography\Core\Exceptions\PublicKeyHashComputationException
     */
    protected function calculateFingerprint($content)
    {
        if ($this->userSHA256Fingerprints) {
            $hash = $this->cryptoService->computeHash($content, HashAlgorithms::SHA256);
        } else {
            $hash = $this->cryptoService->computeHash($content, HashAlgorithms::SHA512);
            $hash = substr($hash, 0, 8);
        }

        return bin2hex($hash);
    }
}
