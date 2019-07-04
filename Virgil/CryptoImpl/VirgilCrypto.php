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


use Exception;

use Virgil\CryptoImpl\Cryptography\VirgilCryptoService;


/**
 * Class VirgilCrypto
 * @package Virgil\CryptoImpl
 */
class VirgilCrypto
{
    const CUSTOM_PARAM_KEY_SIGNATURE = 'VIRGIL-DATA-SIGNATURE';

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
     * @throws VirgilCryptoException
     */
    public function generateKeys($keyPairType = null)
    {
        try {
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
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param string            $encryptedAndSignedContent
     * @param VirgilPrivateKey  $recipientPrivateKey
     * @param VirgilPublicKey[] $signerPublicKeys
     *
     * @return string
     *
     * @throws VirgilCryptoException
     * @throws SignatureIsNotValidException
     */
    public function decryptThenVerify(
        $encryptedAndSignedContent,
        VirgilPrivateKey $recipientPrivateKey,
        array $signerPublicKeys
    ) {
        try {
            $cipher = $this->cryptoService->createCipher();
            $cipherInputOutput = $cipher->createInputOutput($encryptedAndSignedContent);

            $decryptedContent = $cipher->decryptWithKey(
                $cipherInputOutput,
                $recipientPrivateKey->getReceiverID(),
                $recipientPrivateKey->getValue()
            );

            $signature = $cipher->getCustomParam(self::CUSTOM_PARAM_KEY_SIGNATURE);

            $isSignatureValid = false;
            foreach ($signerPublicKeys as $signerPublicKey) {
                if ($this->verifySignature($decryptedContent, $signature, $signerPublicKey)) {
                    $isSignatureValid = true;
                }
            }

            if (!$isSignatureValid) {
                throw new SignatureIsNotValidException('signature is not valid');
            }

            return $decryptedContent;
        } catch (SignatureIsNotValidException $exception) {
            throw new SignatureIsNotValidException($exception->getMessage());
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param string            $content
     * @param VirgilPrivateKey  $signerPrivateKey
     * @param VirgilPublicKey[] $recipientsPublicKeys
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function signThenEncrypt($content, VirgilPrivateKey $signerPrivateKey, array $recipientsPublicKeys)
    {
        try {
            $cipher = $this->cryptoService->createCipher();
            $cipherInputOutput = $cipher->createInputOutput($content);

            $signature = $this->generateSignature($content, $signerPrivateKey);
            $cipher->setCustomParam(self::CUSTOM_PARAM_KEY_SIGNATURE, $signature);

            foreach ($recipientsPublicKeys as $recipientPublicKey) {
                $cipher->addKeyRecipient(
                    $recipientPublicKey->getReceiverID(),
                    $recipientPublicKey->getValue()
                );
            }

            return $cipher->encrypt($cipherInputOutput);

        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param string          $content
     * @param string          $signature
     * @param VirgilPublicKey $signerPublicKey
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    public function verifySignature($content, $signature, VirgilPublicKey $signerPublicKey)
    {
        try {
            return $this->cryptoService->verify(
                $content,
                $signature,
                $signerPublicKey->getValue()
            );
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param resource        $source
     * @param string          $signature
     * @param VirgilPublicKey $signerPublicKey
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    public function verifyStreamSignature($source, $signature, VirgilPublicKey $signerPublicKey)
    {
        try {
            return $this->cryptoService->verifyStream($source, $signature, $signerPublicKey->getValue());
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param string           $content
     * @param VirgilPrivateKey $signerPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateSignature($content, VirgilPrivateKey $signerPrivateKey)
    {
        try {
            return $this->cryptoService->sign($content, $signerPrivateKey->getValue());
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param resource         $source
     * @param VirgilPrivateKey $signerPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateStreamSignature($source, VirgilPrivateKey $signerPrivateKey)
    {
        try {
            return $this->cryptoService->signStream($source, $signerPrivateKey->getValue());
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param string           $encryptedContent
     * @param VirgilPrivateKey $recipientPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function decrypt($encryptedContent, VirgilPrivateKey $recipientPrivateKey)
    {
        try {
            $cipher = $this->cryptoService->createCipher();
            $cipherInputOutput = $cipher->createInputOutput($encryptedContent);

            return $cipher->decryptWithKey(
                $cipherInputOutput,
                $recipientPrivateKey->getReceiverID(),
                $recipientPrivateKey->getValue()
            );
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param resource         $source
     * @param resource         $sin
     * @param VirgilPrivateKey $recipientPrivateKey
     *
     * @throws VirgilCryptoException
     */
    public function decryptStream($source, $sin, VirgilPrivateKey $recipientPrivateKey)
    {
        try {
            $cipher = $this->cryptoService->createStreamCipher();
            $cipherInputOutput = $cipher->createInputOutput($source, $sin);

            $cipher->decryptWithKey(
                $cipherInputOutput,
                $recipientPrivateKey->getReceiverID(),
                $recipientPrivateKey->getValue()
            );

        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param string            $content
     * @param VirgilPublicKey[] $recipientsPublicKeys
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function encrypt($content, array $recipientsPublicKeys)
    {
        try {
            $cipher = $this->cryptoService->createCipher();
            $cipherInputOutput = $cipher->createInputOutput($content);

            foreach ($recipientsPublicKeys as $recipientPublicKey) {
                $cipher->addKeyRecipient(
                    $recipientPublicKey->getReceiverID(),
                    $recipientPublicKey->getValue()
                );
            }

            return $cipher->encrypt($cipherInputOutput);
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param resource          $source
     * @param resource          $sin
     * @param VirgilPublicKey[] $recipientsPublicKeys
     *
     * @throws VirgilCryptoException
     */
    public function encryptStream($source, $sin, array $recipientsPublicKeys)
    {
        try {
            $cipher = $this->cryptoService->createStreamCipher();
            $cipherInputOutput = $cipher->createInputOutput($source, $sin);

            foreach ($recipientsPublicKeys as $recipientPublicKey) {
                $cipher->addKeyRecipient(
                    $recipientPublicKey->getReceiverID(),
                    $recipientPublicKey->getValue()
                );
            }

            $cipher->encrypt($cipherInputOutput);
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param string $content
     * @param string $algorithm
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateHash($content, $algorithm)
    {
        try {
            return $this->cryptoService->computeHash($content, $algorithm);

        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param string $exportedPublicKey
     *
     * @return VirgilPublicKey
     * @throws VirgilCryptoException
     */
    public function importPublicKey($exportedPublicKey)
    {
        try {
            $publicKeyDerEncoded = $this->cryptoService->publicKeyToDer($exportedPublicKey);
            $receiverID = $this->calculateFingerprint($publicKeyDerEncoded);

            return new VirgilPublicKey($receiverID, $publicKeyDerEncoded);

        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param string $exportedPrivateKey
     * @param string $password
     *
     * @return VirgilPrivateKey
     * @throws VirgilCryptoException
     */
    public function importPrivateKey($exportedPrivateKey, $password = '')
    {
        try {
            $privateKeyDER = \VirgilKeyPair::privateKeyToDER($exportedPrivateKey, $password);

            $privateKeyDerEncoded = $this->cryptoService->decryptPrivateKey($privateKeyDER, $password);
            $receiverID = $this->calculateFingerprint(
                $this->cryptoService->extractPublicKey($privateKeyDerEncoded, $password)
            );

            return new VirgilPrivateKey($receiverID, $privateKeyDerEncoded);
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param VirgilPublicKey $publicKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function exportPublicKey(VirgilPublicKey $publicKey)
    {
        try {
            return $this->cryptoService->publicKeyToDer($publicKey->getValue());
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param VirgilPrivateKey $privateKey
     * @param string           $password
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function exportPrivateKey(VirgilPrivateKey $privateKey, $password = '')
    {
        try {
            return $this->cryptoService->privateKeyToDer($privateKey->getValue(), $password);
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param VirgilPrivateKey $privateKey
     * @param string           $password
     *
     * @return VirgilPublicKey
     * @throws VirgilCryptoException
     */
    public function extractPublicKey(VirgilPrivateKey $privateKey, $password = '')
    {
        try {
            $publicKeyData = $this->cryptoService->extractPublicKey($privateKey->getValue(), $password);

            return $this->importPublicKey($publicKeyData);
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }


    /**
     * @param $content
     *
     * @return string
     * @throws VirgilCryptoException
     */
    protected function calculateFingerprint($content)
    {
        try {
            if ($this->userSHA256Fingerprints) {
                $hash = $this->cryptoService->computeHash($content, HashAlgorithms::SHA256);
            } else {
                $hash = $this->cryptoService->computeHash($content, HashAlgorithms::SHA512);
                $hash = substr($hash, 0, 8);
            }

            return $hash;
        } catch (Exception $exception) {
            throw new VirgilCryptoException($exception->getMessage());
        }
    }
}
