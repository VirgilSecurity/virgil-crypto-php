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

namespace Virgil\CryptoImpl\Services;

use \Exception;
use Virgil\CryptoImpl\Core\Data;
use Virgil\CryptoImpl\Core\DataInterface;
use Virgil\CryptoImpl\Core\HashAlgorithms;
use Virgil\CryptoImpl\Core\PublicKeyList;
use Virgil\CryptoImpl\Core\SigningOptions;
use Virgil\CryptoImpl\Core\InputStream;
use Virgil\CryptoImpl\Core\StreamInterface;
use Virgil\CryptoImpl\Core\VerifyingOptions;
use Virgil\CryptoImpl\Exceptions\VirgilCryptoException;
use Virgil\CryptoImpl\Core\InputOutput;
use Virgil\CryptoImpl\Core\KeyPairType;
use Virgil\CryptoImpl\Core\SigningMode;
use Virgil\CryptoImpl\Core\Stream;
use Virgil\CryptoImpl\Core\VerifyingMode;
use Virgil\CryptoImpl\Core\VirgilCryptoError;
use Virgil\CryptoImpl\Core\VirgilKeyPair;
use Virgil\CryptoImpl\Core\VirgilPrivateKey;
use Virgil\CryptoImpl\Core\VirgilPublicKey;
use VirgilCrypto\Foundation\Aes256Gcm;
use VirgilCrypto\Foundation\AlgId;
use VirgilCrypto\Foundation\CtrDrbg;
use VirgilCrypto\Foundation\KeyMaterialRng;
use VirgilCrypto\Foundation\KeyProvider;
use VirgilCrypto\Foundation\PrivateKey;
use VirgilCrypto\Foundation\PublicKey;
use VirgilCrypto\Foundation\Random;
use VirgilCrypto\Foundation\RecipientCipher;
use VirgilCrypto\Foundation\Sha224;
use VirgilCrypto\Foundation\Sha256;
use VirgilCrypto\Foundation\Sha384;
use VirgilCrypto\Foundation\Sha512;
use VirgilCrypto\Foundation\Signer;
use VirgilCrypto\Foundation\Verifier;

/**
 * Class VirgilCryptoService
 *
 * @package Virgil\CryptoImpl\Services
 */
class VirgilCryptoService
{
    /**
     * @var
     */
    private $defaultKeyType;

    /**
     * @var
     */
    private $useSHA256Fingerprints;

    /**
     * @var
     */
    private $chunkSize;

    private const CUSTOM_PARAM_KEY_SIGNATURE = "VIRGIL-DATA-SIGNATURE";
    private const CUSTOM_PARAM_KEY_SIGNER_ID = "VIRGIL-DATA-SIGNER-ID";

    /**
     * VirgilCryptoService constructor.
     *
     * @param KeyPairType $defaultKeyType
     * @param bool $useSHA256Fingerprints
     * @param int $chunkSize
     */
    public function __construct(KeyPairType $defaultKeyType, bool $useSHA256Fingerprints, int $chunkSize)
    {
        $this->defaultKeyType = $defaultKeyType;
        $this->useSHA256Fingerprints = $useSHA256Fingerprints;
        $this->chunkSize = $chunkSize;
    }

    /**
     * @return CtrDrbg
     * @throws VirgilCryptoException
     */
    private function getRandom(): CtrDrbg
    {
        try {
            $rng = new CtrDrbg();
            $rng->setupDefaults();

            return $rng;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * @param PublicKey $publicKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    private function computePublicKeyIdentifier(PublicKey $publicKey): string
    {
        try {
            $publicKeyData = $this->exportInternalPublicKey($publicKey);

            $res = $this->computeHash($publicKeyData, HashAlgorithms::SHA256());

            if (!$this->useSHA256Fingerprints) {
                $res = substr($res, 0, 8);
            }

            return $res;

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * Generates KeyPair of default type using seed
     *
     * @param string $seed
     *
     * @return VirgilKeyPair
     * @throws VirgilCryptoException
     */
    public function generateKeyPairUsingSeed(string $seed): VirgilKeyPair
    {
        try {
            if (KeyMaterialRng::KEY_MATERIAL_LEN_MIN > strlen($seed) | KeyMaterialRng::KEY_MATERIAL_LEN_MAX < strlen($seed))
                throw new VirgilCryptoException(VirgilCryptoError::INVALID_SEED_SIZE());

            $seedRng = new KeyMaterialRng();
            $seedRng->resetKeyMaterial($seed);

            return $this->generateKeyPair($this->defaultKeyType, $seedRng);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
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
        try {
            $keyProvider = new KeyProvider();

            if (!$type)
                $type = $this->defaultKeyType;

            $bitLen = $type->getRsaBitLen($type);

            if ($bitLen)
                $keyProvider->setRsaParams($bitLen);

            if (!$rng)
                $rng = $this->getRandom();

            $keyProvider->useRandom($rng);
            $keyProvider->setupDefaults();

            $algId = $type->getAlgId($type);

            $privateKey = $keyProvider->generatePrivateKey($algId);
            $publicKey = $privateKey->extractPublicKey();
            $keyId = $this->computePublicKeyIdentifier($publicKey);

            $virgilPrivateKey = new VirgilPrivateKey($keyId, $privateKey, $type);
            $virgilPublicKey = new VirgilPublicKey($keyId, $publicKey, $type);

            return new VirgilKeyPair($virgilPrivateKey, $virgilPublicKey);

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * Generates digital signature of data using private key
     * - Note: Returned value contains only digital signature, not data itself.
     * - Note: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
     *   It's secure to pass raw data here.
     * - Note: Verification algorithm depends on PrivateKey type. Default: EdDSA for ed25519 key
     *
     * @param string $data
     * @param VirgilPrivateKey $virgilPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateSignature(string $data, VirgilPrivateKey $virgilPrivateKey): string
    {
        try {
            $signer = new Signer();
            $signer->useRandom($this->getRandom());
            $signer->useHash(new Sha512());

            $signer->reset();
            $signer->appendData($data);

            return $signer->sign($virgilPrivateKey->getPrivateKey());
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param InputOutput $inputOutput
     * @param SigningOptions|null $signingOptions
     *
     * @throws VirgilCryptoException
     */
    private function startEncryption(RecipientCipher $cipher, InputOutput $inputOutput, SigningOptions $signingOptions = null)
    {
        try {

            if ($signingOptions) {
                $signingMode = $signingOptions->getSigningMode();

                switch ($signingMode) {
                    case $signingMode::SIGN_AND_ENCRYPT():

                        switch ($inputOutput) {

                            case $inputOutput instanceof DataInterface:

                                $signature = $this->generateSignature($inputOutput->getInput(), $signingOptions->getVirgilPrivateKey());
                                $cipher->customParams()->addData(self::CUSTOM_PARAM_KEY_SIGNATURE, $signature);
                                $cipher->customParams()->addData(self::CUSTOM_PARAM_KEY_SIGNER_ID,
                                    $signingOptions->getVirgilPrivateKey()->getIdentifier());
                                break;

                            case $inputOutput instanceof StreamInterface:
                                throw new VirgilCryptoException("signAndEncrypt is not supported for streams");
                        }

                        $cipher->startEncryption();
                        break;

                    case $signingMode::SIGN_THEN_ENCRYPT():

                        $cipher->useSignerHash(new Sha512());
                        $cipher->addSigner($signingOptions->getVirgilPrivateKey()->getIdentifier(), $signingOptions->getVirgilPrivateKey()->getPrivateKey());

                        $size = null;

                        switch ($inputOutput) {

                            case $inputOutput instanceof DataInterface:

                                $size = strlen($inputOutput->getInput());
                                break;

                            case $inputOutput instanceof StreamInterface:

                                if (!$inputOutput->getStreamSize())
                                    throw new VirgilCryptoException("signThenEncrypt for streams with unknown size is not supported");

                                $size = $inputOutput->getStreamSize();
                                break;
                        }

                        $cipher->startSignedEncryption($size);
                        break;
                }

            } else {

                $cipher->startEncryption();

            }

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param InputOutput $inputOutput
     * @param SigningOptions|null $signingOptions
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    private function processEncryption(RecipientCipher $cipher, InputOutput $inputOutput, SigningOptions $signingOptions = null)
    {
        try {
            $result = null;

            switch ($inputOutput) {
                case $inputOutput instanceof Data:

                    $result = $cipher->packMessageInfo();
                    $result .= $cipher->processEncryption($inputOutput->getInput());
                    $result .= $cipher->finishEncryption();

                    if (($signingOptions) && ($signingOptions->getSigningMode() == SigningMode::SIGN_THEN_ENCRYPT()))
                        $result .= $cipher->packMessageInfoFooter();

                    break;

                case $inputOutput instanceof Stream:

                    // TODO!
                    //  if inputStream.streamStatus == .notOpen {
                    //      inputStream.open()
                    //  }
                    //  if outputStream.streamStatus == .notOpen {
                    //      outputStream.open()
                    //  }

                    StreamService::write($cipher->packMessageInfo(), $inputOutput->getOutput());
                    $data = StreamService::forEachChunk($inputOutput->getInput(), $inputOutput->getStreamSize());
                    StreamService::write($data, $inputOutput->getOutput());

                    StreamService::write($cipher->finishEncryption(), $inputOutput->getOutput());

                    if ($signingOptions->getSigningMode() == SigningMode::SIGN_THEN_ENCRYPT())
                        $this->streamUtils->write($cipher->packMessageInfoFooter(), $inputOutput->getOutput());

                    break;
            }

            return $result;


        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param InputOutput $inputOutput
     * @param PublicKeyList $recipients
     * @param SigningOptions|null $signingOptions
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    public function encrypt(InputOutput $inputOutput, PublicKeyList $recipients, SigningOptions $signingOptions = null)
    {
        try {

            $aesGcm = new Aes256Gcm();
            $cipher = new RecipientCipher();

            $cipher->useEncryptionCipher($aesGcm);
            $cipher->useRandom($this->getRandom());

            foreach ($recipients->getAsArray() as $recipient) {
                $cipher->addKeyRecipient($recipient->getIdentifier(), $recipient->getPublicKey());
            }

            $this->startEncryption($cipher, $inputOutput, $signingOptions);

            return $this->processEncryption($cipher, $inputOutput, $signingOptions);

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param InputOutput $inputOutput
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    private function processDecryption(RecipientCipher $cipher, InputOutput $inputOutput)
    {
        try {

            $result = null;

            switch ($inputOutput) {
                case $inputOutput instanceof StreamInterface:

                    // TODO!
                    //  if inputStream.streamStatus == .notOpen {
                    //      inputStream.open()
                    //  }
                    //  if outputStream.streamStatus == .notOpen {
                    //      outputStream.open()
                    //  }

                    $data = $this->streamUtils->forEachChunk($inputOutput->getInput(), null);
                    $this->streamUtils->write($data, $inputOutput->getOutput());
                    $this->streamUtils->write($cipher->finishDecryption(), $inputOutput->getOutput());

                    break;

                case $inputOutput instanceof DataInterface:

                    $result = $cipher->processDecryption($inputOutput->getInput());
                    $result .= $cipher->finishDecryption();

                    break;
            }

            return $result;

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param InputOutput $inputOutput
     * @param string|null $result
     * @param PublicKeyList $publicKeys
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    private function verifyPlainSignature(RecipientCipher $cipher, InputOutput $inputOutput, string $result = null, PublicKeyList
    $publicKeys): bool
    {
        try {

            $signerPublicKey = null;

            if ($inputOutput instanceof StreamInterface)
                throw new VirgilCryptoException("signAndEncrypt is not supported for streams");

            if (1 == $publicKeys->getAmountOfKeys()) {
                $signerPublicKey = $publicKeys->getFirst();

            } else {

                $signerId = $cipher->customParams()->findData(self::CUSTOM_PARAM_KEY_SIGNER_ID);

                if (!$signerId)
                    throw new VirgilCryptoException(VirgilCryptoError::SIGNER_NOT_FOUND());

                foreach ($publicKeys->getAsArray() as $publicKey) {
                    if ($publicKey->getIdentifier() == $signerId) {
                        $signerPublicKey = $publicKey;
                        break;
                    }
                }

                if (!$signerPublicKey)
                    throw new VirgilCryptoException(VirgilCryptoError::SIGNER_NOT_FOUND());
            }

            $signature = $cipher->customParams()->findData(self::CUSTOM_PARAM_KEY_SIGNATURE);

            if (!$signature)
                throw new VirgilCryptoException(VirgilCryptoError::SIGNATURE_NOT_FOUND());

            $result = $this->verifySignature($signature, $result, $signerPublicKey);

            if (!$result)
                throw new VirgilCryptoException(VirgilCryptoError::SIGNATURE_NOT_VERIFIED());

            return $result;

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param PublicKeyList $publicKeys
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    private function verifyEncryptedSignature(RecipientCipher $cipher, PublicKeyList $publicKeys): bool
    {
        try {

            $signerPublicKey = null;

            if (!$cipher->isDataSigned())
                throw new VirgilCryptoException(VirgilCryptoError::DATA_IS_NOT_SIGNED());

            $signerInfoList = $cipher->signerInfos();

            $res = ($signerInfoList->hasItem() && !$signerInfoList->hasNext());
            if (!$res)
                throw new VirgilCryptoException(VirgilCryptoError::DATA_IS_NOT_SIGNED());

            $signerInfo = $signerInfoList->item();

            foreach ($publicKeys->getAsArray() as $publicKey) {

                if ($publicKey->getIdentifier() == $signerInfo->signerId()) {
                    $signerPublicKey = $publicKey;
                    break;
                }
            }

            if (!$signerPublicKey)
                throw new VirgilCryptoException(VirgilCryptoError::SIGNER_NOT_FOUND());

            $result = $cipher->verifySignerInfo($signerInfo, $signerPublicKey);

            if (!$result)
                throw new VirgilCryptoException(VirgilCryptoError::SIGNATURE_NOT_VERIFIED());

            return $result;

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param RecipientCipher $cipher
     * @param InputOutput $inputOutput
     * @param string|null $result
     * @param VerifyingOptions|null $verifyingOptions
     *
     * @throws VirgilCryptoException
     */
    private function finishDecryption(RecipientCipher $cipher, InputOutput $inputOutput, string $result = null, VerifyingOptions $verifyingOptions = null)
    {
        try {

            if ($verifyingOptions) {

                $mode = $verifyingOptions->getVerifyingMode();

                if ($mode == VerifyingMode::ANY()) {
                    $mode = $cipher->isDataSigned() ? VerifyingMode::DECRYPT_THEN_VERIFY() : VerifyingMode::DECRYPT_AND_VERIFY();
                }

                switch ($mode) {
                    case VerifyingMode::DECRYPT_THEN_VERIFY():

                        $this->verifyPlainSignature($cipher,  $inputOutput, $result, $verifyingOptions->getVirgilPublicKeys());
                        break;

                    case VerifyingMode::DECRYPT_AND_VERIFY():

                        $this->verifyPlainSignature($cipher, $inputOutput, $result, $verifyingOptions->getVirgilPublicKeys());
                        break;
                }

            } else {
                return;
            }

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param InputOutput $inputOutput
     * @param VerifyingOptions|null $verifyingOptions
     * @param VirgilPrivateKey $privateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function decrypt(InputOutput $inputOutput, VirgilPrivateKey $privateKey, VerifyingOptions $verifyingOptions = null): string
    {
        try {

            $messageInfo = "";

            $cipher = new RecipientCipher();

            $cipher->useRandom($this->getRandom());

            $cipher->startDecryptionWithKey($privateKey->getIdentifier(), $privateKey->getPrivateKey(), $messageInfo);

            $result = $this->processDecryption($cipher, $inputOutput);

            $this->finishDecryption($cipher, $inputOutput, $result, $verifyingOptions);

            return $result;

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /// Signatures --->

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
        try {
            $verifier = new Verifier();
            $verifier->reset($signature);
            $verifier->appendData($data);

            return $verifier->verify($virgilPublicKey->getPublicKey());
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Generates digital signature of data stream using private key
     * - Note: Returned value contains only digital signature, not data itself.
     * - Note: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
     *         It's secure to pass raw data here.
     *
     * @param InputStream $inputStream
     * @param VirgilPrivateKey $virgilPrivateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateStreamSignature(InputStream $inputStream, VirgilPrivateKey $virgilPrivateKey): string
    {
        try {
            $signer = new Signer();

            $signer->useRandom($this->getRandom());
            $signer->useHash(new Sha512());

            $signer->reset();

            $data = StreamService::forEachChunk($inputStream, $this->chunkSize);
            $signer->appendData($data);

            return $signer->sign($virgilPrivateKey->getPrivateKey());

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * Verifies digital signature of data stream
     * - Note: Verification algorithm depends on PublicKey type. Default: EdDSA
     *
     * @param string $signature
     * @param InputStream $inputStream
     * @param VirgilPublicKey $virgilPublicKey
     *
     * @return bool
     * @throws VirgilCryptoException
     */
    public function verifyStreamSignature(string $signature, InputStream $inputStream, VirgilPublicKey $virgilPublicKey): bool
    {
        try {
            $verifier = new Verifier();

            $verifier->reset($signature);

            $data = StreamService::forEachChunk($inputStream, $this->chunkSize);
            $verifier->appendData($data);

            return $verifier->verify($virgilPublicKey->getPublicKey());

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param int $size
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function generateRandomData(int $size): string
    {
        try {
            return $this->getRandom()->random($size);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * Computes hash
     *
     * @param string $data
     * @param HashAlgorithms $algorithm
     *
     * @return null|string
     */
    public function computeHash(string $data, HashAlgorithms $algorithm): ?string
    {
        switch ($algorithm) {
            case $algorithm::SHA224():
                $hash = new Sha224();
                break;
            case $algorithm::SHA256():
                $hash = new Sha256();
                break;
            case $algorithm::SHA384():
                $hash = new Sha384();
                break;
            case $algorithm::SHA512():
                $hash = new Sha512();
                break;
            default:
                $hash = null;
        }

        return $hash::hash($data);
    }

    /**
     * @param string $data
     *
     * @return PrivateKey
     * @throws VirgilCryptoException
     */
    private function importInternalPrivateKey(string $data): PrivateKey
    {
        try {
            $keyProvider = new KeyProvider();

            $keyProvider->useRandom($this->getRandom());
            $keyProvider->setupDefaults();

            return $keyProvider->importPrivateKey($data);

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param string $data
     *
     * @return PublicKey
     * @throws VirgilCryptoException
     */
    private function importInternalPublicKey(string $data): PublicKey
    {
        try {
            $keyProvider = new KeyProvider();

            $keyProvider->useRandom($this->getRandom());
            $keyProvider->setupDefaults();

            return $keyProvider->importPublicKey($data);

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param string $data
     *
     * @return VirgilKeyPair
     * @throws VirgilCryptoException
     */
    public function importPrivateKey(string $data): VirgilKeyPair
    {
        try {
            $privateKey = $this->importInternalPrivateKey($data);

            if ($privateKey->algId() == AlgId::RSA()) {
                $keyType = KeyPairType::getRsaKeyType($privateKey->bitLen());
            } else {
                $algId = $privateKey->algId();

                $keyType = KeyPairType::getFromAlgId($algId);
            }

            $publicKey = $privateKey->extractPublicKey();

            $keyId = $this->computePublicKeyIdentifier($publicKey);

            $virgilPrivateKey = new VirgilPrivateKey($keyId, $privateKey, $keyType);
            $virgilPublicKey = new VirgilPublicKey($keyId, $publicKey, $keyType);

            return new VirgilKeyPair($virgilPrivateKey, $virgilPublicKey);

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param PrivateKey $privateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    private function exportInternalPrivateKey(PrivateKey $privateKey): string
    {
        try {
            $keyProvider = new KeyProvider();

            $keyProvider->useRandom($this->getRandom());
            $keyProvider->setupDefaults();

            return $keyProvider->exportPrivateKey($privateKey);

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * Extracts public key from private key
     *
     * @param VirgilPrivateKey $virgilPrivateKey
     *
     * @return VirgilPublicKey
     * @throws VirgilCryptoException
     */
    public function extractPublicKey(VirgilPrivateKey $virgilPrivateKey): VirgilPublicKey
    {
        try {
            $publicKey = $virgilPrivateKey->getPrivateKey()->extractPublicKey();

            return new VirgilPublicKey($virgilPrivateKey->getIdentifier(), $publicKey, $virgilPrivateKey->getKeyType());
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param PublicKey $publicKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    private function exportInternalPublicKey(PublicKey $publicKey): string
    {
        try {
            $keyProvider = new KeyProvider();

            $keyProvider->useRandom($this->getRandom());
            $keyProvider->setupDefaults();

            return $keyProvider->exportPublicKey($publicKey);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
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
        try {
            $keyProvider = new KeyProvider();

            $keyProvider->useRandom($this->getRandom());
            $keyProvider->setupDefaults();

            $publicKey = $keyProvider->importPublicKey($data);

            if ($publicKey->algId() == AlgId::RSA()) {
                $keyType = KeyPairType::getRsaKeyType($publicKey->bitLen());
            } else {
                $algId = $publicKey->algId();
                $keyType = KeyPairType::getFromAlgId($algId);
            }

            $keyId = $this->computePublicKeyIdentifier($publicKey);

            return new VirgilPublicKey($keyId, $publicKey, $keyType);

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * Exports public key
     *
     * @param VirgilPublicKey $publicKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function exportPublicKey(VirgilPublicKey $publicKey)
    {
        try {
            return $this->exportInternalPublicKey($publicKey->getPublicKey());
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * Export private key
     *
     * @param VirgilPrivateKey $privateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function exportPrivateKey(VirgilPrivateKey $privateKey)
    {
        try {
            return $this->exportInternalPrivateKey($privateKey->getPrivateKey());
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * Signs (with private key) Then Encrypts data / stream (and signature) for passed PublicKeys
     * 1. Generates signature depending on KeyType
     * 2. Generates random AES-256 KEY1
     * 3. Encrypts data with KEY1 using AES-256-GCM and generates signature
     * 4. Encrypts signature with KEY1 using AES-256-GCM
     * 5. Generates ephemeral key pair for each recipient
     * 6. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key
     * 7. Computes KDF to obtain AES-256 key from shared secret for each recipient
     * 8. Encrypts KEY1 with this key using AES-256-CBC for each recipient
     *
     * @param InputOutput $inputOutput
     * @param VirgilPrivateKey $privateKey
     * @param PublicKeyList $recipients
     *
     * @return null|string
     * @throws VirgilCryptoException
     */
    public function authEncrypt(InputOutput $inputOutput, VirgilPrivateKey $privateKey, PublicKeyList $recipients)
    {
        try {
            $signingOptions = new SigningOptions($privateKey, SigningMode::SIGN_THEN_ENCRYPT());
            return $this->encrypt($inputOutput, $recipients, $signingOptions);

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }

    /**
     * Decrypts (with private key) data and signature and Verifies signature using any of signers' PublicKeys
     * or
     * Decrypts (using passed PrivateKey) then verifies (using one of public keys) stream
     *
     * - Note: Decrypted stream should not be used until decryption
     *         of whole InputStream completed due to security reasons
     *
     * 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
     * 2. Computes KDF to obtain AES-256 KEY2 from shared secret
     * 3. Decrypts KEY1 using AES-256-CBC
     * 4. Decrypts data and signature using KEY1 and AES-256-GCM
     * 5. Finds corresponding PublicKey according to signer id inside data
     * 6. Verifies signature
     *
     * @param InputOutput $inputOutput
     * @param VirgilPrivateKey $privateKey
     * @param PublicKeyList $recipients
     * @param bool $allowNotEncryptedSignature
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function authDecrypt(InputOutput $inputOutput, VirgilPrivateKey $privateKey, PublicKeyList $recipients,
                                bool $allowNotEncryptedSignature = false)
    {
        try {

            $verifyMode = $allowNotEncryptedSignature ? VerifyingMode::ANY() : VerifyingMode::DECRYPT_THEN_VERIFY();
            $verifyingOptions = new VerifyingOptions($recipients, $verifyMode);

            return $this->decrypt($inputOutput, $privateKey, $verifyingOptions);

        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage(), $e->getCode());
        }
    }
}