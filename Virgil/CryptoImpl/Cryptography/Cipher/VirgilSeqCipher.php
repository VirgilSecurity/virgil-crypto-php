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

namespace Virgil\CryptoImpl\Cryptography\Cipher;

use Exception;
use Virgil\CryptoImpl\Cryptography\Exceptions\SeqCipherException;
use Virgil\CryptoImpl\VirgilPrivateKey;

/**
 * Class VirgilSeqCipher
 * @package Virgil\CryptoImpl\Cryptography\Cipher
 */
class VirgilSeqCipher
{
    /**
     * @var \VirgilSeqCipher
     */
    private $cipher;

    /**
     * VirgilSeqCipher constructor.
     */
    public function __construct()
    {
        $this->cipher = new \VirgilSeqCipher();
    }

    /**
     * @throws SeqCipherException
     */
    public function startEncryption()
    {
        try {
            return $this->cipher->startEncryption();
        } catch (Exception $exception) {
            throw new SeqCipherException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param $data
     * @return mixed
     * @throws SeqCipherException
     */
    public function process($data)
    {
        try {
            return $this->cipher->process($data);
        } catch (Exception $exception) {
            throw new SeqCipherException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @return mixed
     * @throws SeqCipherException
     */
    public function finish()
    {
        try {
            return $this->cipher->finish();
        } catch (Exception $exception) {
            throw new SeqCipherException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param $password
     */
    public function addPasswordRecipient($password)
    {
        $this->cipher->addPasswordRecipient($password);
    }

    /**
     * @param $recipientId
     * @param $publicKey
     */
    public function addKeyRecipient($recipientId, $publicKey)
    {
        $this->cipher->addKeyRecipient($recipientId, $publicKey);
    }

    /**
     * @param $password
     * @throws SeqCipherException
     */
    public function startDecryptionWithPassword($password)
    {
        try {
            return $this->cipher->startDecryptionWithPassword($password);
        } catch (Exception $exception) {
            throw new SeqCipherException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @param $recipientId
     * @param $privateKey
     * @throws SeqCipherException
     */
    public function startDecryptionWithKey($recipientId, $privateKey)
    {
        try {
            return $this->cipher->startDecryptionWithKey($recipientId, $privateKey);
        } catch (Exception $exception) {
            throw new SeqCipherException($exception->getMessage(), $exception->getCode());
        }
    }

    /**
     * @throws SeqCipherException
     */
    public function removeAllRecipients()
    {
        try {
            $this->cipher->removeAllRecipients();
        } catch (Exception $exception) {
            throw new SeqCipherException($exception->getMessage(), $exception->getCode());
        }
    }
}