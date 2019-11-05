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

#namespace Virgil\CryptoImpl\Cryptography\Cipher;


use Exception;

use VirgilCipherBase;

use Virgil\CryptoImpl\Cryptography\Exceptions\CipherException;

/**
 * Base abstract class for ciphers.
 */
abstract class AbstractVirgilCipher implements CipherInterface
{
    /** @var VirgilCipherBase $cipher */
    protected $cipher;


    /**
     * @inheritdoc
     */
    abstract public function encrypt(InputOutputInterface $cipherInputOutput, $embedContentInfo = true);


    /**
     * @inheritdoc
     */
    abstract public function decryptWithKey(InputOutputInterface $cipherInputOutput, $recipientId, $privateKey);


    /**
     * @inheritdoc
     */
    abstract public function createInputOutput(...$args);


    /**
     * @inheritdoc
     *
     * @throws CipherException
     */
    public function addKeyRecipient($recipientId, $publicKey)
    {
        try {
            $this->cipher->addKeyRecipient($recipientId, $publicKey);

            return $this;
        } catch (Exception $e) {
            throw new CipherException($e->getMessage(), $e->getCode());
        }
    }


    /**
     * @inheritdoc
     */
    public function getCustomParam($key)
    {
        $cipherCustomParams = $this->cipher->customParams();

        return $cipherCustomParams->getData($key);
    }


    /**
     * @inheritdoc
     */
    public function setCustomParam($key, $value)
    {
        $cipherCustomParams = $this->cipher->customParams();
        $cipherCustomParams->setData($key, $value);

        return $this;
    }
}
