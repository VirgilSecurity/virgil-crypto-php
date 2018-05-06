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

namespace Virgil\CryptoImpl\Cryptography\Core\Cipher;


use Exception;

use Virgil\CryptoImpl\Cryptography\Core\Crypto\VirgilCipher as InternalVirgilCipher;

use Virgil\CryptoImpl\Cryptography\Core\Exceptions\CipherException;

/**
 * Class implements cipher operations with primitive data (like strings, numbers etc.)
 */
class VirgilCipher extends AbstractVirgilCipher
{
    /**
     * Class constructor.
     *
     * @param InternalVirgilCipher $cipher
     */
    public function __construct(InternalVirgilCipher $cipher)
    {
        $this->cipher = $cipher;
    }


    /**
     * @inheritdoc
     *
     * @throws CipherException
     */
    public function encrypt(InputOutputInterface $cipherInputOutput, $embedContentInfo = true)
    {
        try {
            return $this->cipher->encrypt($cipherInputOutput->getInput(), $embedContentInfo);
        } catch (Exception $exception) {
            throw new CipherException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * @inheritdoc
     *
     * @throws CipherException
     */
    public function decryptWithKey(InputOutputInterface $cipherInputOutput, $recipientId, $privateKey)
    {
        try {
            return $this->cipher->decryptWithKey($cipherInputOutput->getInput(), $recipientId, $privateKey);
        } catch (Exception $exception) {
            throw new CipherException($exception->getMessage(), $exception->getCode());
        }
    }


    /**
     * @inheritdoc
     */
    public function createInputOutput(...$args)
    {
        return new InputOutput($args[0]);
    }
}
