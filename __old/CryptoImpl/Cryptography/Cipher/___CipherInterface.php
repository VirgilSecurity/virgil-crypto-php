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


use Virgil\CryptoImpl\Cryptography\Exceptions\CipherException;

/**
 * Interface provides cipher operations.
 */
interface CipherInterface
{

    /**
     * Encrypts input content by cipher.
     *
     * @param InputOutputInterface $cipherInputOutput
     * @param bool                 $embedContentInfo
     *
     * @return mixed
     *
     * @throws CipherException
     */
    public function encrypt(InputOutputInterface $cipherInputOutput, $embedContentInfo = true);


    /**
     * Decrypts encrypted content with private key.
     *
     * @param InputOutputInterface $cipherInputOutput
     * @param string               $recipientId
     * @param string               $privateKey
     *
     * @return mixed
     *
     * @throws CipherException
     */
    public function decryptWithKey(InputOutputInterface $cipherInputOutput, $recipientId, $privateKey);


    /**
     * Add recipient's public key to the cipher.
     *
     * @param string $recipientId
     * @param string $publicKey
     *
     * @return $this
     */
    public function addKeyRecipient($recipientId, $publicKey);


    /**
     * Gets data from cipher custom params.
     *
     * @param string $key
     *
     * @return string
     */
    public function getCustomParam($key);


    /**
     * Sets data to cipher custom params.
     *
     * @param string $key
     * @param string $value
     *
     * @return $this
     */
    public function setCustomParam($key, $value);


    /**
     * Creates proper cipher input output object.
     *
     * @param array ...$args
     *
     * @return InputOutputInterface
     */
    public function createInputOutput(...$args);
}
