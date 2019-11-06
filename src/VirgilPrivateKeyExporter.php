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

use Virgil\CryptoApi\PrivateKey;
use Virgil\CryptoApi\PrivateKeyExporter;
use \Exception;
use Virgil\CryptoImpl\Exceptions\VirgilCryptoException;

/**
 * Class VirgilPrivateKeyExporter
 * @package Virgil\CryptoImpl
 */
class VirgilPrivateKeyExporter implements PrivateKeyExporter
{
    /**
     * @var VirgilCrypto
     */
    private $vCrypto;

    /**
     * @var null|string
     */
    private $password;

    /**
     * VirgilPrivateKeyExporter constructor.
     *
     * @param string|null $password
     *
     * @throws VirgilCryptoException
     */
    public function __construct(string $password = null)
    {
        try {
            $this->password = $password;
            $this->vCrypto = new VirgilCrypto();
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * @param PrivateKey $privateKey
     *
     * @return string
     * @throws VirgilCryptoException
     */
    public function exportPrivateKey(PrivateKey $privateKey)
    {
        try {
            if (!$privateKey instanceof VirgilPrivateKey) {
                throw new VirgilCryptoException("Instance of the VirgilPrivateKey expected");
            }

            return base64_encode($this->vCrypto->exportPrivateKey($privateKey, $this->password));
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * @param string $data
     *
     * @return PrivateKey|VirgilKeyPair
     * @throws VirgilCryptoException
     */
    public function importPrivateKey($data)
    {
        try {
            return $this->vCrypto->importPrivateKey(base64_decode($data), $this->password);
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }
}
