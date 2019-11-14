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

namespace Virgil\CryptoImpl\Core;

use Virgil\CryptoImpl\Exceptions\VirgilCryptoException;

/**
 * Class PublicKeyList
 *
 * @package Virgil\CryptoImpl\Services
 */
class PublicKeyList
{
    /**
     * @var array
     */
    private $list = [];

    /**
     * PublicKeyList constructor.
     */
    public function __construct()
    {
        $this->list = null;
    }

    /**
     * @param VirgilPublicKey $publicKey
     *
     * @return PublicKeyList
     */
    public function addPublicKey(VirgilPublicKey $publicKey): PublicKeyList
    {
        $this->list[] = $publicKey;
        return $this;
    }

    /**
     * @return array
     * @throws VirgilCryptoException
     */
    public function getAsArray(): array
    {
        if(empty($this->list))
            throw new VirgilCryptoException("Empty VirgilPublicKey list");

        return $this->list;
    }

    /**
     * @return int
     */
    public function getAmountOfKeys(): int
    {
        return count($this->list);
    }
}