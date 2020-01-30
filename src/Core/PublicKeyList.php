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

namespace Virgil\Crypto\Core;

use Virgil\Crypto\Exceptions\VirgilCryptoServiceException;

/**
 * Class PublicKeyList
 *
 * @package Virgil\Crypto\Services
 */
class PublicKeyList
{
    /**
     * @var array
     */
    private $list = [];

    /**
     * PublicKeyList constructor.
     *
     * @param VirgilPublicKey ...$publicKey
     */
    public function __construct(VirgilPublicKey ...$publicKey)
    {
        if ($publicKey)
            array_push($this->list, ...$publicKey);
    }

    /**
     * @param VirgilPublicKey ...$publicKey
     */
    public function addPublicKey(VirgilPublicKey ...$publicKey): void
    {
        array_push($this->list, ...$publicKey);
    }

    /**
     * @return array
     * @throws VirgilCryptoServiceException
     */
    public function getAsArray(): array
    {
        if($this->check())
            return $this->list;
    }

    /**
     * @return VirgilPublicKey
     * @throws VirgilCryptoServiceException
     */
    public function getFirst(): VirgilPublicKey
    {
        if($this->check())
            return $this->list[0];
    }

    /**
     * @return int
     */
    public function getAmountOfKeys(): int
    {
        return count($this->list);
    }

    /**
     * @return bool
     * @throws VirgilCryptoServiceException
     */
    private function check(): bool
    {
        if(empty($this->list))
            throw new VirgilCryptoServiceException("Empty VirgilPublicKey list");

        return true;
    }
}