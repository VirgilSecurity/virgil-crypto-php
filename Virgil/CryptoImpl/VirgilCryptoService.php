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

namespace Virgil\CryptoImpl;

use Virgil\CryptoImpl\Exceptions\VirgilCryptoException;
use VirgilCrypto\Foundation\CtrDrbg;
use VirgilCrypto\Foundation\KeyProvider;
use VirgilCrypto\Foundation\Random;
use \Exception;

/**
 * Class VirgilCryptoService
 *
 * @package Virgil\CryptoImpl
 */
class VirgilCryptoService
{
    /**
     * @param Random|null $random
     *
     * @return KeyProvider
     * @throws VirgilCryptoException
     */
    public function getKeyProvider(Random $random = null): KeyProvider
    {
        try {
            $keyProvider = new KeyProvider();
            if($random)
                $keyProvider->useRandom($random);

            $keyProvider->setupDefaults();
            return $keyProvider;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }

    /**
     * @param bool $useRandom
     *
     * @return CtrDrbg
     * @throws VirgilCryptoException
     */
    public function getCtrDrbg(bool $setupDefaults = true): CtrDrbg
    {
        try {
            $random = new CtrDrbg();
            if($setupDefaults)
                $random->setupDefaults();

            return $random;
        } catch (Exception $e) {
            throw new VirgilCryptoException($e->getMessage());
        }
    }
}