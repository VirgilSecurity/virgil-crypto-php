<?php
/**
 * Copyright (C) 2015-2020 Virgil Security Inc.
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

namespace Virgil\Crypto\Core\Enum;

use MyCLabs\Enum\Enum;

/**
 * Errors for this framework
 *
 * Class VirgilCryptoError
 *
 * @package Virgil\Crypto
 */
class VirgilCryptoError extends Enum
{
    private const SIGNER_NOT_FOUND = [1, "Signer not found"];
    private const SIGNATURE_NOT_FOUND = [2, "Signature not found"];
    private const SIGNATURE_NOT_VERIFIED = [3, "Signature not verified"];
    private const UNKNOWN_ALG_ID = [4, "Unknown alg id"];
    private const RSA_SHOULD_BE_CONSTRUCTED_DIRECTLY = [5, "Rsa should be constructed directly"];
    private const UNSUPPORTED_RSA_LENGTH = [6, "Unsupported rsa length"];
    private const PASSED_KEY_IS_NOT_VIRGIL = [8, "Passed key is not virgil"];
    private const OUTPUT_STREAM_ERROR = [9, "Output stream has no space left"];
    private const INPUT_STREAM_ERROR = [10, "Input stream has no space left"];
    private const INVALID_SEED_SIZE = [11, "Invalid seed size"];
    private const DATA_IS_NOT_SIGNED = [12, "Data has no signature to verify"];
    private const INVALID_STREAM_SIZE = [13, "Actual stream size doesn't match with given value"];

    /**
     * @return int
     */
    public function getCode(): int
    {
        return $this->getValue()[0];
    }

    /**
     * @return string
     */
    public function getMessage(): string
    {
        return $this->getValue()[1];
    }
}