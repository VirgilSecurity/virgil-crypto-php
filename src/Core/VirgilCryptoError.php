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

use MyCLabs\Enum\Enum;

/**
 * Errors for this framework
 *
 * Class VirgilCryptoError
 *
 * @package Virgil\CryptoImpl
 */
class VirgilCryptoError extends Enum
{
    private const SIGNER_NOT_FOUND = 1;
    private const SIGNATURE_NOT_FOUND = 2;
    private const SIGNATURE_NOT_VERIFIED = 3;
    private const UNKNOWN_ALG_ID = 4;
    private const RSA_SHOULD_BE_CONSTRUCTED_DIRECTLY = 5;
    private const UNSUPPORTED_RSA_LENGTH = 6;
    private const PASSED_KEY_IS_NOT_VIRGIL = 8;
    private const OUTPUT_STREAM_ERROR = 9;
    private const INPUT_STREAM_ERROR = 10;
    private const INVALID_SEED_SIZE = 11;
    private const DATA_IS_NOT_SIGNED = 12;
    private const INVALID_STREAM_SIZE = 13;

    /**
     * Human-readable localized description
     *
     * @param VirgilCryptoError $virgilCryptoError
     *
     * @return null|string
     */
    public static function getErrorDescription(VirgilCryptoError $virgilCryptoError): ?string
    {
        switch ($virgilCryptoError)
        {
            case $virgilCryptoError::SIGNER_NOT_FOUND():
                $res = "Signer not found";
                break;
            case $virgilCryptoError::SIGNATURE_NOT_FOUND():
                $res = "Signature not found";
                break;
            case $virgilCryptoError::SIGNATURE_NOT_VERIFIED():
                $res = "Signature not verified";
                break;
            case $virgilCryptoError::UNKNOWN_ALG_ID():
                $res = "Unknown alg id";
                break;
            case $virgilCryptoError::RSA_SHOULD_BE_CONSTRUCTED_DIRECTLY():
                $res = "Rsa should be constructed directly";
                break;
            case $virgilCryptoError::UNSUPPORTED_RSA_LENGTH():
                $res = "Unsupported rsa length";
                break;
            case $virgilCryptoError::PASSED_KEY_IS_NOT_VIRGIL():
                $res = "Passed key is not virgil";
                break;
            case $virgilCryptoError::OUTPUT_STREAM_ERROR():
                $res = "Output stream has no space left";
                break;
            case $virgilCryptoError::INPUT_STREAM_ERROR():
                $res = "Input stream has no space left";
                break;
            case $virgilCryptoError::INVALID_SEED_SIZE():
                $res = "Invalid seed size";
                break;
            case $virgilCryptoError::DATA_IS_NOT_SIGNED():
                $res = "Data has no signature to verify";
                break;
            case $virgilCryptoError::INVALID_STREAM_SIZE():
                $res = "Actual stream size doesn't match with given value";
                break;
            default:
                $res = null;
        }

        return $res;
    }
}