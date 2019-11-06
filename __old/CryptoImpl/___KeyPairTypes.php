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

#namespace Virgil\CryptoImpl;


use VirgilKeyPair as CryptoVirgilKeyPair;

/**
 * Class keeps list of key pair types constants.
 */
class KeyPairTypes
{
    const RSA256 = CryptoVirgilKeyPair::Type_RSA_256;
    const RSA512 = CryptoVirgilKeyPair::Type_RSA_512;
    const RSA1024 = CryptoVirgilKeyPair::Type_RSA_1024;
    const RSA2048 = CryptoVirgilKeyPair::Type_RSA_2048;
    const RSA3072 = CryptoVirgilKeyPair::Type_RSA_3072;
    const RSA4096 = CryptoVirgilKeyPair::Type_RSA_4096;
    const RSA8192 = CryptoVirgilKeyPair::Type_RSA_8192;
    const EC_SECP192R1 = CryptoVirgilKeyPair::Type_EC_SECP192R1;
    const EC_SECP224R1 = CryptoVirgilKeyPair::Type_EC_SECP224R1;
    const EC_SECP256R1 = CryptoVirgilKeyPair::Type_EC_SECP256R1;
    const EC_SECP384R1 = CryptoVirgilKeyPair::Type_EC_SECP384R1;
    const EC_SECP521R1 = CryptoVirgilKeyPair::Type_EC_SECP521R1;
    const EC_BP256R1 = CryptoVirgilKeyPair::Type_EC_BP256R1;
    const EC_BP384R1 = CryptoVirgilKeyPair::Type_EC_BP384R1;
    const EC_BP512R1 = CryptoVirgilKeyPair::Type_EC_BP512R1;
    const EC_SECP192K1 = CryptoVirgilKeyPair::Type_EC_SECP192K1;
    const EC_SECP224K1 = CryptoVirgilKeyPair::Type_EC_SECP224K1;
    const EC_SECP256K1 = CryptoVirgilKeyPair::Type_EC_SECP256K1;
    const EC_CURVE25519 = CryptoVirgilKeyPair::Type_EC_CURVE25519;
    const FAST_EC_X25519 = CryptoVirgilKeyPair::Type_FAST_EC_X25519;
    const FAST_EC_ED25519 = CryptoVirgilKeyPair::Type_FAST_EC_ED25519;
}
