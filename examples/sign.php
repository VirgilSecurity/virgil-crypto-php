<?php

/**
 * Copyright (C) 2014 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
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
 */

require_once 'lib/virgil_php.php';

try {
    echo 'Read source file' . PHP_EOL;

    $source = file_get_contents('data' . DIRECTORY_SEPARATOR . 'test.txt');
    if($source === false) {
        throw new Exception('Unable to get source data');
    }

    echo 'Read public key from json' . PHP_EOL;

    $publicKeyJson = file_get_contents('data' . DIRECTORY_SEPARATOR . 'virgil_public.key');
    if($publicKeyJson === false) {
        throw new Exception('Failed to open public key file');
    }

    $virgilCertificate = new VirgilCertificate();
    $virgilCertificate->fromJson($publicKeyJson);

    echo 'Read private key' . PHP_EOL;

    $privateKey = file_get_contents('data' . DIRECTORY_SEPARATOR . 'new_private.key');
    if($privateKey === false) {
        throw new Exception('Failed to open private key file');
    }

    echo 'Initialize signer' . PHP_EOL;

    $signer = new VirgilSigner();

    echo 'Sign data' . PHP_EOL;

    $sign = $signer->sign($source, $virgilCertificate->id()->certificateId(), $privateKey, 'password');

    echo 'Save signed data to file' . PHP_EOL;

    file_put_contents('data' . DIRECTORY_SEPARATOR . 'test.txt.sign', $sign->toJson());

} catch (Exception $e) {
    echo $e->getMessage();
}