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

    echo 'Read sign from json' . PHP_EOL;

    $signJson = file_get_contents('data' . DIRECTORY_SEPARATOR . 'test.txt.sign');
    if($signJson === false) {
        throw new Exception('Filed to open sign file');
    }

    $sign = new VirgilSign();
    $sign->fromJson($signJson);

    echo 'Read public key from json' . PHP_EOL;

    $publicKeyJson = file_get_contents('data' . DIRECTORY_SEPARATOR . 'virgil_public.key');
    if($publicKeyJson === false) {
        throw new Exception('Failed to open public key file');
    }

    $virgilCertificate = new VirgilCertificate();
    $virgilCertificate->fromJson($publicKeyJson);

    echo 'Initialize signer' . PHP_EOL;

    $signer = new VirgilSigner();

    echo 'Verify sign' . PHP_EOL;

    if($signer->verify($source, $sign, $virgilCertificate->publicKey()) == true) {
        echo 'Data is verified';
    } else {
        echo 'Data is not verified';
    }

} catch (Exception $e) {
    echo $e->getMessage();
}