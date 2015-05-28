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

const VIRGIL_PKI_URL_BASE = 'https://pki.virgilsecurity.com/v1/';
const USER_ID_TYPE = 'email';
const USER_ID = 'test.php.virgilsecurity-02@mailinator.com';
const VIRGIL_APP_TOKEN = '1234567890';

function getUrl($endpoint) {
    return VIRGIL_PKI_URL_BASE . $endpoint;
}

function httpPost($url, $data = array(), $header = array()) {
    $result = null;

    try {
        $ch = curl_init($url);

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);

        $result = curl_exec($ch);

        if(curl_errno($ch) > 0) {
            throw new Exception('HTTP Request error: ' . curl_error($ch));
        }

        curl_close($ch);
    } catch (Exception $e) {
        echo $e->getMessage();
    }

    return $result;
}

function pkiCreateUser($publicKey, $userIds) {
    $payload = array(
        'public_key' => base64_encode($publicKey),
        'user_data'  => array_map(function($value, $key) {
            return array(
                'class' => 'user_id',
                'type'  => $key,
                'value' => $value
            );
        }, $userIds, array_keys($userIds))
    );

    $headers = array(
        'Content-Type:application/json',
        'Accept:application/json',
        'X-VIRGIL-APP-TOKEN:' . VIRGIL_APP_TOKEN
    );

    $response = json_decode(httpPost(getUrl('public-key'), $payload, $headers));

    if(empty($response) || !empty($response->error)) {
        throw new Exception('Unable to register user');
    }

    $virgilCertificate = new VirgilCertificate($publicKey);
    $virgilCertificate->id()->setAccountId($response->id->account_id);
    $virgilCertificate->id()->setCertificateId($response->id->public_key_id);

    return $virgilCertificate;
}

echo 'Read public key file' . PHP_EOL;

$publicKey = file_get_contents('data' . DIRECTORY_SEPARATOR . 'new_public.key');

try {
    $virgilCertificate = pkiCreateUser($publicKey, array(
        USER_ID_TYPE => USER_ID
    ));

    echo 'Store virgil public key to the output file...';

    file_put_contents('data' . DIRECTORY_SEPARATOR . 'virgil_public.key', $virgilCertificate->publicKey());
} catch (Exception $e) {
    echo $e->getMessage();
}