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

use Virgil\PKI\Models\VirgilUserData;
use Virgil\PKI\Models\VirgilUserDataCollection;

require_once './vendor/autoload.php';

const VIRGIL_PKI_URL_BASE = 'https://pki-stg.virgilsecurity.com/v1/';
const USER_ID_TYPE = 'email';
const USER_ID = 'test.php.virgilsecurity-032@mailinator.com';
const USER_DATA_CLASS = 'user_id';
const VIRGIL_APP_TOKEN = '1234567890';


echo 'Read public key file' . PHP_EOL;

$publicKey = file_get_contents('data' . DIRECTORY_SEPARATOR . 'new_public.key');

try {
    $pkiClient = new Virgil\PKI\PkiClient(VIRGIL_APP_TOKEN);

    $userData = new VirgilUserData();
    $userData->class = USER_DATA_CLASS;
    $userData->type  = USER_ID_TYPE;
    $userData->user_data_id = USER_ID;

    $userDataCollection = new VirgilUserDataCollection(array($userData));

    $virgilAccount = $pkiClient->getAccountsClient()->register($userDataCollection, $publicKey);

    echo 'Store virgil public key to the output file...';

    file_put_contents('data' . DIRECTORY_SEPARATOR . 'virgil_public.key', $virgilAccount->public_keys->get(0)->public_key);
} catch (Exception $e) {
    echo $e->getMessage();
}