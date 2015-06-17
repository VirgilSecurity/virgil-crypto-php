<?php

namespace Virgil\PKI\Clients;

use Virgil\PKI\Models\VirgilUserDataCollection;

interface PublicKeysClientInterface {

    public function getKey($publicKeyId);
    public function searchKey($userId, $userDataType);
    public function addKey($accountId, $publicKey, VirgilUserDataCollection $userData);

}