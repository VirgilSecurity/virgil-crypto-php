<?php

namespace Virgil\PKI\Clients;

use Virgil\PKI\Models\VirgilUserData;

interface AccountsClientInterface {

    public function register($userData, $publicKey);

}