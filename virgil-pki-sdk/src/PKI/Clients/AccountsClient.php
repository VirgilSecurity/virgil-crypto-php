<?php

namespace Virgil\PKI\Clients;

use Virgil\PKI\Models\VirgilAccount;

class AccountsClient extends ApiClient implements AccountsClientInterface {

    public function register($userData, $publicKey) {
        $response = $this->post('public-key', array(
            'public_key' => base64_encode($publicKey),
            'user_data'  => $userData
        ));

        return new VirgilAccount($response->getBody());
    }
}