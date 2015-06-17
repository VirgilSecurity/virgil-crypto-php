<?php

namespace Virgil\PKI\Clients;

use Virgil\PKI\Models\VirgilUserData;

class UserDataClient extends ApiClient implements UserDataClientInterface {

    public function getUserData($userDataId) {
        $response = $this->get('user-data/'. $userDataId);

        return new VirgilUserData($response->getBody());
    }

    public function insertUserData($publicKeyId, VirgilUserData $virgilUserData) {
        $response = $this->post('user-data', array(
            'public_key_id' => $publicKeyId,
            'class'         => $virgilUserData->class,
            'type'          => $virgilUserData->type,
            'value'         => $virgilUserData->value
        ));

        return new VirgilUserData($response->getBody());
    }

    public function confirm($userDataId, $confirmationCode) {
        $response = $this->post('user-data/' . $userDataId . '/actions/confirm', array(
            'code' => $confirmationCode
        ));

        return true;
    }

    public function resendConfirmation($userDataId) {
        $response = $this->post('user-data/' . $userDataId . '/actions/resend-confirmation', array());

        return true;
    }

    public function deleteUserData($userDataId) {

    }
}