<?php

namespace Virgil\PKI\Clients;

use Virgil\PKI\Models\VirgilUserData;

interface UserDataClientInterface {

    public function getUserData($userDataId);
    public function insertUserData($certificateId, VirgilUserData $virgilUserData);
    public function confirm($userDataId, $confirmationCode);
    public function deleteUserData($userDataId);

}