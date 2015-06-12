<?php

namespace Virgil\PKI\Models;

use Virgil\PKI\Models\Base\Collection;

class VirgilUserDataCollection extends Collection {

    public function add(VirgilUserData $object) {
        parent::add($object);
    }
}