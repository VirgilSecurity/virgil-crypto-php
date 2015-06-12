<?php

namespace Virgil\PKI\Models;

use Virgil\PKI\Models\Base\Collection;

class VirgilPublicKeysCollection extends Collection {

    public function add(VirgilPublicKey $object) {
        parent::add($object);
    }
}