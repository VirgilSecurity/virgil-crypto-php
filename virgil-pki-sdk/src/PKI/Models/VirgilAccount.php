<?php

namespace Virgil\PKI\Models;

use Virgil\PKI\Models\Base\Model;
use Virgil\PKI\Utils\DataTransferObject;

class VirgilAccount extends Model {

    public $account_id;
    public $public_keys;

    public function __construct(DataTransferObject $object = null) {
        $this->public_keys = new VirgilPublicKeysCollection();

        if($object !== null) {
            if(isset($object->id)) {
                $this->account_id = $object->id->account_id;
            }

            $this->public_keys->add(new VirgilPublicKey($object));
        }
    }

}