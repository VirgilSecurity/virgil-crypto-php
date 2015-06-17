<?php

namespace Virgil\PKI\Models;

use Virgil\PKI\Models\Base\Model;
use Virgil\PKI\Utils\DataTransferObject;

class VirgilPublicKey extends Model {

   public $public_key_id;
   public $public_key;
   public $user_data;

    public function __construct(DataTransferObject $object = null) {
        $this->user_data  = new VirgilUserDataCollection();

        if($object !== null) {
            if(isset($object->id)) {
                $this->public_key_id = $object->id->public_key_id;
            }

            $this->public_key = base64_decode($object->public_key);

            if(isset($object->user_data)) {
                foreach($object->user_data as $item) {
                    $this->user_data->add(new VirgilUserData($item));
                }
            }
        }
    }

}
