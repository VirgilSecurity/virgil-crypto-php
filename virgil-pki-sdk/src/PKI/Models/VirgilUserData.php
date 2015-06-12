<?php

namespace Virgil\PKI\Models;

use Virgil\PKI\Models\Base\Model;
use Virgil\PKI\Utils\DataTransferObject;

class VirgilUserData extends Model {

    public $user_data_id;
    public $class;
    public $type;
    public $value;
    public $is_confirmed;
    public $signs = array();

    public function __construct(DataTransferObject $object = null) {
        if($object !== null) {
            $this->user_data_id  = $object->id->user_data_id;
            $this->class         = $object->class;
            $this->type          = $object->type;
            $this->value         = $object->value;
            $this->is_confirmed  = $object->is_confirmed;
        }
    }

}