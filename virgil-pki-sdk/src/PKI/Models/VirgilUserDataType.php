<?php

namespace Virgil\PKI\Models;

class VirgilUserDataType {

    private static $_userIdTypes = array(
        'email',
        'domain',
        'application'
    );

    public static function isValidType($type) {
        return in_array($type, self::$_userIdTypes);
    }

}