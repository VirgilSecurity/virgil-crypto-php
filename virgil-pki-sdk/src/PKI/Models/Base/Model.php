<?php

namespace Virgil\PKI\Models\Base;

use Virgil\PKI\Utils\DataTransferObject;
use Virgil\PKI\Utils\Getter;

abstract class Model implements \JsonSerializable {

    /**
     * (PHP 5 &gt;= 5.4.0)<br/>
     * Specify data which should be serialized to JSON
     * @link http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     */
    public function jsonSerialize() {
        $result  = array();
        $reflect = new \ReflectionClass($this);

        $properties = $reflect->getProperties(\ReflectionProperty::IS_PUBLIC);
        foreach($properties as $property) {
            $result[$property->getName()] = $property->getValue($this);
        }

        return $result;
    }
}