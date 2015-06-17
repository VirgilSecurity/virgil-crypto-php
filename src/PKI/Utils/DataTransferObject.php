<?php

namespace Virgil\PKI\Utils;

use Traversable;

class DataTransferObject implements \IteratorAggregate {

    use DataTrait;

    public function __construct($data = array()) {
        foreach($data as $field => $value) {
            if(is_array($value)) {
                $this->{$field} = new self($value);
            } else {
                $this->{$field} = $value;
            }
        }
    }

    public function getData() {
        return $this->_data;
    }

    public function __isset($field) {
        return isset($this->_data[$field]);
    }


    /**
     * (PHP 5 &gt;= 5.0.0)<br/>
     * Retrieve an external iterator
     * @link http://php.net/manual/en/iteratoraggregate.getiterator.php
     * @return Traversable An instance of an object implementing <b>Iterator</b> or
     * <b>Traversable</b>
     */
    public function getIterator() {
        return new \ArrayIterator($this->_data);
    }
}