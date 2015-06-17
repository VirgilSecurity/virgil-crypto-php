<?php

namespace Virgil\PKI\Models\Base;

use Traversable;

abstract class Collection implements \IteratorAggregate, \JsonSerializable {

    protected $_collection = array();

    public function __construct($data = array()) {
        foreach($data as $object) {
            $this->add($object);
        }
    }

    public function add($object) {
        $this->_collection[] = $object;
    }
    
    public function get($index) {
        if(isset($this->_collection[$index])) {
            return $this->_collection[$index];
        }
        
        return null;
    }

    public function remove($index) {
        unset($this->_collection[$index]);
    }

    /**
     * (PHP 5 &gt;= 5.0.0)<br/>
     * Retrieve an external iterator
     * @link http://php.net/manual/en/iteratoraggregate.getiterator.php
     * @return Traversable An instance of an object implementing <b>Iterator</b> or
     * <b>Traversable</b>
     */
    public function getIterator() {
        return new \ArrayIterator($this->_collection);
    }

    /**
     * (PHP 5 &gt;= 5.4.0)<br/>
     * Specify data which should be serialized to JSON
     * @link http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     */
    public function jsonSerialize() {
        return $this->_collection;
    }
}
