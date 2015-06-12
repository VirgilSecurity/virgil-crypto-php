<?php

namespace Virgil\PKI\Utils;

trait Getter {

    public function __get($name) {
        if(isset($this->_data[$name])) {
            return $this->_data[$name];
        }

        return null;
    }

}