<?php

namespace Virgil\PKI\Utils;

trait Setter {

    public function __set($name, $value) {
        $this->_data[$name] = $value;
    }

}