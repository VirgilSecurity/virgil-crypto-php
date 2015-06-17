<?php

namespace Virgil\PKI;

require_once __DIR__ . '/../../vendor/autoload.php';

use Virgil\PKI\Clients\AccountsClient;
use Virgil\PKI\Clients\PublicKeysClient;
use Virgil\PKI\Clients\UserDataClient;
use Virgil\PKI\Http\Connection;
use Virgil\PKI\Utils\Config;

class PkiClient {

    protected $_config           = null;
    protected $_accountsClient   = null;
    protected $_publicKeysClient = null;
    protected $_userDataClient   = null;

    public function __construct($appToken) {
        $this->_config = $this->_initConfig();

        $connection = new Connection($appToken, $this->_config->base_url, $this->_config->api_version);

        $this->_accountsClient   = new AccountsClient($connection);
        $this->_publicKeysClient = new PublicKeysClient($connection);
        $this->_userDataClient   = new UserDataClient($connection);
    }

    /**
     * @return AccountsClient
     */
    public function getAccountsClient() {
        return $this->_accountsClient;
    }

    /**
     * @return PublicKeysClient
     */
    public function getPublicKeysClient() {
        return $this->_publicKeysClient;
    }

    /**
     * @return UserDataClient
     */
    public function getUserDataClient() {
        return $this->_userDataClient;
    }

    /**
     * @return \Virgil\PKI\Utils\Config
     */
    private function _initConfig() {
        return new Config(parse_ini_file(__DIR__ . DIRECTORY_SEPARATOR . 'config.ini'));
    }

}