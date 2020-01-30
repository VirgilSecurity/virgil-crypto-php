<?php

const VSCF_FOUNDATION_PHP = "vscf_foundation_php";
const VSCE_PHE_PHP = "vsce_phe_php";

const EXT_LIST = [VSCF_FOUNDATION_PHP];

/**
 * @return mixed
 */
function getScannedIniDir()
{
    $res = null;
    $rawData = php_ini_scanned_files();

    if ($rawData)
        $res = explode(",", $rawData);

    return pathinfo($res[0], PATHINFO_DIRNAME);
}

$extArr = [];

foreach (EXT_LIST as $ext) {
    $extArr[] = [
        'name' => $ext,
        'version' => phpversion($ext),
        'is_extension_loaded' => extension_loaded($ext),
    ];
}

$config = [
    'OS' => PHP_OS,
    'PHP_VERSION' => PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION,
    'PATH_TO_EXTENSIONS_DIR' => PHP_EXTENSION_DIR,
    'PATH_TO_MAIN_PHP.INI' => php_ini_loaded_file(),
    'PATH_TO_ADDITIONAL_INI_FILES' => getScannedIniDir(),
];

var_dump($extArr, $config);
exit(1);