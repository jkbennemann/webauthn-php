<?php

include "vendor/autoload.php";

use Jkbennemann\Webauthn\Configuration;
use Jkbennemann\Webauthn\Enums\KeyFormat;
use Jkbennemann\Webauthn\Enums\UserVerification;
use Jkbennemann\Webauthn\Webauthn;

$webauthn = new Webauthn(
    new Configuration("localhost - Test", "localhost", 32),
    KeyFormat::all()
);

print_r($webauthn);

$userId = dechex(random_int(100000000000, 999999999999));

$create = $webauthn->getCreateArgs($userId, "Jakob", "Jakob's Device", UserVerification::DISCOURAGED, true);

//print_r($create);

$createProcess = $webauthn->processCreate('', '', $create->challenge, false, true, false);

foreach (KeyFormat::all() as $type) {
//    echo $type . PHP_EOL;
}
