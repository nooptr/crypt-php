<?php

$plain_text = '{
    "first": "最初",
    "second": 1,
    "third": "テストです。"
}';

$salt = "ABDcvZy#q##kTW8_n#EBzvd7VDj.LEv4";


echo encrypt($plain_text,$salt);
$crypt_text = encrypt($plain_text,$salt);
echo "\n";
echo decrypt($crypt_text,$salt);


function encrypt($input,$key = "key_default"){
    $key = md5($key);

    $td  = mcrypt_module_open('tripledes', '', 'ecb', '');
    $key = substr($key, 0, mcrypt_enc_get_key_size($td));
    $iv  = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);

    if (mcrypt_generic_init($td, $key, $iv) < 0) {
      exit('error.');
    }

    $encrypted_data = base64_encode(mcrypt_generic($td, $input));

    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);

    return $encrypted_data;
}


function decrypt($input,$key = "key_default")
{
    $key = md5($key);

    $td  = mcrypt_module_open('tripledes', '', 'ecb', '');
    $key = substr($key, 0, mcrypt_enc_get_key_size($td));
    $iv  = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);

    if (mcrypt_generic_init($td, $key, $iv) < 0) {
      exit('error.');
    }

    $encrypted_data = mdecrypt_generic($td, base64_decode($input));

    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);

    return $encrypted_data;
}


