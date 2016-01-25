<?php
/**
 * User: sajib
 * Date: 1/25/16
 * Time: 5:43 PM
 *
 * Note: this class requires 'OpenSSL' PHP extension for random key/string generation on Windows
 * and for encryption/decryption on all platforms. For the highest security level PHP version >= 5.5.0 is recommended.
 *
 */

    require_once 'Security.php';

    $security = new Security();

    $password = '123456';

    /*
     * When a user provides a password for the first time (e.g., upon registration), the password needs to be hashed:
     * @param string $password
     */
    $hash = $security->generatePasswordHash($password);


    /*
     * When a user attempts to log in, the submitted password must be verified against the previously hashed and stored password:
     * @param string $password is user input password.
     * @param string $hash can retrieve from your database table.
     * */

    if($security->validatePassword($password, $hash)){
        echo "Valid Password";
    }else{
        echo "Invalid Password";
    }


