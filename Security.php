<?php
/**
 * User: sajib
 * Date: 1/25/16
 * Time: 5:39 PM
 */

/**
 * Security provides a set of methods to handle common security-related tasks.
 *
 * In particular, Security supports the following features:
 *
 * - Encryption/decryption: [[encryptByKey()]], [[decryptByKey()]], [[encryptByPassword()]] and [[decryptByPassword()]]
 * - Key derivation using standard algorithms: [[pbkdf2()]] and [[hkdf()]]
 * - Data tampering prevention: [[hashData()]] and [[validateData()]]
 * - Password validation: [[generatePasswordHash()]] and [[validatePassword()]]
 *
 * > Note: this class requires 'OpenSSL' PHP extension for random key/string generation on Windows and
 * for encryption/decryption on all platforms. For the highest security level PHP version >= 5.5.0 is recommended.
 *
 * @author Qiang Xue <qiang.xue@gmail.com>
 * @author Tom Worster <fsb@thefsb.org>
 * @author Klimov Paul <klimov.paul@gmail.com>
 * @since 2.0
 */
class Security
{
    /**
     * @var string The cipher to use for encryption and decryption.
     */
    public $cipher = 'AES-128-CBC';
    /**
     * @var array[] Look-up table of block sizes and key sizes for each supported OpenSSL cipher.
     *
     * In each element, the key is one of the ciphers supported by OpenSSL (@see openssl_get_cipher_methods()).
     * The value is an array of two integers, the first is the cipher's block size in bytes and the second is
     * the key size in bytes.
     *
     * > Warning: All OpenSSL ciphers that we recommend are in the default value, i.e. AES in CBC mode.
     *
     * > Note: Yii's encryption protocol uses the same size for cipher key, HMAC signature key and key
     * derivation salt.
     */
    public $allowedCiphers = [
        'AES-128-CBC' => [16, 16],
        'AES-192-CBC' => [16, 24],
        'AES-256-CBC' => [16, 32],
    ];
    /**
     * @var string Hash algorithm for key derivation. Recommend sha256, sha384 or sha512.
     * @see hash_algos()
     */
    public $kdfHash = 'sha256';
    /**
     * @var string Hash algorithm for message authentication. Recommend sha256, sha384 or sha512.
     * @see hash_algos()
     */
    public $macHash = 'sha256';
    /**
     * @var string HKDF info value for derivation of message authentication key.
     * @see hkdf()
     */
    public $authKeyInfo = 'AuthorizationKey';
    /**
     * @var integer derivation iterations count.
     * Set as high as possible to hinder dictionary password attacks.
     */
    public $derivationIterations = 100000;
    /**
     * @var string strategy, which should be used to generate password hash.
     * Available strategies:
     * - 'password_hash' - use of PHP `password_hash()` function with PASSWORD_DEFAULT algorithm.
     *   This option is recommended, but it requires PHP version >= 5.5.0
     * - 'crypt' - use PHP `crypt()` function.
     */
    public $passwordHashStrategy = 'crypt';
    /**
     * @var integer Default cost used for password hashing.
     * Allowed value is between 4 and 31.
     * @see generatePasswordHash()
     * @since 2.0.6
     */
    public $passwordHashCost = 13;


    /**
     * Generates specified number of random bytes.
     * Note that output may not be ASCII.
     * @see generateRandomString() if you need a string.
     *
     * @param integer $length the number of bytes to generate
     * @return string the generated random bytes
     * @throws Exception on failure.
     */
    public function generateRandomKey($length = 32)
    {
        /*
         * Strategy
         *
         * The most common platform is Linux, on which /dev/urandom is the best choice. Many other OSs
         * implement a device called /dev/urandom for Linux compat and it is good too. So if there is
         * a /dev/urandom then it is our first choice regardless of OS.
         *
         * Nearly all other modern Unix-like systems (the BSDs, Unixes and OS X) have a /dev/random
         * that is a good choice. If we didn't get bytes from /dev/urandom then we try this next but
         * only if the system is not Linux. Do not try to read /dev/random on Linux.
         *
         * Finally, OpenSSL can supply CSPR bytes. It is our last resort. On Windows this reads from
         * CryptGenRandom, which is the right thing to do. On other systems that don't have a Unix-like
         * /dev/urandom, it will deliver bytes from its own CSPRNG that is seeded from kernel sources
         * of randomness. Even though it is fast, we don't generally prefer OpenSSL over /dev/urandom
         * because an RNG in user space memory is undesirable.
         *
         * For background, see http://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/
         */

        $bytes = '';

        // If we are on Linux or any OS that mimics the Linux /dev/urandom device, e.g. FreeBSD or OS X,
        // then read from /dev/urandom.
        if (@file_exists('/dev/urandom')) {
            $handle = fopen('/dev/urandom', 'r');
            if ($handle !== false) {
                $bytes .= fread($handle, $length);
                fclose($handle);
            }
        }

        if (self::byteLength($bytes) >= $length) {
            return self::byteSubstr($bytes, 0, $length);
        }

        // If we are not on Linux and there is a /dev/random device then we have a BSD or Unix device
        // that won't block. It's not safe to read from /dev/random on Linux.
        if (PHP_OS !== 'Linux' && @file_exists('/dev/random')) {
            $handle = fopen('/dev/random', 'r');
            if ($handle !== false) {
                $bytes .= fread($handle, $length);
                fclose($handle);
            }
        }

        if (self::byteLength($bytes) >= $length) {
            return self::byteSubstr($bytes, 0, $length);
        }

        if (!extension_loaded('openssl')) {
            throw new Exception('The OpenSSL PHP extension is not installed.');
        }

        $bytes .= openssl_random_pseudo_bytes($length, $cryptoStrong);

        if (self::byteLength($bytes) < $length || !$cryptoStrong) {
            throw new Exception('Unable to generate random bytes.');
        }

        return self::byteSubstr($bytes, 0, $length);
    }

    /**
     * Generates a random string of specified length.
     * The string generated matches [A-Za-z0-9_-]+ and is transparent to URL-encoding.
     *
     * @param integer $length the length of the key in characters
     * @return string the generated random key
     * @throws InvalidConfigException if OpenSSL extension is needed but not installed.
     * @throws Exception on failure.
     */
    public function generateRandomString($length = 32)
    {
        $bytes = $this->generateRandomKey($length);
        // '=' character(s) returned by base64_encode() are always discarded because
        // they are guaranteed to be after position $length in the base64_encode() output.
        return strtr(substr(base64_encode($bytes), 0, $length), '+/', '_-');
    }

    /**
     * Generates a secure hash from a password and a random salt.
     *
     * The generated hash can be stored in database.
     * Later when a password needs to be validated, the hash can be fetched and passed
     * to [[validatePassword()]]. For example,
     *
     * ~~~
     * // generates the hash (usually done during user registration or when the password is changed)
     * $hash = Yii::$app->getSecurity()->generatePasswordHash($password);
     * // ...save $hash in database...
     *
     * // during login, validate if the password entered is correct using $hash fetched from database
     * if (Yii::$app->getSecurity()->validatePassword($password, $hash) {
     *     // password is good
     * } else {
     *     // password is bad
     * }
     * ~~~
     *
     * @param string $password The password to be hashed.
     * @param integer $cost Cost parameter used by the Blowfish hash algorithm.
     * The higher the value of cost,
     * the longer it takes to generate the hash and to verify a password against it. Higher cost
     * therefore slows down a brute-force attack. For best protection against brute-force attacks,
     * set it to the highest value that is tolerable on production servers. The time taken to
     * compute the hash doubles for every increment by one of $cost.
     * @return string The password hash string. When [[passwordHashStrategy]] is set to 'crypt',
     * the output is always 60 ASCII characters, when set to 'password_hash' the output length
     * might increase in future versions of PHP (http://php.net/manual/en/function.password-hash.php)
     * @throws Exception on bad password parameter or cost parameter.
     * @throws InvalidConfigException when an unsupported password hash strategy is configured.
     * @see validatePassword()
     */
    public function generatePasswordHash($password, $cost = null)
    {
        if ($cost === null) {
            $cost = $this->passwordHashCost;
        }

        switch ($this->passwordHashStrategy) {
            case 'password_hash':
                if (!function_exists('password_hash')) {
                    throw new Exception('Password hash key strategy "password_hash" requires PHP >= 5.5.0, either upgrade your environment or use another strategy.');
                }
                /** @noinspection PhpUndefinedConstantInspection */
                return password_hash($password, PASSWORD_DEFAULT, ['cost' => $cost]);
            case 'crypt':
                $salt = $this->generateSalt($cost);
                $hash = crypt($password, $salt);
                // strlen() is safe since crypt() returns only ascii
                if (!is_string($hash) || strlen($hash) !== 60) {
                    throw new Exception('Unknown error occurred while generating hash.');
                }
                return $hash;
            default:
                throw new Exception("Unknown password hash strategy '{$this->passwordHashStrategy}'");
        }
    }

    /**
     * Verifies a password against a hash.
     * @param string $password The password to verify.
     * @param string $hash The hash to verify the password against.
     * @return boolean whether the password is correct.
     * @throws ExceptionHandler on bad password/hash parameters or if crypt() with Blowfish hash is not available.
     * @throws InvalidConfigException when an unsupported password hash strategy is configured.
     * @see generatePasswordHash()
     */
    public function validatePassword($password, $hash)
    {

        try{
            if (!is_string($password) || $password === '') {
                throw new Exception('Password must be a string and cannot be empty.');
            }

            if (!preg_match('/^\$2[axy]\$(\d\d)\$[\.\/0-9A-Za-z]{22}/', $hash, $matches) || $matches[1] < 4 || $matches[1] > 30) {
                throw new Exception('Hash is invalid.');
            }

            switch ($this->passwordHashStrategy) {
                case 'password_hash':
                    if (!function_exists('password_verify')) {
                        throw new Exception('Password hash key strategy "password_hash" requires PHP >= 5.5.0, either upgrade your environment or use another strategy.');
                    }
                    return password_verify($password, $hash);
                case 'crypt':
                    $test = crypt($password, $hash);
                    $n = strlen($test);
                    if ($n !== 60) {
                        return false;
                    }
                    return $this->compareString($test, $hash);
                default:
                    throw new Exception("Unknown password hash strategy '{$this->passwordHashStrategy}'");
            }
        }catch (Exception $e){
            print_r($e->getMessage());
        }

    }

    /**
     * Generates a salt that can be used to generate a password hash.
     *
     * The PHP [crypt()](http://php.net/manual/en/function.crypt.php) built-in function
     * requires, for the Blowfish hash algorithm, a salt string in a specific format:
     * "$2a$", "$2x$" or "$2y$", a two digit cost parameter, "$", and 22 characters
     * from the alphabet "./0-9A-Za-z".
     *
     * @param integer $cost the cost parameter
     * @return string the random salt value.
     * @throws ExceptionHandler if the cost parameter is out of the range of 4 to 31.
     */
    protected function generateSalt($cost = 13)
    {
        $cost = (int) $cost;
        if ($cost < 4 || $cost > 31) {
            throw new Exception('Cost must be between 4 and 31.');
        }

        // Get a 20-byte random string
        $rand = $this->generateRandomKey(20);
        // Form the prefix that specifies Blowfish (bcrypt) algorithm and cost parameter.
        $salt = sprintf("$2y$%02d$", $cost);
        // Append the random salt data in the required base64 format.
        $salt .= str_replace('+', '.', substr(base64_encode($rand), 0, 22));

        return $salt;
    }

    /**
     * Performs string comparison using timing attack resistant approach.
     * @see http://codereview.stackexchange.com/questions/13512
     * @param string $expected string to compare.
     * @param string $actual user-supplied string.
     * @return boolean whether strings are equal.
     */
    public function compareString($expected, $actual)
    {
        $expected .= "\0";
        $actual .= "\0";
        $expectedLength = self::byteLength($expected);
        $actualLength = self::byteLength($actual);
        $diff = $expectedLength - $actualLength;
        for ($i = 0; $i < $actualLength; $i++) {
            $diff |= (ord($actual[$i]) ^ ord($expected[$i % $expectedLength]));
        }
        return $diff === 0;
    }

    public static function byteLength($string)
    {
        return mb_strlen($string, '8bit');
    }

    /**
     * Returns the portion of string specified by the start and length parameters.
     * This method ensures the string is treated as a byte array by using `mb_substr()`.
     * @param string $string the input string. Must be one character or longer.
     * @param integer $start the starting position
     * @param integer $length the desired portion length. If not specified or `null`, there will be
     * no limit on length i.e. the output will be until the end of the string.
     * @return string the extracted part of string, or FALSE on failure or an empty string.
     * @see http://www.php.net/manual/en/function.substr.php
     */
    public static function byteSubstr($string, $start, $length = null)
    {
        return mb_substr($string, $start, $length === null ? mb_strlen($string, '8bit') : $length, '8bit');
    }
}
