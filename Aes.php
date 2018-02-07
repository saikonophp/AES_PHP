<?php

define('AES_128_CBC', 'aes-128-cbc');
define('AES_192_CBC', 'aes-192-cbc');
define('AES_256_CBC', 'aes-256-cbc');


class saikonophpAes
{
    private $encryption_key;
    private $iv;
    private $encryption_type;

    public function __construct($encryption_key, $iv, $encryption_type = 'AES128')
    {
        if($encryption_type == null)
            $this->encryption_type = AES_128_CBC;
        else
            $encryption_type = strtolower($encryption_type);

        if($encryption_type == "aes128")
            $this->encryption_type = AES_128_CBC;
        else if($encryption_type == "aes192")
            $this->encryption_type = AES_192_CBC;
        else if($encryption_type == "aes256")
            $this->encryption_type = AES_256_CBC;

        if($encryption_key == null)
        {
            if($this->encryption_type == AES_128_CBC)
                $this->encryption_key = openssl_random_pseudo_bytes(128);
            else if($this->encryption_type == AES_192_CBC)
                $this->encryption_key = openssl_random_pseudo_bytes(192);
            else if($this->encryption_type == AES_256_CBC)
                $this->encryption_key = openssl_random_pseudo_bytes(256);
        }
        else
        {
            $this->encryption_key = base64_decode($encryption_key);
        }
		
		if($iv == null)
		{
			$this->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->encryption_type));
		}
		else
		{
			$this->iv = base64_decode($iv);
		}
    }

    public function encrypt($plaintext)
    {
        $plaintext = base64_encode($plaintext);
        return openssl_encrypt($plaintext, $this->encryption_type, $this->encryption_key, 0, $this->iv);
    }

    public function decrypt($plaintext)
    {
        return base64_decode(openssl_decrypt($plaintext, $this->encryption_type, $this->encryption_key, 0, $this->iv));
    }

	public function setEncryptionKey($setEncryptionKey)
    {
        $this->encryption_key = base64_decode($setEncryptionKey);
    }
	public function setIvKey($setIvKey)
    {
        $this->iv = base64_decode($setIvKey);
    }
    public function setEncryptionType($setEncryptionType)
    {
        if($setEncryptionType == null)
        {
            $this->encryption_type = AES_128_CBC;
            return;
        }

        $setEncryptionType = strtolower($setEncryptionType);

        if($setEncryptionType == "aes128")
            $this->encryption_type = AES_128_CBC;
        else if($setEncryptionType == "aes192")
            $this->encryption_type = AES_192_CBC;
        else if($setEncryptionType == "aes256")
            $this->encryption_type = AES_256_CBC;
    }

    public function getEncryptionKey()
    {
        return base64_encode($this->encryption_key);
    }

    public function getIvKey()
    {
        return base64_encode($this->iv);
    }
    public function getEncryptionType()
    {
        if($this->encryption_type == AES_128_CBC)
            return 'AES128';
        else if($this->encryption_type == AES_192_CBC)
            return 'AES192';
        else if($this->encryption_type == AES_256_CBC)
            return 'AES256';
    }

    public function generateNewEncryptionKey($encryption_type = 'AES128')
    {
        if($encryption_type == null)
            return base64_encode(openssl_random_pseudo_bytes(128));
        else
            $encryption_type = strtolower($encryption_type);

        if($encryption_type == "aes128")
            return base64_encode(openssl_random_pseudo_bytes(128));
        else if($encryption_type == "aes192")
            return base64_encode(openssl_random_pseudo_bytes(192));
        else if($encryption_type == "aes256")
            return base64_encode(openssl_random_pseudo_bytes(256));
    }
    public function generateNewIvKey($encryption_type)
    {
        if($encryption_type == null)
            return base64_encode(openssl_random_pseudo_bytes(openssl_cipher_iv_length(AES_128_CBC)));
        else
            $encryption_type = strtolower($encryption_type);

        if($encryption_type == "aes128")
            return base64_encode(openssl_random_pseudo_bytes(openssl_cipher_iv_length(AES_128_CBC)));
        else if($encryption_type == "aes192")
            return base64_encode(openssl_random_pseudo_bytes(openssl_cipher_iv_length(AES_192_CBC)));
        else if($encryption_type == "aes256")
            return base64_encode(openssl_random_pseudo_bytes(openssl_cipher_iv_length(AES_256_CBC)));
    }
    public function selectRandomEncryptionType()
    {
        try {
            $num = random_int(1, 3);
        } catch (Exception $e) {
            echo 'Failed to create random number. ' . $e . PHP_EOL;
        }
        if (!empty($num)) {
            switch ($num) {
                case 1:
                    $this->encryption_type = AES_128_CBC;
                    return $this->getEncryptionType();
                case 2:
                    $this->encryption_type = AES_192_CBC;
                    return $this->getEncryptionType();
                case 3:
                    $this->encryption_type = AES_256_CBC;
                    return $this->getEncryptionType();
            }
        }
        return 'error';
    }
}
