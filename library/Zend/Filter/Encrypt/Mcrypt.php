<?php
/**
 * Zend Framework
 *
 * LICENSE
 *
 * This source file is subject to the new BSD license that is bundled
 * with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://framework.zend.com/license/new-bsd
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@zend.com so we can send you a copy immediately.
 *
 * @category   Zend
 * @package    Zend_Filter
 * @copyright  Copyright (c) 2005-2015 Zend Technologies USA Inc. (http://www.zend.com)
 * @license    http://framework.zend.com/license/new-bsd     New BSD License
 * @version    $Id$
 */

/**
 * @see Zend_Filter_Encrypt_Interface
 */
require_once 'Zend/Filter/Encrypt/Interface.php';

/** @see Zend_Crypt_Math */
require_once 'Zend/Crypt/Math.php';

/**
 * Encryption adapter for mcrypt
 *
 * @category   Zend
 * @package    Zend_Filter
 * @copyright  Copyright (c) 2005-2015 Zend Technologies USA Inc. (http://www.zend.com)
 * @license    http://framework.zend.com/license/new-bsd     New BSD License
 */
class Zend_Filter_Encrypt_Mcrypt implements Zend_Filter_Encrypt_Interface
{
    /**
     * Definitions for encryption
     * array(
     *     'key' => encryption key string
     *     'algorithm' => algorithm to use
     *     'algorithm_directory' => directory where to find the algorithm
     *     'mode' => encryption mode to use
     *     'modedirectory' => directory where to find the mode
     * )
     */
    protected $_encryption = array(
        'key'                 => 'ZendFramework',
        'algorithm'           => 'blowfish',
        'algorithm_directory' => '',
        'mode'                => 'cbc',
        'mode_directory'      => '',
        'vector'              => null,
        'salt'                => false
    );

    /**
     * Internal compression
     *
     * @var array
     */
    protected $_compression;

    protected static $_srandCalled = false;

    /**
     * Class constructor
     *
     * @param string|array|Zend_Config $options Cryption Options
     */
    public function __construct($options)
    {
        if (!extension_loaded('mcrypt')) {
            require_once 'Zend/Filter/Exception.php';
            throw new Zend_Filter_Exception('This filter needs the mcrypt extension');
        }

        if ($options instanceof Zend_Config) {
            $options = $options->toArray();
        } elseif (is_string($options)) {
            $options = array('key' => $options);
        } elseif (!is_array($options)) {
            require_once 'Zend/Filter/Exception.php';
            throw new Zend_Filter_Exception('Invalid options argument provided to filter');
        }

        if (array_key_exists('compression', $options)) {
            $this->setCompression($options['compression']);
            unset($options['compress']);
        }

        $this->setEncryption($options);
    }

    /**
     * Returns the set encryption options
     *
     * @return array
     */
    public function getEncryption()
    {
        return $this->_encryption;
    }

    /**
     * Sets new encryption options
     *
     * @param  string|array $options Encryption options
     * @return Zend_Filter_File_Encryption
     */
    public function setEncryption()
    {
        require_once 'Zend/Filter/Exception.php';
        throw new Zend_Filter_Exception('Mcrypt functions have been removed in PHP 7.2');
    }

    /**
     * Returns the set vector
     *
     * @return string
     */
    public function getVector()
    {
        return $this->_encryption['vector'];
    }

    /**
     * Sets the initialization vector
     *
     * @param string $vector (Optional) Vector to set
     * @return Zend_Filter_Encrypt_Mcrypt
     */
    public function setVector()
    {
        require_once 'Zend/Filter/Exception.php';
        throw new Zend_Filter_Exception('Mcrypt functions have been removed in PHP 7.2');
    }

    /**
     * Returns the compression
     *
     * @return array
     */
    public function getCompression()
    {
        return $this->_compression;
    }

    /**
     * Sets a internal compression for values to encrypt
     *
     * @param string|array $compression
     * @return Zend_Filter_Encrypt_Mcrypt
     */
    public function setCompression($compression)
    {
        if (is_string($this->_compression)) {
            $compression = array('adapter' => $compression);
        }

        $this->_compression = $compression;
        return $this;
    }

    /**
     * Defined by Zend_Filter_Interface
     *
     * Encrypts $value with the defined settings
     *
     * @param  string $value The content to encrypt
     * @return string The encrypted content
     */
    public function encrypt($value)
    {
        require_once 'Zend/Filter/Exception.php';
        throw new Zend_Filter_Exception('Mcrypt functions have been removed in PHP 7.2');
    }

    /**
     * Defined by Zend_Filter_Interface
     *
     * Decrypts $value with the defined settings
     *
     * @param  string $value Content to decrypt
     * @return string The decrypted content
     */
    public function decrypt($value)
    {
        require_once 'Zend/Filter/Exception.php';
        throw new Zend_Filter_Exception('Mcrypt functions have been removed in PHP 7.2');
    }

    /**
     * Returns the adapter name
     *
     * @return string
     */
    public function toString()
    {
        return 'Mcrypt';
    }

    /**
     * Open a cipher
     *
     * @throws Zend_Filter_Exception When the cipher can not be opened
     * @return resource Returns the opened cipher
     */
    protected function _openCipher()
    {
        require_once 'Zend/Filter/Exception.php';
        throw new Zend_Filter_Exception('Mcrypt functions have been removed in PHP 7.2');
    }

    /**
     * Close a cipher
     *
     * @param  resource $cipher Cipher to close
     * @return Zend_Filter_Encrypt_Mcrypt
     */
    protected function _closeCipher()
    {
        require_once 'Zend/Filter/Exception.php';
        throw new Zend_Filter_Exception('Mcrypt functions have been removed in PHP 7.2');
    }

    /**
     * Initialises the cipher with the set key
     *
     * @param  resource $cipher
     * @throws
     * @return resource
     */
    protected function _initCipher($cipher)
    {
        require_once 'Zend/Filter/Exception.php';
        throw new Zend_Filter_Exception('Mcrypt functions have been removed in PHP 7.2');
    }

    /**
     * _srand() interception
     *
     * @see ZF-8742
     */
    protected function _srand()
    {
        if (version_compare(PHP_VERSION, '5.3.0', '>=')) {
            return;
        }
        if (!self::$_srandCalled) {
            srand(Zend_Crypt_Math::randInteger(0, PHP_INT_MAX));
            self::$_srandCalled = true;
        }
    }
}
