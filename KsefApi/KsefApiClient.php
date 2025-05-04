<?php
/**
 * Copyright 2023-2024 NETCAT (www.netcat.pl)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * @author NETCAT <firma@netcat.pl>
 * @copyright 2023-2024 NETCAT (www.netcat.pl)
 * @license http://www.apache.org/licenses/LICENSE-2.0
 */

namespace KsefApi;

use DateTime;
use KsefApi\Model\ErrorResult;
use KsefApi\Model\Faktura;
use KsefApi\Model\KsefInvoiceEncrypted;
use KsefApi\Model\KsefInvoiceGenerateRequest;
use KsefApi\Model\KsefInvoicePlain;
use KsefApi\Model\KsefInvoiceQueryStartRange;
use KsefApi\Model\KsefInvoiceQueryStartRequest;
use KsefApi\Model\KsefInvoiceQueryStartResponse;
use KsefApi\Model\KsefInvoiceSendRequest;
use KsefApi\Model\KsefInvoiceSendResponse;
use KsefApi\Model\KsefInvoiceStatusResponse;
use KsefApi\Model\KsefInvoiceValidateResponse;
use KsefApi\Model\KsefInvoiceVisualizeRequest;
use KsefApi\Model\KsefPublicKeyResponse;
use KsefApi\Model\KsefSessionCloseResponse;
use KsefApi\Model\KsefSessionOpenRequest;
use KsefApi\Model\KsefSessionOpenResponse;
use KsefApi\Model\KsefSessionStatusResponse;

/**
 * KSEF API service client
 */
class KsefApiClient
{
    const VERSION = '1.2.3';

    const PRODUCTION_URL = 'https://ksefapi.pl/api';
    const TEST_URL = 'https://ksefapi.pl/api-test';
    const NIP24_URL = 'https://www.nip24.pl/api/ksef';
    
    const ENC_ALG = 'aes-256-cbc';

    private $url;
    private $id;
    private $key;
    private $app;

    private $errcode;
    private $err;

    /**
     * Register KSEF API's PSR-0 autoloader
     */
    public static function registerAutoloader()
    {
        spl_autoload_register(__NAMESPACE__ . '\\KsefApiClient::autoload');
    }

    /**
     * KSEF API PSR-0 autoloader
     */
    public static function autoload($className)
    {
        $className = str_replace('KsefApi\\', '', $className);
        $path = __DIR__ . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, $className) . '.php';

        if (file_exists($path)) {
            require $path;
        }
    }

    /**
     * Construct new service client object
     * @param string $url KSEF API URL (KsefApiClient::PRODUCTION_URL, KsefApiClient::TEST_URL or KsefApiClient::NIP24_URL)
     * @param string $id KSEF API key identifier
     * @param string $key KSEF API key
     */
    public function __construct(string $url, string $id, string $key)
    {
        $this->url = $url;
        $this->id = $id;
        $this->key = $key;

        $this->app = '';
        $this->clear();
    }

    /**
     * Set non default service URL
     * @param string $url service URL
     */
    public function setURL(string $url)
    {
        $this->url = $url;
    }

    /**
     * Set application info
     * @param string $app app info
     */
    public function setApp(string $app)
    {
        $this->app = $app;
    }

    /**
     * Generate new init vector for AES256
     * @return string|false new init vector
     */
    public function generateInitVector()
    {
        // clear error
        $this->clear();

        return $this->getRandomBytes(16);
    }

    /**
     * Generate new AES256 key
     * @return string|false new key
     */
    public function generateKey()
    {
        // clear error
        $this->clear();

        return $this->getRandomBytes(32);
    }

    /**
     * Encrypt AES256 key with KSeF public key
     * @param KsefPublicKeyResponse $publicKey KSeF public key
     * @param string $key AES256 key to encrypt
     * @return string|false encrypted AES256 key
     */
    public function encryptKey(KsefPublicKeyResponse $publicKey, string $key)
    {
        // clear error
        $this->clear();

        // pkey object
        $pem = "-----BEGIN PUBLIC KEY-----\n" . $publicKey->getPublicKey() . "\n-----END PUBLIC KEY-----";

        $pk = openssl_pkey_get_public($pem);
        if (! $pk) {
            $this->set(Error::CLI_PKEY_FORMAT);
            return false;
        }

        // encrypt
        if ($publicKey->getAlgorithm() === 'RSA') {
            if (!openssl_public_encrypt($key, $enc, $pk, OPENSSL_PKCS1_PADDING)) {
                $this->set(Error::CLI_RSA_ENCRYPT);
                return false;
            }
        } else {
            $this->set(Error::CLI_PKEY_ALG);
            return false;
        }

        return $enc;
    }

    /**
     * Encrypt data with AES256 key
     * @param string $iv init vector
     * @param string $key AES256 key
     * @param string $data data to encrypt
     * @return string|false encrypted data
     */
    public function encryptData(string $iv, string $key, string $data)
    {
        // clear error
        $this->clear();

        $enc = openssl_encrypt($data, self::ENC_ALG, $key, OPENSSL_RAW_DATA, $iv);
        if (! $enc) {
            $this->set(Error::CLI_AES_ENCRYPT);
            return false;
        }

        return $enc;
    }

    /**
     * Decrypt data with AES256 key
     * @param string $iv init vector
     * @param string $key AES256 key
     * @param string $encrypted encrypted data
     * @return string|false decrypted plain data
     */
    public function decryptData(string $iv, string $key, string $encrypted)
    {
        // clear error
        $this->clear();

        $data = openssl_decrypt($encrypted, self::ENC_ALG, $key, OPENSSL_RAW_DATA, $iv);
        if (! $data) {
            $this->set(Error::CLI_AES_DECRYPT);
            return false;
        }

        return $data;
    }

    /**
     * Get SHA256 hash
     * @param string $data input data
     * @return string output hash as raw binary string
     */
    public function getHash(string $data): string
    {
        // clear error
        $this->clear();

        return hash('sha256', $data, true);
    }

    /**
     * Get KSeF public key
     * @return KsefPublicKeyResponse|false KSeF public key for encryption
     */
    public function ksefPublicKey()
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/public/key');

        $res = $this->send($url, null, null, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefPublicKeyResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefPublicKeyResponse');
        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Open a new KSeF session
     * @param string $invoiceVersion requested invoice schema version as KsefInvoiceVersion const value
     * @param string|null $initVector optional AES256 init vector (base64, 32 chars)
     * @param string|null $encryptedKey optional encrypted AES256 key (base64, 512 chars)
     * @return KsefSessionOpenResponse|false session details
     */
    public function ksefSessionOpen(string $invoiceVersion, string $initVector = null, string $encryptedKey = null)
    {
        // clear error
        $this->clear();

        // send request
        $req = new KsefSessionOpenRequest();
        $req->setInvoiceVersion($invoiceVersion);
        $req->setInitVector($initVector);
        $req->setEncryptedKey($encryptedKey);

        $body = $this->sendObject($req);
        if (! $body) {
            return false;
        }

        $url = ($this->url . '/invoice/session/open');

        $res = $this->send($url, 'application/json', $body, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefSessionOpenResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefSessionOpenResponse');

        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Get KSeF session status
     * @param string $sessionId session id
     * @return string|false session status
     */
    public function ksefSessionStatus(string $sessionId)
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/session/status/' . urlencode($sessionId));

        $res = $this->send($url, null, null, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefSessionStatusResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefSessionStatusResponse');

        if (! $obj) {
            return false;
        }

        return $obj->getStatus();
    }

    /**
     * Close KSeF session
     * @param string $sessionId session id
     * @return bool closing result
     */
    public function ksefSessionClose(string $sessionId): bool
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/session/close/' . urlencode($sessionId));

        $res = $this->send($url, null, null, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefSessionCloseResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefSessionCloseResponse');

        if (! $obj) {
            return false;
        }

        return $obj->getResult();
    }

    /**
     * Get UPO for specified session
     * @param string $sessionId session id
     * @return string|false XML with UPO
     */
    public function ksefSessionUpo(string $sessionId)
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/session/upo/' . urlencode($sessionId));

        $res = $this->send($url, null, null, array('text/xml', 'application/json'));
        if (! $res) {
            return false;
        }

        // return response
        return $res;
    }

    /**
     * Generate an invoice XML
     * @param Faktura $invoice invoice object
     * @return string|false invoice XML
     */
    public function ksefInvoiceGenerate(Faktura $invoice)
    {
        // clear error
        $this->clear();

        // send request
        $req = new KsefInvoiceGenerateRequest();
        $req->setInvoice($invoice);

        $body = $this->sendObject($req);
        if (! $body) {
            return false;
        }

        $url = ($this->url . '/invoice/generate');

        $res = $this->send($url, 'application/json', $body, array('text/xml', 'application/json'));
        if (! $res) {
            return false;
        }

        // return response
        return $res;
    }

    /**
     * Validate invoice XML against XSD schema
     * @param string $invoiceXml invoice XML
     * @return KsefInvoiceValidateResponse|false validation result
     */
    public function ksefInvoiceValidate(string $invoiceXml)
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/validate');

        $res = $this->send($url, 'text/xml', $invoiceXml, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefInvoiceValidateResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefInvoiceValidateResponse');

        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Send an invoice
     * @param string $sessionId session id
     * @param int $size plain invoice size in bytes (only for encrypted data)
     * @param string|null $hash plain invoice SHA256 hash (only for encrypted data)
     * @param string $data plain or encrypted invoice data
     * @return KsefInvoiceSendResponse|false sending result with invoice id
     */
    public function ksefInvoiceSend(string $sessionId, int $size, ?string $hash, string $data)
    {
        // clear error
        $this->clear();

        // send request
        $req = new KsefInvoiceSendRequest();
        $req->setSessionId($sessionId);

        if (empty($size) && empty($hash)) {
            $plain = new KsefInvoicePlain();
            $plain->setInvoice(base64_encode($data));
            $req->setPlain($plain);
        } else {
            $encrypted = new KsefInvoiceEncrypted();
            $encrypted->setInvoiceSize($size);
            $encrypted->setInvoiceHash(base64_encode($hash));
            $encrypted->setEncryptedInvoice(base64_encode($data));
            $req->setEncrypted($encrypted);
        }

        $body = $this->sendObject($req);
        if (! $body) {
            return false;
        }

        $url = ($this->url . '/invoice/send');

        $res = $this->send($url, 'application/json', $body, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefInvoiceSendResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefInvoiceSendResponse');

        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Get status of specified invoice
     * @param string $invoiceId invoice id
     * @return KsefInvoiceStatusResponse|false invoice status including KSeF ref number and acquisition timestamp
     */
    public function ksefInvoiceStatus(string $invoiceId)
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/status/' . urlencode($invoiceId));

        $res = $this->send($url, null, null, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefInvoiceStatusResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefInvoiceStatusResponse');

        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Get an invoice
     * @param string $sessionId session id
     * @param string $ksefRefNumber invoice KSeF reference number
     * @return string|false invoice XML as plain or encrypted data (depends on session type)
     */
    public function ksefInvoiceGet(string $sessionId, string $ksefRefNumber)
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/get/' . urlencode($sessionId) . '/' . urlencode($ksefRefNumber));

        $res = $this->send($url, null, null, array('application/octet-stream', 'text/xml', 'application/json'));
        if (! $res) {
            return false;
        }

        return $res;
    }

    /**
     * Start new invoice query
     * @param string $sessionId session id
     * @param string $subjectType invoice subject type (subject1, subject2, subject3, subjectAuthorized)
     * @param DateTime $from begin of range
     * @param DateTime $to end of range
     * @return string|false new query id
     */
    public function ksefInvoiceQueryStart(string $sessionId, $subjectType, DateTime $from, DateTime $to)
    {
        // clear error
        $this->clear();

        // send request
        $range = new KsefInvoiceQueryStartRange();
        $range->setFrom($from);
        $range->setTo($to);

        $req = new KsefInvoiceQueryStartRequest();
        $req->setSessionId($sessionId);
        $req->setSubjectType($subjectType);
        $req->setRange($range);

        $body = $this->sendObject($req);
        if (! $body) {
            return false;
        }

        $url = ($this->url . '/invoice/query/start');

        $res = $this->send($url, 'application/json', $body, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefInvoiceQueryStartResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefInvoiceQueryStartResponse');

        if (! $obj) {
            return false;
        }

        return $obj->getQueryId();
    }

    /**
     * Get current status of query
     * @param string $sessionId session id
     * @param string $queryId query id
     * @return array|false array of result parts numbers
     */
    public function ksefInvoiceQueryStatus(string $sessionId, string $queryId)
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/query/status/' . urlencode($sessionId) . '/' . urlencode($queryId));

        $res = $this->send($url, null, null, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var array $obj */
        $obj = $this->getObject($res, 'string[]');

        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Get data for specified query part
     * @param string $sessionId session id
     * @param string $queryId query id
     * @param string $partNumber query part number
     * @return string|false plain or encrypted ZIP archive with invoices (depends on session type)
     */
    public function ksefInvoiceQueryResult(string $sessionId, string $queryId, string $partNumber)
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/query/result/' . urlencode($sessionId) . '/' . urlencode($queryId)
            . '/' . urlencode($partNumber));

        $res = $this->send($url, null, null, array('application/octet-stream', 'application/zip', 'application/json'));
        if (! $res) {
            return false;
        }

        return $res;
    }

    /**
     * Generate visualization of an invoice
     * @param string $ksefRefNumber KSeF reference number
     * @param string $invoice invoice XML data
     * @param bool $logo include logo
     * @param bool $qrcode include qr-code
     * @param string $format output format (html or pdf)
     * @param string $lang output language (pl)
     * @return string|false invoice visualization in requested format
     */
    public function ksefInvoiceVisualize(string $ksefRefNumber, string $invoice, bool $logo, bool $qrcode,
                                         string $format, string $lang)
    {
        // clear error
        $this->clear();

        // send request
        $req = new KsefInvoiceVisualizeRequest();
        $req->setIncludeLogo($logo);
        $req->setIncludeQrCode($qrcode);
        $req->setOutputFormat($format);
        $req->setOutputLanguage($lang);
        $req->setInvoiceKsefNumber($ksefRefNumber);
        $req->setInvoiceData(base64_encode($invoice));

        $body = $this->sendObject($req);
        if (! $body) {
            return false;
        }

        $url = ($this->url . '/invoice/visualize');

        $res = $this->send($url, 'application/json', $body, array('application/pdf', 'text/html', 'application/json'));
        if (! $res) {
            return false;
        }

        return $res;
    }

	/**
     * Get last error code
     * @return int error code
     */
    public function getLastErrorCode(): int
    {
        return $this->errcode;
    }

    /**
     * Get last error message
     * @return string error message
     */
    public function getLastError(): string
    {
        return $this->err;
    }

    /**
     * Clear error
     */
    private function clear()
    {
        $this->errcode = 0;
        $this->err = '';
    }

    /**
     * Set error details
     * @param int $code error code
     * @param string $err error message
     */
    private function set(int $code, string $err = '')
    {
        $this->errcode = $code;
        $this->err = (empty($err) ? Error::message($code) : $err);
    }

    /**
     * Generate random bytes
     * @param int $length bytes required
     * @return string|false random bytes
     */
    private function getRandomBytes(int $length)
    {
        // try 10 times
        for ($i = 0; $i < 10; $i++) {
            try {
                $strong = false;
                $bytes = openssl_random_pseudo_bytes($length, $strong);

                if ($bytes && $strong) {
                    return $bytes;
                }
            } catch (\Exception $e) {
            }
        }

        return false;
    }

    /**
     * Prepare authorization header content
     * @return string|false
     */
    private function auth()
    {
        // prepare auth header
        $basic = base64_encode($this->id . ':' . $this->key);
        
        if (! $basic) {
            return false;
        }
        
        return 'Authorization: Basic ' . $basic;
    }

    /**
     * Prepare user agent information header content
     * @return string
     */
    private function userAgent(): string
    {
        return 'User-Agent: ' . (! empty($this->app) ? $this->app . ' ' : '') . 'KsefApiClient/' . self::VERSION
            . ' PHP/' . phpversion();
    }

    /**
     * Set some common CURL options
     * @param resource $curl
     */
    private function setCurlOpt($curl)
    {
        if (strtoupper(substr(PHP_OS, 0, 3)) == 'WIN') {
            // curl on a windows does not know where to look for certificates
            // use local info downloaded from https://curl.haxx.se/docs/caextract.html
            curl_setopt($curl, CURLOPT_CAINFO, __DIR__ . DIRECTORY_SEPARATOR . 'cacert.pem');
        }
        
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
    }

    /**
     * Send HTTP request and read server's response
     * @param string $url target URL
     * @param string|null $type request content type (null for GET)
     * @param string|null $body request body (null for GET)
     * @param array $accept requested response MIME types
     * @return string|false
     */
    private function send(string $url, ?string $type, ?string $body, array $accept)
    {
        // auth
        $auth = $this->auth();

        if (! $auth) {
            $this->set(Error::CLI_AUTH);
            return false;
        }

        // method
        $post = !empty($type);

        // headers
        $headers = array(
            'Accept: ' . implode(', ', $accept),
            $auth,
            $this->userAgent()
        );

        if ($post) {
            $headers[] = 'Content-Type: ' . $type;
            $headers[] = 'Content-Length: ' . strlen($body);
        }

        // send request
        $curl = curl_init();

        if (! $curl) {
            $this->set(Error::CLI_CONNECT);
            return false;
        }

        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_POST, $post);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

        if ($post) {
            error_log('Request: ' . print_r($body, true));
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }

        $this->setCurlOpt($curl);
        $res = curl_exec($curl);

        if (! $res) {
            $this->set(Error::CLI_CONNECT, curl_error($curl));
            return false;
        }

        if (!($code = curl_getinfo($curl, CURLINFO_HTTP_CODE))) {
            $this->set(Error::CLI_CONNECT, curl_error($curl));
            return false;
        }

        curl_close($curl);

        if ($code !== 200) {
            error_log('Response: ' . print_r($res, true));
            $obj = json_decode($res, false);

            if (! $obj) {
                $this->set(Error::CLI_RESPONSE);
                return false;
            }

            $err = ObjectSerializer::deserialize($obj, '\KsefApi\Model\ErrorResult');

            if ($err instanceof ErrorResult && $err->getError()) {
                $this->set($err->getError()->getCode(), $err->getError()->getDescription());
            } else {
                $this->set(Error::CLI_RESPONSE);
            }

            return false;
        }

        return $res;
    }

    /**
     * Convert class object into HTTP request
     * @param object $obj request object
     * @return string|false
     */
    private function sendObject(object $obj)
    {
        $body = ObjectSerializer::sanitizeForSerialization($obj);

        if (! $body) {
            $this->set(Error::CLI_SEND);
            return false;
        }

        $json = json_encode($body);

        if (! $json) {
            $this->set(Error::CLI_SEND);
            return false;
        }

        return $json;
    }

    /**
     * Convert HTTP response into class object
     * @param string $res HTTP response
     * @param string $class output object class name
     * @return object|false
     */
    private function getObject(string $res, string $class)
    {
        $obj = json_decode($res, false);

        if (! $obj) {
            $this->set(Error::CLI_RESPONSE);
            return false;
        }

        $cla = ObjectSerializer::deserialize($obj, $class);

        if (! $cla) {
            $this->set(Error::CLI_RESPONSE);
            return false;
        }

        return $cla;
    }
}

/* EOF */
