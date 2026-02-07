<?php
/**
 * Copyright 2024-2026 NETCAT (www.netcat.pl)
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
 * @copyright 2024-2026 NETCAT (www.netcat.pl)
 * @license http://www.apache.org/licenses/LICENSE-2.0
 */

namespace KsefApi;

use CurlHandle;
use Exception;
use KsefApi\Model\BoxDownloadInvoicesRequest;
use KsefApi\Model\BoxDownloadInvoicesResponse;
use KsefApi\Model\BoxUploadBatchRequest;
use KsefApi\Model\BoxUploadBatchResponse;
use KsefApi\Model\BoxUploadBatchStatusResponse;
use KsefApi\Model\BoxUploadInvoiceRequest;
use KsefApi\Model\BoxUploadInvoiceResponse;
use KsefApi\Model\BoxUploadInvoiceStatusResponse;
use KsefApi\Model\Error;
use KsefApi\Model\ErrorResult;
use KsefApi\Model\Faktura;
use KsefApi\Model\KsefInvoiceGenerateRequest;
use KsefApi\Model\KsefInvoiceQueryStartRequest;
use KsefApi\Model\KsefInvoiceQueryStartResponse;
use KsefApi\Model\KsefInvoiceQueryStatusResponse;
use KsefApi\Model\KsefInvoiceSendRequest;
use KsefApi\Model\KsefInvoiceSendResponse;
use KsefApi\Model\KsefInvoiceStatusResponse;
use KsefApi\Model\KsefInvoiceValidateResponse;
use KsefApi\Model\KsefInvoiceVisualizeRequest;
use KsefApi\Model\KsefPublicKeyResponse;
use KsefApi\Model\KsefSessionCloseResponse;
use KsefApi\Model\KsefSessionInvoicesResponse;
use KsefApi\Model\KsefSessionOpenBatchRequest;
use KsefApi\Model\KsefSessionOpenBatchResponse;
use KsefApi\Model\KsefSessionOpenOnlineRequest;
use KsefApi\Model\KsefSessionOpenOnlineResponse;
use KsefApi\Model\KsefSessionStatusResponse;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use SplFileObject;

/**
 * KSEF API service client
 */
class KsefApiClient
{
    const VERSION = '2.0.2';

    const PRODUCTION_URL = 'https://ksefapi.pl/api';
    const TEST_URL = 'https://ksefapi.pl/api-test';

    private string $url;
    private string $id;
    private string $key;
    private string $app;

    private ?Error $error;

    /**
     * Construct a new service client object
     * @param string $url KSEF API URL (KsefApiClient::PRODUCTION_URL, KsefApiClient::TEST_URL)
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
     * Set application info
     * @param string $app app info
     */
    public function setApp(string $app): void
    {
        $this->app = $app;
    }

    /**
     * Generate new init vector for AES256
     * @return string|false new init vector
     */
    public function generateInitVector(): string|false
    {
        // clear error
        $this->clear();

        return $this->getRandomBytes(16);
    }

    /**
     * Generate a new AES256 key
     * @return string|false new key
     */
    public function generateKey(): string|false
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
    public function encryptKey(KsefPublicKeyResponse $publicKey, string $key): string|false
    {
        // clear error
        $this->clear();

        // pkey object
        $pem = "-----BEGIN PUBLIC KEY-----\n" . $publicKey->getPublicKey() . "\n-----END PUBLIC KEY-----";

        try {
            $pk = PublicKeyLoader::load($pem);
        } catch (Exception) {
            $this->set(ClientError::CLI_PKEY_FORMAT);
            return false;
        }

        // encrypt
        if ($publicKey->getAlgorithm() === 'RSA') {
            $enc = $pk->withPadding(RSA::ENCRYPTION_OAEP)->withMGFHash('sha256')->withHash('sha256')->encrypt($key);
            if (! $enc) {
                $this->set(ClientError::CLI_RSA_ENCRYPT);
                return false;
            }
        } else {
            $this->set(ClientError::CLI_PKEY_ALG);
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
    public function encryptData(string $iv, string $key, string $data): string|false
    {
        // clear error
        $this->clear();

        $aes = new AES('cbc');
        $aes->setIV($iv);
        $aes->setKey($key);

        $enc = $aes->encrypt($data);
        if (! $enc) {
            $this->set(ClientError::CLI_AES_ENCRYPT);
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
    public function decryptData(string $iv, string $key, string $encrypted): string|false
    {
        // clear error
        $this->clear();

        $aes = new AES('cbc');
        $aes->setIV($iv);
        $aes->setKey($key);

        $data = $aes->decrypt($encrypted);
        if (! $data) {
            $this->set(ClientError::CLI_AES_DECRYPT);
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
    public function ksefPublicKey(): KsefPublicKeyResponse|false
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
     * Open a new KSeF online session
     * @param KsefSessionOpenOnlineRequest $req request object
     * @return KsefSessionOpenOnlineResponse|false session details
     */
    public function ksefSessionOpenOnline(KsefSessionOpenOnlineRequest $req): KsefSessionOpenOnlineResponse|false
    {
        // clear error
        $this->clear();

        // send request
        $body = $this->sendObject($req);
        if (! $body) {
            return false;
        }

        $url = ($this->url . '/invoice/session/open/online');

        $res = $this->send($url, 'application/json', $body, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefSessionOpenOnlineResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefSessionOpenOnlineResponse');

        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Open a new KSeF batch session
     * @param KsefSessionOpenBatchRequest $req request object
     * @return KsefSessionOpenBatchResponse|false session details
     */
    public function ksefSessionOpenBatch(KsefSessionOpenBatchRequest $req): KsefSessionOpenBatchResponse|false
    {
        // clear error
        $this->clear();

        // send request
        $body = $this->sendObject($req);
        if (! $body) {
            return false;
        }

        $url = ($this->url . '/invoice/session/open/batch');

        $res = $this->send($url, 'application/json', $body, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefSessionOpenBatchResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefSessionOpenBatchResponse');

        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Get KSeF session status
     * @param string $sessionId session id
     * @return KsefSessionStatusResponse|false session status
     */
    public function ksefSessionStatus(string $sessionId): KsefSessionStatusResponse|false
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

        return $obj;
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
     * Get session's invoices info
     * @param string $sessionId session id
     * @return KsefSessionInvoicesResponse|false list of invoices info
     */
    public function ksefSessionInvoices(string $sessionId): KsefSessionInvoicesResponse|false
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/session/invoices/' . urlencode($sessionId));

        $res = $this->send($url, null, null, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefSessionInvoicesResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefSessionInvoicesResponse');

        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Get UPO for specified session
     * @param string $sessionId session id
     * @return string|false XML with UPO
     */
    public function ksefSessionUpo(string $sessionId): string|false
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
    public function ksefInvoiceGenerate(Faktura $invoice): string|false
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
    public function ksefInvoiceValidate(string $invoiceXml): KsefInvoiceValidateResponse|false
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
     * @param KsefInvoiceSendRequest $req request object
     * @return KsefInvoiceSendResponse|false sending result with invoice id
     */
    public function ksefInvoiceSend(KsefInvoiceSendRequest $req): KsefInvoiceSendResponse|false
    {
        // clear error
        $this->clear();

        // send request
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
    public function ksefInvoiceStatus(string $invoiceId): KsefInvoiceStatusResponse|false
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
     * @param string $ksefRefNumber invoice KSeF reference number
     * @return string|false invoice XML
     */
    public function ksefInvoiceGet(string $ksefRefNumber): string|false
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/get/' . urlencode($ksefRefNumber));

        $res = $this->send($url, null, null, array('text/xml', 'application/json'));
        if (! $res) {
            return false;
        }

        return $res;
    }

    /**
     * Start a new invoice query
     * @param KsefInvoiceQueryStartRequest $req request object
     * @return string|false new query id
     */
    public function ksefInvoiceQueryStart(KsefInvoiceQueryStartRequest $req): string|false
    {
        // clear error
        $this->clear();

        // send request
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
     * @param string $queryId query id
     * @return KsefInvoiceQueryStatusResponse|false array of result parts numbers
     */
    public function ksefInvoiceQueryStatus(string $queryId): KsefInvoiceQueryStatusResponse|false
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/query/status/' . urlencode($queryId));

        $res = $this->send($url, null, null, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var KsefInvoiceQueryStatusResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\KsefInvoiceQueryStatusResponse');

        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Get data for specified query part
     * @param string $queryId query id
     * @param string $partNumber query part number
     * @return string|false encrypted ZIP archive with invoices
     */
    public function ksefInvoiceQueryResult(string $queryId, string $partNumber): string|false
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/invoice/query/result/' . urlencode($queryId) . '/' . urlencode($partNumber));

        $res = $this->send($url, null, null, array('application/octet-stream', 'application/json'));
        if (! $res) {
            return false;
        }

        return $res;
    }

    /**
     * Generate visualization of an invoice
     * @param KsefInvoiceVisualizeRequest $req request object
     * @return string|false invoice visualization in requested format
     */
    public function ksefInvoiceVisualize(KsefInvoiceVisualizeRequest $req): string|false
    {
        // clear error
        $this->clear();

        // send request
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
     * Upload plain invoice XML to KSeF
     * @param BoxUploadInvoiceRequest $req request object
     * @return bool upload result
     */
    public function boxUploadInvoice(BoxUploadInvoiceRequest $req): bool
    {
        // clear error
        $this->clear();

        // send request
        $body = $this->sendObject($req);
        if (! $body) {
            return false;
        }

        $url = ($this->url . '/box/upload/invoice');

        $res = $this->send($url, 'application/json', $body, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var BoxUploadInvoiceResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\BoxUploadInvoiceResponse');

        if (! $obj) {
            return false;
        }

        return $obj->getResult();
    }

    /**
     * Get status of uploaded invoice
     * @param string $uploadId upload identifier
     * @return BoxUploadInvoiceStatusResponse|false upload result
     */
    public function boxUploadInvoiceStatus(string $uploadId): BoxUploadInvoiceStatusResponse|false
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/box/upload/invoice/' . urlencode($uploadId));

        $res = $this->send($url, null, null, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var BoxUploadInvoiceStatusResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\BoxUploadInvoiceStatusResponse');

        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Upload batch of plain invoices XMLs to KSeF
     * @param BoxUploadBatchRequest $req request object
     * @param SplFileObject|string $file batch file data
     * @return bool upload result
     */
    public function boxUploadBatch(BoxUploadBatchRequest $req, SplFileObject|string $file): bool
    {
        // clear error
        $this->clear();

        // boundary
        if (!($bytes = $this->getRandomBytes(18))) {
            return false;
        }
        $boundary = base64_encode($bytes);

        // send request
        $body = $this->sendObjectWithZip($boundary, $req, $file);
        if ($body === false) {
            return false;
        }

        $url = ($this->url . '/box/upload/batch');

        $res = $this->send($url, 'multipart/form-data; boundary=' . $boundary, $body, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var BoxUploadBatchResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\BoxUploadBatchResponse');

        if (! $obj) {
            return false;
        }

        return $obj->getResult();
    }

    /**
     * Get status of uploaded batch
     * @param string $uploadId upload identifier
     * @return BoxUploadBatchStatusResponse|false upload result
     */
    public function boxUploadBatchStatus(string $uploadId): BoxUploadBatchStatusResponse|false
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/box/upload/batch/' . urlencode($uploadId));

        $res = $this->send($url, null, null, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var BoxUploadBatchStatusResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\BoxUploadBatchStatusResponse');

        if (! $obj) {
            return false;
        }

        return $obj;
    }

    /**
     * Send query for invoice download
     * @param BoxDownloadInvoicesRequest $req request object
     * @return bool sending result
     */
    public function boxDownloadInvoices(BoxDownloadInvoicesRequest $req): bool
    {
        // clear error
        $this->clear();

        // send request
        $body = $this->sendObject($req);
        if (! $body) {
            return false;
        }

        $url = ($this->url . '/box/download/invoices');

        $res = $this->send($url, 'application/json', $body, array('application/json'));
        if (! $res) {
            return false;
        }

        // parse response
        /** @var BoxDownloadInvoicesResponse $obj */
        $obj = $this->getObject($res, '\KsefApi\Model\BoxDownloadInvoicesResponse');

        if (! $obj) {
            return false;
        }

        return $obj->getResult();
    }

    /**
     * Get status of download query
     * @param string $downloadId download identifier
     * @return string|false download result (ZIP archive)
     */
    public function boxDownloadInvoicesResult(string $downloadId): string|false
    {
        // clear error
        $this->clear();

        // send request
        $url = ($this->url . '/box/download/invoices/' . urlencode($downloadId));

        $res = $this->send($url, null, null, array('application/zip', 'application/json'));
        if (! $res) {
            return false;
        }

        return $res;
    }

    /**
     * Get the last error message
     * @return ?Error error message
     */
    public function getLastError(): ?Error
    {
        return $this->error;
    }

    /**
     * Clear error
     */
    private function clear(): void
    {
        $this->error = null;
    }

    /**
     * Set last error information
     * @param int $code error code
     * @param string|null $description error description
     * @param string|null $details error details
     */
    private function set(int $code, ?string $description = null, ?string $details = null): void
    {
        $this->error = new Error();

        $this->error->setCode($code);
        $this->error->setDescription(empty($description) ? ClientError::message($code) : $description);

        if (!empty($details)) {
            $this->error->setDetails($details);
        }
    }

    /**
     * Generate random bytes
     * @param int $length bytes required
     * @return string|false random bytes
     */
    private function getRandomBytes(int $length): string|false
    {
        try {
            return random_bytes($length);
        } catch (Exception) {
            return false;
        }
    }

    /**
     * Prepare authorization header content
     * @return string|false
     */
    private function auth(): string|false
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
     * @param CurlHandle $curl
     */
    private function setCurlOpt(CurlHandle $curl): void
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
     * @param string|array|null $body request body (null for GET)
     * @param array $accept requested response MIME types
     * @return string|false
     */
    private function send(string $url, string|null $type, string|array|null $body, array $accept): string|false
    {
        // auth
        $auth = $this->auth();

        if (! $auth) {
            $this->set(ClientError::CLI_AUTH);
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
            if (is_string($body)) {
                $len = strlen($body);
            } else if (is_array($body)) {
                $len = strlen($body['prefix']) + $body['file']->getSize() + strlen($body['suffix']);
            } else {
                $this->set(ClientError::CLI_SEND);
                return false;
            }

            $headers[] = 'Content-Type: ' . $type;
            $headers[] = 'Content-Length: ' . $len;
        }

        // send request
        $curl = curl_init();

        if (! $curl) {
            $this->set(ClientError::CLI_CONNECT);
            return false;
        }

        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_POST, $post);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

        if ($post) {
            curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'POST');

            if (is_string($body)) {
                curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
            } else if (is_array($body)) {
                curl_setopt($curl, CURLOPT_READFUNCTION, function($ch, $fd, $length) use (&$body) {
                    if ($body['phase'] === 'prefix') {
                        $data = substr($body['prefix'], 0, $length);
                        $body['prefix'] = substr($body['prefix'], strlen($data));

                        if (strlen($data) > 0) {
                            return $data;
                        } else {
                            $body['phase'] = 'file';
                        }
                    }

                    if ($body['phase'] === 'file') {
                        $data = ($body['file']->eof() ? '' : $body['file']->fread($length));
                        if ($data === false) {
                            return false;
                        }
                        if (strlen($data) > 0) {
                            return $data;
                        } else {
                            $body['phase'] = 'suffix';
                        }
                    }

                    if ($body['phase'] === 'suffix') {
                        $data = substr($body['suffix'], 0, $length);
                        $body['suffix'] = substr($body['suffix'], strlen($data));

                        if (strlen($data) > 0) {
                            return $data;
                        }
                    }

                    return '';
                });
            } else {
                $this->set(ClientError::CLI_SEND);
                return false;
            }
        }

        $this->setCurlOpt($curl);
        $res = curl_exec($curl);

        if (! $res) {
            $this->set(ClientError::CLI_CONNECT, null, curl_error($curl));
            return false;
        }

        if (!($code = curl_getinfo($curl, CURLINFO_HTTP_CODE))) {
            $this->set(ClientError::CLI_CONNECT, null, curl_error($curl));
            return false;
        }

        curl_close($curl);

        if ($code !== 200) {
            $obj = json_decode($res, false);

            if (! $obj) {
                $this->set(ClientError::CLI_RESPONSE);
                return false;
            }

            $err = ObjectSerializer::deserialize($obj, '\KsefApi\Model\ErrorResult');

            if ($err instanceof ErrorResult && $err->getError()) {
                $this->set($err->getError()->getCode(), $err->getError()->getDescription(), $err->getError()->getDetails());
            } else {
                $this->set(ClientError::CLI_RESPONSE);
            }

            return false;
        }

        return $res;
    }

    /**
     * Convert HTTP response into a class object
     * @param string $res HTTP response
     * @param string $class output object class name
     * @return object|false
     */
    private function getObject(string $res, string $class): object|false
    {
        $obj = json_decode($res, false);

        if (! $obj) {
            $this->set(ClientError::CLI_RESPONSE);
            return false;
        }

        $cla = ObjectSerializer::deserialize($obj, $class);

        if (! $cla) {
            $this->set(ClientError::CLI_RESPONSE);
            return false;
        }

        return $cla;
    }

    /**
     * Convert a class object into HTTP request
     * @param object $obj request object
     * @return string|false
     */
    private function sendObject(object $obj): string|false
    {
        $body = ObjectSerializer::sanitizeForSerialization($obj);

        if (! $body) {
            $this->set(ClientError::CLI_SEND);
            return false;
        }

        $json = json_encode($body);

        if (! $json) {
            $this->set(ClientError::CLI_SEND);
            return false;
        }

        return $json;
    }

    /**
     * Convert a class object and ZIP file into multipart HTTP body
     * @param string $boundary boundary name
     * @param object $obj request object
     * @param SplFileObject|string $file ZIP file content
     * @return array|string|false
     */
    private function sendObjectWithZip(string $boundary, object $obj, SplFileObject|string $file): array|string|false
    {
        if (!($json = $this->sendObject($obj))) {
            return false;
        }

        $prefix = "--" . $boundary . "\r\n"
            . "Content-Disposition: form-data; name=\"request\"\r\n"
            . "Content-Type: application/json\r\n"
            . "\r\n"
            . $json . "\r\n"
            . "--" . $boundary . "\r\n"
            . "Content-Disposition: form-data; name=\"file\"; filename=\"batch.zip\"\r\n"
            . "Content-Type: application/zip\r\n"
            . "\r\n";

        $suffix = "\r\n"
            . "--" . $boundary . "--\r\n";

        if (is_string($file)) {
            return ($prefix . $file . $suffix);
        } else if ($file instanceof SplFileObject) {
            return [
                'phase' => 'prefix',
                'prefix' => $prefix,
                'file' => $file,
                'suffix' => $suffix
            ];
        } else {
            $this->set(ClientError::CLI_SEND);
            return false;
        }
    }
}

/* EOF */
