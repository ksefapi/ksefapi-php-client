<?php
    // enable debug information
    ini_set('display_errors', 1);
    error_reporting(E_ALL);

    // load ksefapi lib (and all dependencies)
    require_once __DIR__ . '/../vendor/autoload.php';

    // some helper functions
    function obj2json($obj) {
        header('Content-Type: application/json');
        return json_encode(\KsefApi\ObjectSerializer::sanitizeForSerialization($obj));
    }

    function err2json(\KsefApi\KsefApiClient $client) {
        $obj = new stdClass();
        $obj->code = $client->getLastError()->getCode();
        $obj->description = $client->getLastError()->getDescription();
        $obj->details = $client->getLastError()->getDetails();

        http_response_code(400);
        header('Content-Type: application/json');
        return json_encode($obj);
    }

    function code2json($code, $description) {
        $obj = new stdClass();
        $obj->code = $code;
        $obj->description = $description;
        $obj->details = null;

        http_response_code(400);
        header('Content-Type: application/json');
        return json_encode($obj);
    }

    // new ksef api client
    $ksef_api = new \KsefApi\KsefApiClient(\KsefApi\KsefApiClient::TEST_URL, 'enter valid api id here', 'enter valid api key here');

    // backend functions (HTTP POST)
    $fun = ($_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST['fun'] : null);

    if ($fun === 'generateInitVector') {
        // generate new iv
        $res_iv = $ksef_api->generateInitVector();
        if ($res_iv) {
            $obj = new stdClass();
            $obj->iv = base64_encode($res_iv);
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'generateKey') {
        // generate new key
        $res_k = $ksef_api->generateKey();
        if ($res_k) {
            $obj = new stdClass();
            $obj->key = base64_encode($res_k);
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'encryptKey') {
        $pkey = new \KsefApi\Model\KsefPublicKeyResponse();
        $pkey->setAlgorithm('RSA');
        $pkey->setPublicKey($_POST['public_key']);
        $res_ek = $ksef_api->encryptKey($pkey, base64_decode($_POST['key']));
        if ($res_ek) {
            $obj = new stdClass();
            $obj->encryptedKey = base64_encode($res_ek);
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'encryptData') {
        $res_ed = $ksef_api->encryptData(base64_decode($_POST['iv']), base64_decode($_POST['key']),
            base64_decode($_POST['data']));
        if ($res_ed) {
            $obj = new stdClass();
            $obj->encryptedData = base64_encode($res_ed);
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'decryptData') {
        $res_dd = $ksef_api->decryptData(base64_decode($_POST['iv']), base64_decode($_POST['key']),
            base64_decode($_POST['encrypted']));
        if ($res_dd) {
            $obj = new stdClass();
            $obj->data = base64_encode($res_dd);
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'getHash') {
        $res_gh = $ksef_api->getHash(base64_decode($_POST['data']));
        if ($res_gh) {
            $obj = new stdClass();
            $obj->hash = base64_encode($res_gh);
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefPublicKey') {
        // get public key
        $res_pk = $ksef_api->ksefPublicKey();
        if ($res_pk) {
            echo obj2json($res_pk);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefSessionOpen') {
        // open session
        $ei = new \KsefApi\Model\EncryptionInfo();
        $ei->setInitVector($_POST['iv']);
        $ei->setEncryptedKey($_POST['enc_key']);

        $req = new \KsefApi\Model\KsefSessionOpenOnlineRequest();
        $req->setInvoiceVersion(\KsefApi\Model\KsefInvoiceVersion::V3);
        $req->setEncryptionInfo($ei);

        $res_so = $ksef_api->ksefSessionOpenOnline($req);
        if ($res_so) {
            echo obj2json($res_so);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefSessionStatus') {
        // session status
        $res_ss = $ksef_api->ksefSessionStatus($_POST['session_id']);
        if ($res_ss) {
            echo obj2json($res_ss);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefSessionClose') {
        // close session
        $res_sc = $ksef_api->ksefSessionClose($_POST['session_id']);
        if ($res_sc) {
            $obj = new stdClass();
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefSessionUpo') {
        // get upo
        $res_su = $ksef_api->ksefSessionUpo($_POST['session_id']);
        if ($res_su) {
            $obj = new stdClass();
            $obj->upo = base64_encode($res_su);
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceGenerate') {
        // generate invoice xml
        $invoice = \KsefApi\ObjectSerializer::deserialize(
                json_decode(base64_decode($_POST['invoice']), false),
                '\KsefApi\Model\Faktura');
        if (! $invoice instanceof \KsefApi\Model\Faktura) {
            echo code2json(350, 'JSON faktury ma nieprawidłową składnię');
            die();
        }
        $res_ig = $ksef_api->ksefInvoiceGenerate($invoice);
        if ($res_ig) {
            $obj = new stdClass();
            $obj->xml = base64_encode($res_ig);
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceValidate') {
        // invoice validate
        $res_iv = $ksef_api->ksefInvoiceValidate(base64_decode($_POST['invoice']));
        if ($res_iv) {
            echo obj2json($res_iv);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceSend') {
        // send invoice
        $enc = new \KsefApi\Model\KsefInvoiceEncrypted();
        $enc->setInvoiceSize($_POST['size']);
        $enc->setInvoiceHash($_POST['hash']);
        $enc->setEncryptedInvoice($_POST['data']);

        $req = new \KsefApi\Model\KsefInvoiceSendRequest();
        $req->setSessionId($_POST['session_id']);
        $req->setEncrypted($enc);

        $res_is = $ksef_api->ksefInvoiceSend($req);
        if ($res_is) {
            echo obj2json($res_is);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceStatus') {
        // invoice status
        $res_is = $ksef_api->ksefInvoiceStatus($_POST['invoice_id']);
        if ($res_is) {
            echo obj2json($res_is);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceGet') {
        // invoice get
        $res_ig = $ksef_api->ksefInvoiceGet($_POST['invoice_num']);
        if ($res_ig) {
            header('Content-Type: text/xml; charset=UTF-8');
            header('Content-Disposition: attachment; filename="faktura.xml"');
            echo $res_ig;
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceQueryStart') {
        // start query
        $ei = new \KsefApi\Model\EncryptionInfo();
        $ei->setInitVector($_POST['iv']);
        $ei->setEncryptedKey($_POST['enc_key']);

        $range = new \KsefApi\Model\KsefInvoiceQueryStartRange();
        $range->setFrom(DateTime::createFromFormat('Y-m-d', $_POST['from']));
        $range->setTo(DateTime::createFromFormat('Y-m-d', $_POST['to']));

        $req = new \KsefApi\Model\KsefInvoiceQueryStartRequest();
        $req->setEncryptionInfo($ei);
        $req->setSubjectType($_POST['subject_type']);
        $req->setRange($range);

        $res_iqs = $ksef_api->ksefInvoiceQueryStart($req);
        if ($res_iqs) {
            $obj = new stdClass();
            $obj->queryId = $res_iqs;
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceQueryStatus') {
        // query status
        $res_iqs = $ksef_api->ksefInvoiceQueryStatus($_POST['query_id']);
        if ($res_iqs) {
            echo obj2json($res_iqs);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceQueryResult') {
        // query result
        $res_iqr = $ksef_api->ksefInvoiceQueryResult($_POST['query_id'], $_POST['part_num']);
        if ($res_iqr) {
            header('Content-Type: application/octet-stream');
            header('Content-Length: ' . strlen($res_iqr));
            header('Content-Disposition: attachment; filename="faktury.zip.aes"');
            echo $res_iqr;
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceVisualize') {
        // visualization
        $req = new \KsefApi\Model\KsefInvoiceVisualizeRequest();
        $req->setOffline(false);
        $req->setInvoiceKsefNumber($_POST['invoice_num']);
        $req->setInvoiceData($_POST['invoice']);
        $req->setOutputFormat($_POST['format']);
        $req->setOutputLanguage('pl');

        $res_iv = $ksef_api->ksefInvoiceVisualize($req);
        if ($res_iv) {
            header('Content-Type: ' . $_POST['format'] === 'html' ? 'text/html; charset=UTF-8' : 'application/pdf');
            header('Content-Disposition: attachment; filename="faktura.' . $_POST['format'] . '"');
            echo $res_iv;
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'boxUploadInvoice') {
        $req = new \KsefApi\Model\BoxUploadInvoiceRequest();
        $req->setUploadId($_POST['upload_id']);
        $req->setOffline($_POST['offline'] === 'true');
        $req->setNotify(false);
        $req->setInvoiceData($_POST['invoice']);

        $res_ui = $ksef_api->boxUploadInvoice($req);
        if ($res_ui) {
            $obj = new stdClass();
            $obj->result = true;
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'boxUploadInvoiceStatus') {
        $res_uis = $ksef_api->boxUploadInvoiceStatus($_POST['upload_id']);
        if ($res_uis) {
            echo obj2json($res_uis);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'boxUploadBatch') {
        $req = new \KsefApi\Model\BoxUploadBatchRequest();
        $req->setUploadId($_POST['upload_id']);
        $req->setOffline($_POST['offline'] === 'true');
        $req->setNotify(false);
        $req->setInvoiceVersion($_POST['invoice_version']);

        $res_ub = $ksef_api->boxUploadBatch($req, base64_decode($_POST['batch']));
        if ($res_ub) {
            $obj = new stdClass();
            $obj->result = true;
            echo obj2json($obj);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'boxUploadBatchStatus') {
        $res_ubs = $ksef_api->boxUploadBatchStatus($_POST['upload_id']);
        if ($res_ubs) {
            echo obj2json($res_ubs);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'boxDownloadInvoices') {
        $range = new \KsefApi\Model\KsefInvoiceQueryStartRange();
        $range->setFrom(DateTime::createFromFormat('Y-m-d', $_POST['from']));
        $range->setTo(DateTime::createFromFormat('Y-m-d', $_POST['to']));

        $req = new \KsefApi\Model\BoxDownloadInvoicesRequest();
        $req->setDownloadId($_POST['download_id']);
        $req->setNotify(false);
        $req->setSubjectType($_POST['subject_type']);
        $req->setRange($range);

        $res_di = $ksef_api->boxDownloadInvoices($req);
        $obj = new stdClass();
        $obj->result = $res_di;
        echo obj2json($obj);
        die();
    } else if ($fun === 'boxDownloadInvoicesResult') {
        $res_dir = $ksef_api->boxDownloadInvoicesResult($_POST['download_id']);
        if ($res_dir) {
            header('Content-Type: application/zip');
            header('Content-Length: ' . strlen($res_dir));
            header('Content-Disposition: attachment; filename="faktury.zip"');
            echo $res_dir;
        } else {
            echo err2json($ksef_api);
        }
        die();
    }
?>
<!doctype html>
<html lang="pl">
	<head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>KSEF API Client - Przykład użycia</title>

        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
        <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
	</head>

	<body>
        <div class="container">
            <form>
                <div class="row mb-3">
                    <div class="col">
                        <h3>Klucz publiczny KSeF</h3>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="pkey-get" type="button" class="btn btn-sm btn-primary">Pobierz klucz</button>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="pkey" class="form-label">Klucz publiczny (ASN.1 SubjectPublicKeyInfo w base64)</label>
                        <input id="pkey" type="text" class="form-control">
                        <div id="pkey-err" class="text-danger"></div>
                    </div>
                </div>

                <div class="row mb-3">
                    <div class="col">
                        <h3>Zarządzanie sesją</h3>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="session-iv" class="form-label">Init vector</label>
                        <input id="session-iv" type="text" class="form-control">
                    </div>
                    <div class="col">
                        <label for="session-key" class="form-label">Klucz AES256</label>
                        <input id="session-key" type="text" class="form-control">
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="session-new-ivkey" type="button" class="btn btn-sm btn-primary">Nowy init vector i klucz</button>
                        <button id="session-new" type="button" class="btn btn-sm btn-primary">Nowa sesja online</button>
                        <button id="session-check" type="button" class="btn btn-sm btn-primary">Status sesji</button>
                        <button id="session-close" type="button" class="btn btn-sm btn-primary">Zamknij sesję</button>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="session-id" class="form-label">ID sesji</label>
                        <input id="session-id" type="text" class="form-control">
                        <div id="session-status" class="text-success"></div>
                    </div>
                    <div class="col">
                        <label for="session-enc-key" class="form-label">Zaszyfrowany klucz AES256</label>
                        <input id="session-enc-key" type="text" class="form-control">
                    </div>
                </div>

                <div class="row mb-3">
                    <div class="col">
                        <h3>Wysyłanie faktury</h3>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="invoice" class="form-label">Faktura (XML, należy dostosować dane przed wysłaniem)</label>
                        <textarea id="invoice" class="form-control"></textarea>
                        <div id="invoice-status" class="text-success"></div>
                        <div id="invoice-err" class="text-danger"></div>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="invoice-validate" type="button" class="btn btn-sm btn-primary">Weryfikuj XML faktury</button>
                        <button id="invoice-send" type="button" class="btn btn-sm btn-primary">Wyślij fakturę</button>
                        <button id="invoice-check" type="button" class="btn btn-sm btn-primary">Status faktury</button>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="invoice-id" class="form-label">ID faktury (otrzymany po wysłaniu faktury)</label>
                        <input id="invoice-id" type="text" class="form-control">
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="invoice-num" class="form-label">Numer faktury nadany przez KSeF (po sprawdzeniu statusu faktury)</label>
                        <input id="invoice-num" type="text" class="form-control">
                    </div>
                    <div class="col">
                        <label for="invoice-date" class="form-label">Data faktury nadana przez KSeF (po sprawdzeniu statusu faktury)</label>
                        <input id="invoice-date" type="text" class="form-control">
                    </div>
                </div>

                <div class="row mb-3">
                    <div class="col">
                        <h3>UPO</h3>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="session-upo" type="button" class="btn btn-sm btn-primary">Pobierz UPO</button>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="upo" class="form-label">UPO (XML, tylko dla zamkniętej sesji, w której zostały wysłane jakieś faktury)</label>
                        <textarea id="upo" class="form-control"></textarea>
                    </div>
                </div>

                <div class="row mb-3">
                    <div class="col">
                        <h3>Pobieranie faktury</h3>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="get-invoice-num" class="form-label">Numer faktury nadany przez KSeF</label>
                        <input id="get-invoice-num" type="text" class="form-control">
                        <div id="get-invoice-err" class="text-danger"></div>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="get-invoice" type="button" class="btn btn-sm btn-primary">Pobierz fakturę</button>
                    </div>
                </div>

                <div class="row mb-3">
                    <div class="col">
                        <h3>Wyszukiwanie faktur</h3>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="query-subject" class="form-label">Typ podmiotu</label>
                        <select id="query-subject" class="form-select">
                            <option value="Subject1">Subject1 (Podmiot 1 - sprzedawca)</option>
                            <option value="Subject2">Subject2 (Podmiot 2 - nabywca)</option>
                            <option value="Subject3">Subject3 (Podmiot 3)</option>
                            <option value="SubjectAuthorized">SubjectAuthorized (Podmiot upoważniony)</option>
                        </select>
                        <div id="query-err" class="text-danger"></div>
                    </div>
                    <div class="col">
                        <label for="query-from" class="form-label">Data od (yyyy-mm-dd)</label>
                        <input id="query-from" type="text" class="form-control" value="<?= date('Y-m-d') ?>">
                    </div>
                    <div class="col">
                        <label for="query-to" class="form-label">Data do (yyyy-mm-dd)</label>
                        <input id="query-to" type="text" class="form-control" value="<?= date('Y-m-d') ?>">
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="query-start" type="button" class="btn btn-sm btn-primary">Rozpocznij wyszukiwanie</button>
                        <button id="query-status" type="button" class="btn btn-sm btn-primary">Status zapytania</button>
                        <button id="query-result" type="button" class="btn btn-sm btn-primary">Pobierz wynik</button>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="query-id" class="form-label">ID zapytania</label>
                        <input id="query-id" type="text" class="form-control">
                    </div>
                    <div class="col">
                        <label for="query-part" class="form-label">Numer części wyniku</label>
                        <select id="query-part" class="form-select"></select>
                    </div>
                </div>

                <div class="row mb-3">
                    <div class="col">
                        <h3>Wizualizacja faktury</h3>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="invoice-format" class="form-label">Format</label>
                        <select id="invoice-format" class="form-select">
                            <option value="html">HTML</option>
                            <option value="pdf">PDF</option>
                        </select>
                        <div id="invoice-visualize-err" class="text-danger"></div>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="invoice-visualize" type="button" class="btn btn-sm btn-primary">Wizualizacja faktury</button>
                    </div>
                </div>

                <hr/>

                <div class="row mb-3">
                    <div class="col">
                        <h3>Black Box - Wysłanie faktury</h3>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="upload-invoice-id" class="form-label">ID wysyłki (unikalne ID nadane przez użytkownika)</label>
                        <input id="upload-invoice-id" type="text" class="form-control">
                    </div>
                    <div class="col">
                        <label for="upload-invoice-offline" class="form-label">Tryb przesyłania</label>
                        <select id="upload-invoice-offline" class="form-select">
                            <option value="false" selected>Online</option>
                            <option value="true">Offline</option>
                        </select>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="upload-invoice-id-new" type="button" class="btn btn-sm btn-primary">Nowe ID</button>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="upload-invoice-file" class="form-label">Faktura (plik XML)</label>
                        <input id="upload-invoice-file" type="file" accept=".xml" class="form-control"/>
                        <div id="upload-invoice-res" class="text-success"></div>
                        <div id="upload-invoice-err" class="text-danger"></div>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="upload-invoice" type="button" class="btn btn-sm btn-primary">Wyślij fakturę</button>
                        <button id="upload-invoice-status" type="button" class="btn btn-sm btn-primary">Sprawdź status wysyłki</button>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="upload-invoice-num" class="form-label">Numer faktury nadany przez KSeF (po sprawdzeniu statusu wysyłki)</label>
                        <input id="upload-invoice-num" type="text" class="form-control">
                    </div>
                    <div class="col">
                        <label for="upload-invoice-date" class="form-label">Data faktury nadana przez KSeF (po sprawdzeniu statusu wysyłki)</label>
                        <input id="upload-invoice-date" type="text" class="form-control">
                    </div>
                </div>

                <div class="row mb-3">
                    <div class="col">
                        <h3>Black Box - Wysłanie paczki faktur</h3>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="upload-batch-id" class="form-label">ID wysyłki (unikalne ID nadane przez użytkownika)</label>
                        <input id="upload-batch-id" type="text" class="form-control">
                    </div>
                    <div class="col">
                        <label for="upload-batch-offline" class="form-label">Tryb przesyłania</label>
                        <select id="upload-batch-offline" class="form-select">
                            <option value="false" selected>Online</option>
                            <option value="true">Offline</option>
                        </select>
                    </div>
                    <div class="col">
                        <label for="upload-batch-ver" class="form-label">Wersja schematu XML faktur w paczce</label>
                        <select id="upload-batch-ver" class="form-select">
                            <option value="v3" selected>FA (3)</option>
                        </select>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="upload-batch-id-new" type="button" class="btn btn-sm btn-primary">Nowe ID</button>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="upload-batch-file" class="form-label">Paczka faktur (plik ZIP)</label>
                        <input id="upload-batch-file" type="file" accept=".zip" class="form-control"/>
                        <div id="upload-batch-res" class="text-success"></div>
                        <div id="upload-batch-err" class="text-danger"></div>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="upload-batch" type="button" class="btn btn-sm btn-primary">Wyślij paczkę faktur</button>
                        <button id="upload-batch-status" type="button" class="btn btn-sm btn-primary">Sprawdź status wysyłki</button>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="upload-batch-info" class="form-label">Status faktur z paczki (po sprawdzeniu statusu wysyłki)</label>
                        <textarea id="upload-batch-info" class="form-control"></textarea>
                    </div>
                </div>

                <div class="row mb-3">
                    <div class="col">
                        <h3>Black Box - Pobieranie faktur</h3>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <label for="download-invoices-id" class="form-label">ID zlecenia (unikalne ID nadane przez użytkownika)</label>
                        <input id="download-invoices-id" type="text" class="form-control">
                    </div>
                    <div class="col">
                        <label for="download-invoices-subject" class="form-label">Typ podmiotu</label>
                        <select id="download-invoices-subject" class="form-select">
                            <option value="Subject1">Subject1 (Podmiot 1 - sprzedawca)</option>
                            <option value="Subject2">Subject2 (Podmiot 2 - nabywca)</option>
                            <option value="Subject3">Subject3 (Podmiot 3)</option>
                            <option value="SubjectAuthorized">SubjectAuthorized (Podmiot upoważniony)</option>
                        </select>
                    </div>
                    <div class="col">
                        <label for="download-invoices-from" class="form-label">Data od (yyyy-mm-dd)</label>
                        <input id="download-invoices-from" type="text" class="form-control" value="<?= date('Y-m-d') ?>">
                    </div>
                    <div class="col">
                        <label for="download-invoices-to" class="form-label">Data do (yyyy-mm-dd)</label>
                        <input id="download-invoices-to" type="text" class="form-control" value="<?= date('Y-m-d') ?>">
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <div id="download-invoices-res" class="text-danger"></div>
                        <div id="download-invoices-err" class="text-danger"></div>
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="download-invoices-id-new" type="button" class="btn btn-sm btn-primary">Nowe ID</button>
                        <button id="download-invoices" type="button" class="btn btn-sm btn-primary">Wyślij zlecenie pobrania</button>
                        <button id="download-invoices-status" type="button" class="btn btn-sm btn-primary">Sprawdź status</button>
                    </div>
                </div>
            </form>
        </div>
    </body>

    <script>
        const sampleInvoice = 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPEZha3R1cmEgeG1sbnM6ZXRkPSJodHRwOi8vY3JkLmdvdi5wbC94bWwvc2NoZW1hdHkvZHppZWR6aW5vd2UvbWYvMjAyMi8wMS8wNS9lRC9EZWZpbmljamVUeXB5LyIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIKeG1sbnM9Imh0dHA6Ly9jcmQuZ292LnBsL3d6b3IvMjAyNS8wNi8yNS8xMzc3NS8iPgoJPE5hZ2xvd2VrPgoJCTxLb2RGb3JtdWxhcnphIGtvZFN5c3RlbW93eT0iRkEgKDMpIiB3ZXJzamFTY2hlbXk9IjEtMEUiPkZBPC9Lb2RGb3JtdWxhcnphPgoJCTxXYXJpYW50Rm9ybXVsYXJ6YT4zPC9XYXJpYW50Rm9ybXVsYXJ6YT4KCQk8RGF0YVd5dHdvcnplbmlhRmE+MjAyNi0wMi0wMVQwMDowMDowMFo8L0RhdGFXeXR3b3J6ZW5pYUZhPgoJCTxTeXN0ZW1JbmZvPlNhbXBsb0Zha3R1cjwvU3lzdGVtSW5mbz4KCTwvTmFnbG93ZWs+Cgk8UG9kbWlvdDE+CgkJPERhbmVJZGVudHlmaWthY3lqbmU+CgkJCTxOSVA+OTk5OTk5OTk5OTwvTklQPgoJCQk8TmF6d2E+QUJDIEFHRCBzcC4geiBvLiBvLjwvTmF6d2E+CgkJPC9EYW5lSWRlbnR5ZmlrYWN5am5lPgoJCTxBZHJlcz4KCQkJPEtvZEtyYWp1PlBMPC9Lb2RLcmFqdT4KCQkJPEFkcmVzTDE+dWwuIEt3aWF0b3dhIDEgbS4gMjwvQWRyZXNMMT4KCQkJPEFkcmVzTDI+MDAtMDAxIFdhcnN6YXdhPC9BZHJlc0wyPgoJCTwvQWRyZXM+CgkJPERhbmVLb250YWt0b3dlPgoJCQk8RW1haWw+YWJjQGFiYy5wbDwvRW1haWw+CgkJCTxUZWxlZm9uPjY2NzQ0NDU1NTwvVGVsZWZvbj4KCQk8L0RhbmVLb250YWt0b3dlPgoJPC9Qb2RtaW90MT4KCTxQb2RtaW90Mj4KCQk8RGFuZUlkZW50eWZpa2FjeWpuZT4KCQkJPE5JUD4xMTExMTExMTExPC9OSVA+CgkJCTxOYXp3YT5GLkguVS4gSmFuIEtvd2Fsc2tpPC9OYXp3YT4KCQk8L0RhbmVJZGVudHlmaWthY3lqbmU+CgkJPEFkcmVzPgoJCQk8S29kS3JhanU+UEw8L0tvZEtyYWp1PgoJCQk8QWRyZXNMMT51bC4gUG9sbmEgMTwvQWRyZXNMMT4KCQkJPEFkcmVzTDI+MDAtMDAxIFdhcnN6YXdhPC9BZHJlc0wyPgoJCTwvQWRyZXM+CgkJPERhbmVLb250YWt0b3dlPgoJCQk8RW1haWw+amFuQGtvd2Fsc2tpLnBsPC9FbWFpbD4KCQkJPFRlbGVmb24+NTU1Nzc3OTk5PC9UZWxlZm9uPgoJCTwvRGFuZUtvbnRha3Rvd2U+CgkJPE5yS2xpZW50YT5mZGZkNzc4MzQzPC9OcktsaWVudGE+CgkJPEpTVD4yPC9KU1Q+CgkJPEdWPjI8L0dWPgoJPC9Qb2RtaW90Mj4KCTxGYT4KCQk8S29kV2FsdXR5PlBMTjwvS29kV2FsdXR5PgoJCTxQXzE+MjAyNi0wMi0xNTwvUF8xPgoJCTxQXzFNPldhcnN6YXdhPC9QXzFNPgoJCTxQXzI+RlYyMDI2LzAyLzE1MDwvUF8yPgoJCTxQXzY+MjAyNi0wMS0yNzwvUF82PgoJCTxQXzEzXzE+MTY2Ni42NjwvUF8xM18xPgoJCTxQXzE0XzE+MzgzLjMzPC9QXzE0XzE+CgkJPFBfMTNfMz4wLjk1PC9QXzEzXzM+CgkJPFBfMTRfMz4wLjA1PC9QXzE0XzM+CgkJPFBfMTU+MjA1MTwvUF8xNT4KCQk8QWRub3RhY2plPgoJCQk8UF8xNj4yPC9QXzE2PgoJCQk8UF8xNz4yPC9QXzE3PgoJCQk8UF8xOD4yPC9QXzE4PgoJCQk8UF8xOEE+MjwvUF8xOEE+CgkJCTxad29sbmllbmllPgoJCQkJPFBfMTlOPjE8L1BfMTlOPgoJCQk8L1p3b2xuaWVuaWU+CgkJCTxOb3dlU3JvZGtpVHJhbnNwb3J0dT4KCQkJCTxQXzIyTj4xPC9QXzIyTj4KCQkJPC9Ob3dlU3JvZGtpVHJhbnNwb3J0dT4KCQkJPFBfMjM+MjwvUF8yMz4KCQkJPFBNYXJ6eT4KCQkJCTxQX1BNYXJ6eU4+MTwvUF9QTWFyenlOPgoJCQk8L1BNYXJ6eT4KCQk8L0Fkbm90YWNqZT4KCQk8Um9kemFqRmFrdHVyeT5WQVQ8L1JvZHphakZha3R1cnk+CgkJPEZQPjE8L0ZQPgoJCTxEb2RhdGtvd3lPcGlzPgoJCQk8S2x1Y3o+cHJlZmVyb3dhbmUgZ29kemlueSBkb3dvenU8L0tsdWN6PgoJCQk8V2FydG9zYz5kbmkgcm9ib2N6ZSAxNzowMCAtIDIwOjAwPC9XYXJ0b3NjPgoJCTwvRG9kYXRrb3d5T3Bpcz4KCQk8RmFXaWVyc3o+CgkJCTxOcldpZXJzemFGYT4xPC9OcldpZXJzemFGYT4KCQkJPFVVX0lEPmFhYWExMTExMzMzMzk5OTA8L1VVX0lEPgoJCQk8UF83PmxvZMOzd2thIFppbW5vdGVjaCBtazE8L1BfNz4KCQkJPFBfOEE+c3p0LjwvUF84QT4KCQkJPFBfOEI+MTwvUF84Qj4KCQkJPFBfOUE+MTYyNi4wMTwvUF85QT4KCQkJPFBfMTE+MTYyNi4wMTwvUF8xMT4KCQkJPFBfMTI+MjM8L1BfMTI+CgkJPC9GYVdpZXJzej4KCQk8RmFXaWVyc3o+CgkJCTxOcldpZXJzemFGYT4yPC9OcldpZXJzemFGYT4KCQkJPFVVX0lEPmFhYWExMTExMzMzMzk5OTE8L1VVX0lEPgoJCQk8UF83PnduaWVzaWVuaWUgc3ByesSZdHU8L1BfNz4KCQkJPFBfOEE+c3p0LjwvUF84QT4KCQkJPFBfOEI+MTwvUF84Qj4KCQkJPFBfOUE+NDAuNjU8L1BfOUE+CgkJCTxQXzExPjQwLjY1PC9QXzExPgoJCQk8UF8xMj4yMzwvUF8xMj4KCQk8L0ZhV2llcnN6PgoJCTxGYVdpZXJzej4KCQkJPE5yV2llcnN6YUZhPjM8L05yV2llcnN6YUZhPgoJCQk8VVVfSUQ+YWFhYTExMTEzMzMzOTk5MjwvVVVfSUQ+CgkJCTxQXzc+cHJvbW9jamEgbG9kw7N3a2EgcGXFgm5hIG1sZWthPC9QXzc+CgkJCTxQXzhBPnN6dC48L1BfOEE+CgkJCTxQXzhCPjE8L1BfOEI+CgkJCTxQXzlBPjAuOTU8L1BfOUE+CgkJCTxQXzExPjAuOTU8L1BfMTE+CgkJCTxQXzEyPjU8L1BfMTI+CgkJPC9GYVdpZXJzej4KCQk8UGxhdG5vc2M+CgkJCTxaYXBsYWNvbm8+MTwvWmFwbGFjb25vPgoJCQk8RGF0YVphcGxhdHk+MjAyNi0wMS0yNzwvRGF0YVphcGxhdHk+CgkJCTxGb3JtYVBsYXRub3NjaT42PC9Gb3JtYVBsYXRub3NjaT4KCQk8L1BsYXRub3NjPgoJCTxXYXJ1bmtpVHJhbnNha2NqaT4KCQkJPFphbW93aWVuaWE+CgkJCQk8RGF0YVphbW93aWVuaWE+MjAyNi0wMS0yNjwvRGF0YVphbW93aWVuaWE+CgkJCQk8TnJaYW1vd2llbmlhPjQzNTQzNDM8L05yWmFtb3dpZW5pYT4KCQkJPC9aYW1vd2llbmlhPgoJCTwvV2FydW5raVRyYW5zYWtjamk+Cgk8L0ZhPgoJPFN0b3BrYT4KCQk8SW5mb3JtYWNqZT4KCQkJPFN0b3BrYUZha3R1cnk+S2FwaWHFgiB6YWvFgmFkb3d5IDUgMDAwIDAwMDwvU3RvcGthRmFrdHVyeT4KCQk8L0luZm9ybWFjamU+CgkJPFJlamVzdHJ5PgoJCQk8S1JTPjAwMDAwOTk5OTk8L0tSUz4KCQkJPFJFR09OPjk5OTk5OTk5OTwvUkVHT04+CgkJCTxCRE8+MDAwMDk5OTk5PC9CRE8+CgkJPC9SZWplc3RyeT4KCTwvU3RvcGthPgo8L0Zha3R1cmE+Cg==';

        function send(req, ok, id) {
            $.post('index.php', req
            ).done((data) => {
                $('#' + id).text('');
                ok(data);
            }).fail((xhr, status, error) => {
                const data = xhr.responseJSON;
                $('#' + id).text('Error: ' + data.description + ' (code: ' + data.code + ')');
            });
        }

        function download(req, id) {
            $.ajaxSetup({
                beforeSend: (xhr, settings) => {
                    if (settings.dataType === 'binary') {
                        settings.xhr = () => $.extend(new window.XMLHttpRequest(), {responseType:'arraybuffer'});
                        settings.processData = false;
                    }
                }
            });

            $.ajax({
                type: 'POST',
                url: 'index.php',
                data: req,
                dataType: 'binary',
                success: (data, status, xhr) => {
                    $('#' + id).text('');
                    const disposition = xhr.getResponseHeader('Content-Disposition');
                    let filename = '';
                    if (disposition && disposition.indexOf('attachment') !== -1) {
                        const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
                        const matches = filenameRegex.exec(disposition);
                        if (matches != null && matches[1]) {
                            filename = matches[1].replace(/['"]/g, '');
                        }
                    }

                    const type = xhr.getResponseHeader('Content-Type');
                    const blob = new Blob([data], {type: type});

                    const URL = window.URL || window.webkitURL;
                    const downloadUrl = URL.createObjectURL(blob);

                    if (filename) {
                        const a = document.createElement("a");
                        if (typeof a.download === 'undefined') {
                            window.location = downloadUrl;
                        } else {
                            a.href = downloadUrl;
                            a.download = filename;
                            document.body.appendChild(a);
                            a.click();
                        }
                    } else {
                        window.location = downloadUrl;
                    }

                    setTimeout(() => {
                        URL.revokeObjectURL(downloadUrl);
                    }, 100);
                },
                error: (xhr, status, err) => {
                    $('#' + id).text('Error: ' + xhr.statusText + ' (code: ' + xhr.status + ')');
                }
            });
        }

        function b64EncodeUnicode(str) {
            return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
                function toSolidBytes(match, p1) {
                    return String.fromCharCode('0x' + p1);
                }));
        }

        function b64DecodeUnicode(str) {
            return decodeURIComponent(atob(str).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
        }

        function makeid(length) {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            const len = chars.length;
            let id = '';
            for (let i = 0; i < length; i++ ) {
                id += chars.charAt(Math.floor(Math.random() * len));
            }
            return id;
        }

        $(document).ready(() => {
            $('#invoice').val(b64DecodeUnicode(sampleInvoice));

            $('#pkey-get').on('click', () => {
                send(
                    {fun: 'ksefPublicKey'},
                    (data) => {
                        $('#pkey').val(data.publicKey);
                    },
                    'pkey-err'
                );
            });

            $('#session-new-ivkey').on('click', () => {
                send(
                    {fun: 'generateInitVector'},
                    (data) => {
                        $('#session-iv').val(data.iv);
                    },
                    'session-err'
                );
                send(
                    {fun: 'generateKey'},
                    (data) => {
                        $('#session-key').val(data.key);
                    },
                    'session-err'
                );
            });

            $('#session-new').on('click', () => {
                send(
                    {
                        fun: 'encryptKey',
                        public_key: $('#pkey').val(),
                        key: $('#session-key').val()
                    },
                    (data) => {
                        $('#session-enc-key').val(data.encryptedKey);
                        send(
                            {
                                fun: 'ksefSessionOpen',
                                iv: $('#session-iv').val(),
                                enc_key: $('#session-enc-key').val()
                            },
                            (data) => {
                                $('#session-id').val(data.id);
                            },
                            'session-err'
                        );
                    },
                    'session-err'
                );
            });

            $('#session-check').on('click', () => {
                send(
                    {
                        fun: 'ksefSessionStatus',
                        session_id: $('#session-id').val()
                    },
                    (data) => {
                        $('#session-status').text(data.sessionInfo.status.description);
                    },
                    'session-err'
                );
            });

            $('#session-close').on('click', () => {
                send(
                    {
                        fun: 'ksefSessionClose',
                        session_id: $('#session-id').val()
                    },
                    (data) => {
                        $('#session-status').text('closed');
                    },
                    'session-err'
                );
            });

            $('#session-upo').on('click', () => {
                send(
                    {
                        fun: 'ksefSessionUpo',
                        session_id: $('#session-id').val()
                    },
                    (data) => {
                        $('#upo').text(b64DecodeUnicode(data.upo));
                    },
                    'session-err'
                );
            });

            $('#invoice-validate').on('click', () => {
                send(
                    {
                        fun: 'ksefInvoiceValidate',
                        invoice: b64EncodeUnicode($('#invoice').val())
                    },
                    (data) => {
                        $('#invoice-status').text('valid: ' + data.valid + ', version: ' + data.invoiceVersion);
                    },
                    'invoice-err'
                );
            });

            $('#invoice-send').on('click', () => {
                const invoice = $('#invoice').val();
                const size = new Blob([invoice]).size;
                send(
                    {
                        fun: 'getHash',
                        data: b64EncodeUnicode(invoice)
                    },
                    (data) => {
                        const hash = data.hash;
                        send(
                            {
                                fun: 'encryptData',
                                iv: $('#session-iv').val(),
                                key: $('#session-key').val(),
                                data: b64EncodeUnicode(invoice)
                            },
                            (data) => {
                                send(
                                    {
                                        fun: 'ksefInvoiceSend',
                                        session_id: $('#session-id').val(),
                                        size: size,
                                        hash: hash,
                                        data: data.encryptedData
                                    },
                                    (data) => {
                                        $('#invoice-id').val(data.id);
                                    },
                                    'invoice-err'
                                );
                            },
                            'invoice-err'
                        );
                    },
                    'invoice-err'
                );
            });

            $('#invoice-check').on('click', () => {
                send(
                    {
                        fun: 'ksefInvoiceStatus',
                        invoice_id: $('#invoice-id').val()
                    },
                    (data) => {
                        $('#invoice-status').text(data.invoiceInfo.status.description + ' ' + (data.invoiceInfo.status.details ?? ''));
                        $('#invoice-num').val(data.invoiceInfo.ksefNumber);
                        $('#invoice-date').val(data.invoiceInfo.acquisitionDate);
                        if (data.error) {
                            $('#invoice-err').text('Error: ' + data.error.description + ', (code: ' + data.error.code + ')');
                        }
                    },
                    'invoice-err'
                );
            });

            $('#get-invoice').on('click', () => {
                download(
                    {
                        fun: 'ksefInvoiceGet',
                        invoice_num: $('#get-invoice-num').val()
                    },
                    'get-invoice-err'
                );
            });

            $('#query-start').on('click', () => {
                send(
                    {
                        fun: 'ksefInvoiceQueryStart',
                        iv: $('#session-iv').val(),
                        enc_key: $('#session-enc-key').val(),
                        subject_type: $('#query-subject').val(),
                        from: $('#query-from').val(),
                        to: $('#query-to').val()
                    },
                    (data) => {
                        $('#query-id').val(data.queryId);
                    },
                    'query-err'
                );
            });

            $('#query-status').on('click', () => {
                send(
                    {
                        fun: 'ksefInvoiceQueryStatus',
                        query_id: $('#query-id').val()
                    },
                    (data) => {
                        $('#query-part').empty();
                        $.each(data.partNumbers, (idx, val) => {
                            $('#query-part').append($('<option>', {value: val, text: val}));
                        });
                    },
                    'query-err'
                );
            });

            $('#query-result').on('click', () => {
                download(
                    {
                        fun: 'ksefInvoiceQueryResult',
                        query_id: $('#query-id').val(),
                        part_num: $('#query-part').val()
                    },
                    'query-err'
                );
            });

            $('#invoice-visualize').on('click', () => {
                download(
                    {
                        fun: 'ksefInvoiceVisualize',
                        invoice_num: $('#invoice-num').val(),
                        invoice: b64EncodeUnicode($('#invoice').val()),
                        format: $('#invoice-format').val()
                    },
                    'invoice-visualize-err'
                );
            });

            $('#upload-invoice-id-new').on('click', () => {
                $('#upload-invoice-id').val(makeid(10));
            });

            $('#upload-invoice').on('click', async () => {
                const input = $('#upload-invoice-file')[0];
                if (!input.files.length) {
                    alert('Najpierw wskaż plik XML z fakturą');
                    return;
                }
                const data = await input.files[0].bytes();
                send(
                    {
                        fun: 'boxUploadInvoice',
                        upload_id: $('#upload-invoice-id').val(),
                        offline: $('#upload-invoice-offline').val(),
                        invoice: data.toBase64()
                    },
                    (data) => {
                        if (data.result) {
                            $('#upload-invoice-res').text('request sent');
                        } else {
                            $('#upload-invoice-err').text('request failed');
                        }
                    },
                    'upload-invoice-err'
                );
            });

            $('#upload-invoice-status').on('click', () => {
                send(
                    {
                        fun: 'boxUploadInvoiceStatus',
                        upload_id: $('#upload-invoice-id').val()
                    },
                    (data) => {
                        $('#upload-invoice-res').text(data.invoiceInfo.status.description + ' ' + (data.invoiceInfo.status.details ?? ''));
                        if (data.invoiceInfo.ksefNumber) {
                            $('#upload-invoice-num').val(data.invoiceInfo.ksefNumber);
                            $('#upload-invoice-date').val(data.invoiceInfo.acquisitionDate);
                        }
                    },
                    'upload-invoice-err'
                );
            });

            $('#upload-batch-id-new').on('click', () => {
                $('#upload-batch-id').val(makeid(10));
            });

            $('#upload-batch').on('click', async () => {
                const input = $('#upload-batch-file')[0];
                if (!input.files.length) {
                    alert('Najpierw wskaż plik ZIP z fakturami');
                    return;
                }
                const data = await input.files[0].bytes();
                send(
                    {
                        fun: 'boxUploadBatch',
                        upload_id: $('#upload-batch-id').val(),
                        offline: $('#upload-batch-offline').val(),
                        invoice_version: $('#upload-batch-ver').val(),
                        batch: data.toBase64()
                    },
                    (data) => {
                        if (data.result) {
                            $('#upload-batch-res').text('request sent');
                        } else {
                            $('#upload-batch-err').text('request failed');
                        }
                    },
                    'upload-batch-err'
                );
            });

            $('#upload-batch-status').on('click', () => {
                send(
                    {
                        fun: 'boxUploadBatchStatus',
                        upload_id: $('#upload-batch-id').val()
                    },
                    (data) => {
                        $('#upload-batch-info').text(JSON.stringify(data));
                    },
                    'upload-batch-err'
                );
            });

            $('#download-invoices-id-new').on('click', () => {
                $('#download-invoices-id').val(makeid(10));
            });

            $('#download-invoices').on('click', () => {
                send(
                    {
                        fun: 'boxDownloadInvoices',
                        download_id: $('#download-invoices-id').val(),
                        subject_type: $('#download-invoices-subject').val(),
                        from: $('#download-invoices-from').val(),
                        to: $('#download-invoices-to').val()
                    },
                    (data) => {
                        if (data.result) {
                            $('#download-invoices-res').text('request sent');
                        } else {
                            $('#download-invoices-err').text('request failed');
                        }
                    },
                    'download-invoices-err'
                );
            });

            $('#download-invoices-status').on('click', () => {
                download(
                    {
                        fun: 'boxDownloadInvoicesResult',
                        download_id: $('#download-invoices-id').val()
                    },
                    'download-invoices-err'
                );
            });
        });
    </script>
</html>
