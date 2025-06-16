<?php
    // enable debug information
    ini_set('display_errors', 1);
    error_reporting(E_ALL);

    // load ksef api
    require_once 'KsefApi/KsefApiClient.php';

    \KsefApi\KsefApiClient::registerAutoloader();

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
    $ksef_api = new \KsefApi\KsefApiClient(\KsefApi\KsefApiClient::TEST_URL, 'enter valid id here', 'enter valid key here');

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
        if ($res_pk instanceof \KsefApi\Model\KsefPublicKeyResponse) {
            echo obj2json($res_pk);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefSessionOpen') {
        // open session
        $res_so = $ksef_api->ksefSessionOpen(\KsefApi\Model\KsefInvoiceVersion::V2,
            isset($_POST['iv']) ? $_POST['iv'] : null,
            isset($_POST['enc_key']) ? $_POST['enc_key'] : null);
        if ($res_so instanceof \KsefApi\Model\KsefSessionOpenResponse) {
            echo obj2json($res_so);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefSessionStatus') {
        // session status
        $res_ss = $ksef_api->ksefSessionStatus($_POST['session_id']);
        if ($res_ss) {
            $obj = new stdClass();
            $obj->status = $res_ss;
            echo obj2json($obj);
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
        if ($res_iv instanceof \KsefApi\Model\KsefInvoiceValidateResponse) {
            echo obj2json($res_iv);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceSend') {
        // send invoice
        $res_is = $ksef_api->ksefInvoiceSend($_POST['session_id'], isset($_POST['size']) ? intval($_POST['size']) : 0,
            isset($_POST['hash']) ? base64_decode($_POST['hash']) : null, base64_decode($_POST['data']));
        if ($res_is instanceof \KsefApi\Model\KsefInvoiceSendResponse) {
            echo obj2json($res_is);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceStatus') {
        // invoice status
        $res_is = $ksef_api->ksefInvoiceStatus($_POST['invoice_id']);
        if ($res_is instanceof \KsefApi\Model\KsefInvoiceStatusResponse) {
            echo obj2json($res_is);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceGet') {
        // invoice get
        $res_ig = $ksef_api->ksefInvoiceGet($_POST['session_id'], $_POST['invoice_num']);
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
        $res_iqs = $ksef_api->ksefInvoiceQueryStart($_POST['session_id'], $_POST['subject_type'],
            DateTime::createFromFormat('Y-m-d', $_POST['from']), DateTime::createFromFormat('Y-m-d', $_POST['to']));
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
        $res_iqs = $ksef_api->ksefInvoiceQueryStatus($_POST['session_id'], $_POST['query_id']);
        if ($res_iqs) {
            echo obj2json($res_iqs);
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceQueryResult') {
        // query result
        $enc = ($_POST['session_type'] === 'encrypted');
        $res_iqr = $ksef_api->ksefInvoiceQueryResult($_POST['session_id'], $_POST['query_id'], $_POST['part_num']);
        if ($res_iqr) {
            header('Content-Type: ' . ($enc ? 'application/octet-stream' : 'application/zip'));
            header('Content-Length: ' . strlen($res_iqr));
            header('Content-Disposition: attachment; filename="faktury.zip' . ($enc ? '.encrypted' : '') . '"');
            echo $res_iqr;
        } else {
            echo err2json($ksef_api);
        }
        die();
    } else if ($fun === 'ksefInvoiceVisualize') {
        // visualization
        $res_iv = $ksef_api->ksefInvoiceVisualize($_POST['invoice_num'], base64_decode($_POST['invoice']),
            true, true, $_POST['format'], 'pl');
        if ($res_iv) {
            header('Content-Type: ' . $_POST['format'] === 'html' ? 'text/html; charset=UTF-8' : 'application/pdf');
            header('Content-Disposition: attachment; filename="faktura.' . $_POST['format'] . '"');
            echo $res_iv;
        } else {
            echo err2json($ksef_api);
        }
        die();
    }
?>
<!DOCTYPE html>
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
                        <label for="session-type" class="form-label">Typ sesji</label>
                        <select id="session-type" class="form-select">
                            <option value="plain">Bez szyfrowania</option>
                            <option value="encrypted">Z szyfrowaniem</option>
                        </select>
                        <div id="session-err" class="text-danger"></div>
                    </div>
                    <div class="col">
                        <label for="session-iv" class="form-label">Init vector (dla sesji z szyfrowaniem)</label>
                        <input id="session-iv" type="text" class="form-control">
                    </div>
                    <div class="col">
                        <label for="session-key" class="form-label">Klucz AES256 (dla sesji z szyfrowaniem)</label>
                        <input id="session-key" type="text" class="form-control">
                    </div>
                </div>
                <div class="row mb-3">
                    <div class="col">
                        <button id="session-new-ivkey" type="button" class="btn btn-sm btn-primary">Nowy init vector i klucz</button>
                        <button id="session-new" type="button" class="btn btn-sm btn-primary">Nowa sesja</button>
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
                        <label for="session-enc-key" class="form-label">Zaszyfrowany klucz AES256 (dla sesji z szyfrowaniem)</label>
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
                        <label for="invoice" class="form-label">Faktura (XML)</label>
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
                            <option value="subject1">subject1</option>
                            <option value="subject2">subject2</option>
                            <option value="subject3">subject3</option>
                            <option value="subjectAuthorized">subjectAuthorized</option>
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
            </form>
        </div>
    </body>

    <script>
        const sampleInvoice = 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4NCjxGYWt0dXJhIHhtbG5zOmV0ZD0iaHR0cDovL2NyZC5nb3YucGwveG1sL3NjaGVtYXR5L2R6aWVkemlub3dlL21mLzIwMjIvMDEvMDUvZUQvRGVmaW5pY2plVHlweS8iIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiDQp4bWxucz0iaHR0cDovL2NyZC5nb3YucGwvd3pvci8yMDIzLzA2LzI5LzEyNjQ4LyI+DQoJPE5hZ2xvd2VrPg0KCQk8S29kRm9ybXVsYXJ6YSBrb2RTeXN0ZW1vd3k9IkZBICgyKSIgd2Vyc2phU2NoZW15PSIxLTBFIj5GQTwvS29kRm9ybXVsYXJ6YT4NCgkJPFdhcmlhbnRGb3JtdWxhcnphPjI8L1dhcmlhbnRGb3JtdWxhcnphPg0KCQk8RGF0YVd5dHdvcnplbmlhRmE+MjAyMi0wMS0wMVQwMDowMDowMFo8L0RhdGFXeXR3b3J6ZW5pYUZhPg0KCQk8U3lzdGVtSW5mbz5TYW1wbG9GYWt0dXI8L1N5c3RlbUluZm8+DQoJPC9OYWdsb3dlaz4NCgk8UG9kbWlvdDE+DQoJCTxEYW5lSWRlbnR5ZmlrYWN5am5lPg0KCQkJPE5JUD45OTk5OTk5OTk5PC9OSVA+DQoJCQk8TmF6d2E+QUJDIEFHRCBzcC4geiBvLiBvLjwvTmF6d2E+DQoJCTwvRGFuZUlkZW50eWZpa2FjeWpuZT4NCgkJPEFkcmVzPg0KCQkJPEtvZEtyYWp1PlBMPC9Lb2RLcmFqdT4NCgkJCTxBZHJlc0wxPnVsLiBLd2lhdG93YSAxIG0uIDI8L0FkcmVzTDE+DQoJCQk8QWRyZXNMMj4wMC0wMDEgV2Fyc3phd2E8L0FkcmVzTDI+DQoJCTwvQWRyZXM+DQoJCTxEYW5lS29udGFrdG93ZT4NCgkJCTxFbWFpbD5hYmNAYWJjLnBsPC9FbWFpbD4NCgkJCTxUZWxlZm9uPjY2NzQ0NDU1NTwvVGVsZWZvbj4NCgkJPC9EYW5lS29udGFrdG93ZT4NCgk8L1BvZG1pb3QxPg0KCTxQb2RtaW90Mj4NCgkJPERhbmVJZGVudHlmaWthY3lqbmU+DQoJCQk8TklQPjExMTExMTExMTE8L05JUD4NCgkJCTxOYXp3YT5GLkguVS4gSmFuIEtvd2Fsc2tpPC9OYXp3YT4NCgkJPC9EYW5lSWRlbnR5ZmlrYWN5am5lPg0KCQk8QWRyZXM+DQoJCQk8S29kS3JhanU+UEw8L0tvZEtyYWp1Pg0KCQkJPEFkcmVzTDE+dWwuIFBvbG5hIDE8L0FkcmVzTDE+DQoJCQk8QWRyZXNMMj4wMC0wMDEgV2Fyc3phd2E8L0FkcmVzTDI+DQoJCTwvQWRyZXM+DQoJCTxEYW5lS29udGFrdG93ZT4NCgkJCTxFbWFpbD5qYW5Aa293YWxza2kucGw8L0VtYWlsPg0KCQkJPFRlbGVmb24+NTU1Nzc3OTk5PC9UZWxlZm9uPg0KCQk8L0RhbmVLb250YWt0b3dlPg0KCQk8TnJLbGllbnRhPmZkZmQ3NzgzNDM8L05yS2xpZW50YT4NCgk8L1BvZG1pb3QyPg0KCTxGYT4NCgkJPEtvZFdhbHV0eT5QTE48L0tvZFdhbHV0eT4NCgkJPFBfMT4yMDIyLTAyLTE1PC9QXzE+DQoJCTxQXzFNPldhcnN6YXdhPC9QXzFNPg0KCQk8UF8yPkZWMjAyMi8wMi8xNTA8L1BfMj4NCgkJPFBfNj4yMDIyLTAxLTI3PC9QXzY+DQoJCTxQXzEzXzE+MTY2Ni42NjwvUF8xM18xPg0KCQk8UF8xNF8xPjM4My4zMzwvUF8xNF8xPg0KCQk8UF8xM18zPjAuOTU8L1BfMTNfMz4NCgkJPFBfMTRfMz4wLjA1PC9QXzE0XzM+DQoJCTxQXzE1PjIwNTE8L1BfMTU+DQoJCTxBZG5vdGFjamU+DQoJCQk8UF8xNj4yPC9QXzE2Pg0KCQkJPFBfMTc+MjwvUF8xNz4NCgkJCTxQXzE4PjI8L1BfMTg+DQoJCQk8UF8xOEE+MjwvUF8xOEE+DQoJCQk8WndvbG5pZW5pZT4NCgkJCQk8UF8xOU4+MTwvUF8xOU4+DQoJCQk8L1p3b2xuaWVuaWU+DQoJCQk8Tm93ZVNyb2RraVRyYW5zcG9ydHU+DQoJCQkJPFBfMjJOPjE8L1BfMjJOPg0KCQkJPC9Ob3dlU3JvZGtpVHJhbnNwb3J0dT4NCgkJCTxQXzIzPjI8L1BfMjM+DQoJCQk8UE1hcnp5Pg0KCQkJCTxQX1BNYXJ6eU4+MTwvUF9QTWFyenlOPg0KCQkJPC9QTWFyenk+DQoJCTwvQWRub3RhY2plPg0KCQk8Um9kemFqRmFrdHVyeT5WQVQ8L1JvZHphakZha3R1cnk+DQoJCTxGUD4xPC9GUD4NCgkJPERvZGF0a293eU9waXM+DQoJCQk8S2x1Y3o+cHJlZmVyb3dhbmUgZ29kemlueSBkb3dvenU8L0tsdWN6Pg0KCQkJPFdhcnRvc2M+ZG5pIHJvYm9jemUgMTc6MDAgLSAyMDowMDwvV2FydG9zYz4NCgkJPC9Eb2RhdGtvd3lPcGlzPg0KCQk8RmFXaWVyc3o+DQoJCQk8TnJXaWVyc3phRmE+MTwvTnJXaWVyc3phRmE+DQoJCQk8VVVfSUQ+YWFhYTExMTEzMzMzOTk5MDwvVVVfSUQ+DQoJCQk8UF83PmxvZMOzd2thIFppbW5vdGVjaCBtazEgLSB6YcW8w7PFgsSHIGfEmcWbbMSFIGphxbrFhCBaQcW7w5PFgcSGIEfEmMWaTMSEIEpBxbnFgzwvUF83Pg0KCQkJPFBfOEE+c3p0LjwvUF84QT4NCgkJCTxQXzhCPjE8L1BfOEI+DQoJCQk8UF85QT4xNjI2LjAxPC9QXzlBPg0KCQkJPFBfMTE+MTYyNi4wMTwvUF8xMT4NCgkJCTxQXzEyPjIzPC9QXzEyPg0KCQk8L0ZhV2llcnN6Pg0KCQk8RmFXaWVyc3o+DQoJCQk8TnJXaWVyc3phRmE+MjwvTnJXaWVyc3phRmE+DQoJCQk8VVVfSUQ+YWFhYTExMTEzMzMzOTk5MTwvVVVfSUQ+DQoJCQk8UF83PnduaWVzaWVuaWUgc3ByesSZdHU8L1BfNz4NCgkJCTxQXzhBPnN6dC48L1BfOEE+DQoJCQk8UF84Qj4xPC9QXzhCPg0KCQkJPFBfOUE+NDAuNjU8L1BfOUE+DQoJCQk8UF8xMT40MC42NTwvUF8xMT4NCgkJCTxQXzEyPjIzPC9QXzEyPg0KCQk8L0ZhV2llcnN6Pg0KCQk8RmFXaWVyc3o+DQoJCQk8TnJXaWVyc3phRmE+MzwvTnJXaWVyc3phRmE+DQoJCQk8VVVfSUQ+YWFhYTExMTEzMzMzOTk5MjwvVVVfSUQ+DQoJCQk8UF83PnByb21vY2phIGxvZMOzd2thIHBlxYJuYSBtbGVrYTwvUF83Pg0KCQkJPFBfOEE+c3p0LjwvUF84QT4NCgkJCTxQXzhCPjE8L1BfOEI+DQoJCQk8UF85QT4wLjk1PC9QXzlBPg0KCQkJPFBfMTE+MC45NTwvUF8xMT4NCgkJCTxQXzEyPjU8L1BfMTI+DQoJCTwvRmFXaWVyc3o+DQoJCTxQbGF0bm9zYz4NCgkJCTxaYXBsYWNvbm8+MTwvWmFwbGFjb25vPg0KCQkJPERhdGFaYXBsYXR5PjIwMjItMDEtMjc8L0RhdGFaYXBsYXR5Pg0KCQkJPEZvcm1hUGxhdG5vc2NpPjY8L0Zvcm1hUGxhdG5vc2NpPg0KCQk8L1BsYXRub3NjPg0KCQk8V2FydW5raVRyYW5zYWtjamk+DQoJCQk8WmFtb3dpZW5pYT4NCgkJCQk8RGF0YVphbW93aWVuaWE+MjAyMi0wMS0yNjwvRGF0YVphbW93aWVuaWE+DQoJCQkJPE5yWmFtb3dpZW5pYT40MzU0MzQzPC9OclphbW93aWVuaWE+DQoJCQk8L1phbW93aWVuaWE+DQoJCTwvV2FydW5raVRyYW5zYWtjamk+DQoJPC9GYT4NCgk8U3RvcGthPg0KCQk8SW5mb3JtYWNqZT4NCgkJCTxTdG9wa2FGYWt0dXJ5PkthcGl0YcWCIHpha8WCYWRvd3kgNSAwMDAgMDAwPC9TdG9wa2FGYWt0dXJ5Pg0KCQk8L0luZm9ybWFjamU+DQoJCTxSZWplc3RyeT4NCgkJCTxLUlM+MDAwMDA5OTk5OTwvS1JTPg0KCQkJPFJFR09OPjk5OTk5OTk5OTwvUkVHT04+DQoJCQk8QkRPPjAwMDA5OTk5OTwvQkRPPg0KCQk8L1JlamVzdHJ5Pg0KCTwvU3RvcGthPg0KPC9GYWt0dXJhPg0K';

        function send(req, ok, id) {
            $.post('example.php', req
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
                url: 'example.php',
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
                const type = $('#session-type').val();
                if (type === 'plain') {
                    send(
                        {fun: 'ksefSessionOpen'},
                        (data) => {
                            $('#session-id').val(data.id);
                        },
                        'session-err'
                    );
                } else if (type === 'encrypted') {
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
                }
            });

            $('#session-check').on('click', () => {
                send(
                    {
                        fun: 'ksefSessionStatus',
                        session_id: $('#session-id').val()
                    },
                    (data) => {
                        $('#session-status').text(data.status);
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
                const type = $('#session-type').val();
                if (type === 'plain') {
                    send(
                        {
                            fun: 'ksefInvoiceSend',
                            session_id: $('#session-id').val(),
                            data: b64EncodeUnicode($('#invoice').val())
                        },
                        (data) => {
                            $('#invoice-id').val(data.id);
                        },
                        'invoice-err'
                    );
                } else if (type === 'encrypted') {
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

                }
            });

            $('#invoice-check').on('click', () => {
                send(
                    {
                        fun: 'ksefInvoiceStatus',
                        invoice_id: $('#invoice-id').val()
                    },
                    (data) => {
                        $('#invoice-status').text(data.status);
                        $('#invoice-num').val(data.ksefReferenceNumber);
                        $('#invoice-date').val(data.acquisitionTimestamp);
                        if (data.error) {
                            $('#invoice-err').text('Error: ' + data.error.description + ', (code: ' + data.error.code + ')');
                        }
                    },
                    'invoice-err'
                );
            });
        });

        $('#get-invoice').on('click', () => {
            download(
                {
                    fun: 'ksefInvoiceGet',
                    session_id: $('#session-id').val(),
                    invoice_num: $('#get-invoice-num').val()
                },
                'get-invoice-err'
            );
        });

        $('#query-start').on('click', () => {
            send(
                {
                    fun: 'ksefInvoiceQueryStart',
                    session_id: $('#session-id').val(),
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
                    session_id: $('#session-id').val(),
                    query_id: $('#query-id').val()
                },
                (data) => {
                    $('#query-part').empty();
                    $.each(data, (idx, val) => {
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
                    session_id: $('#session-id').val(),
                    session_type: $('#session-type').val(),
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
    </script>
</html>
