<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>KSEF API Client for PHP</title>
</head>
<body>
<?php
/**
 * Copyright 2025-2026 NETCAT (www.netcat.pl)
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
 * @copyright 2025-2026 NETCAT (www.netcat.pl)
 * @license http://www.apache.org/licenses/LICENSE-2.0
 */

use KsefApi\KsefApiClient;
use KsefApi\Model\Adnotacje;
use KsefApi\Model\BatchInfo;
use KsefApi\Model\BatchPartInfo;
use KsefApi\Model\BoxDownloadInvoicesRequest;
use KsefApi\Model\BoxUploadBatchRequest;
use KsefApi\Model\BoxUploadInvoiceRequest;
use KsefApi\Model\EncryptionInfo;
use KsefApi\Model\Fa;
use KsefApi\Model\Faktura;
use KsefApi\Model\FaWiersz;
use KsefApi\Model\InvoiceInfo;
use KsefApi\Model\KsefInvoiceEncrypted;
use KsefApi\Model\KsefInvoiceLinksRequest;
use KsefApi\Model\KsefInvoiceQueryStartRange;
use KsefApi\Model\KsefInvoiceQueryStartRequest;
use KsefApi\Model\KsefInvoiceSendRequest;
use KsefApi\Model\KsefInvoiceVersion;
use KsefApi\Model\KsefInvoiceVisualizeRequest;
use KsefApi\Model\KsefSessionOpenBatchRequest;
use KsefApi\Model\KsefSessionOpenOnlineRequest;
use KsefApi\Model\KsefUpoVisualizeRequest;
use KsefApi\Model\NoweSrodkiTransportu;
use KsefApi\Model\Platnosc;
use KsefApi\Model\PMarzy;
use KsefApi\Model\Podmiot1;
use KsefApi\Model\Podmiot2;
use KsefApi\Model\TAdres;
use KsefApi\Model\TKodFormularza;
use KsefApi\Model\TKodKraju;
use KsefApi\Model\TKodWaluty;
use KsefApi\Model\TNaglowek;
use KsefApi\Model\TPodmiot1;
use KsefApi\Model\TPodmiot2;
use KsefApi\Model\TRodzajFaktury;
use KsefApi\Model\TStawkaPodatku;
use KsefApi\Model\TFormaPlatnosci;
use KsefApi\Model\WariantFormularza;
use KsefApi\Model\Zwolnienie;

// load ksefapi lib (and all dependencies)
require_once __DIR__ . '/../vendor/autoload.php';

// enable debug information
ini_set('display_errors', 1);
error_reporting(E_ALL);

/**
 * Print a line of example output
 */
function out(string $message): void
{
    echo '<pre>' . $message . '</pre>' . PHP_EOL;
}

/**
 * Print object as JSON
 * @param mixed $object the object
 * @return string JSON string
 */
function printObject(mixed $object): string
{
    return json_encode($object, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
}

/**
 * Example program
 */
class Program {

    private DateTimeImmutable $now;
    private string $sellerNip;
    private string $sellerName;
    private int $invoiceNumber;

    private KsefApiClient $ksefApi;

    private string $iv;
    private string $sKey;
    private string $encKey;
    private ?string $ksefNumber;

    /**
     * Construct new object
     */
    public function __construct() {
        // set some basic data
        $this->now = new DateTimeImmutable();

        // seller NIP and name (this data must match yours data at KSeF portal)
        $this->sellerNip = "enter your company's NIP here";
        $this->sellerName = "enter your company's name here";

        // increment on each run to avoid duplicates
        $this->invoiceNumber = 1;

        // KSEF API client object
        $this->ksefApi = new KsefApiClient(KsefApiClient::TEST_URL, 'enter valid API id here', 'enter valid API key here');

        $this->generate_encryption_data();
        $this->ksefNumber = null;
    }

    /**
     * Throw a runtime exception based on the client's last error
     */
    private function fail(string $context): void
    {
        $error = $this->ksefApi->getLastError();
        $suffix = $error ? (string)$error : 'unknown error';
        throw new RuntimeException($context . ': ' . $suffix);
    }

    /**
     * Create a random temp file path
     */
    private function temp_file(string $prefix, string $extension): string
    {
        return rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR
            . $prefix . bin2hex(random_bytes(16)) . $extension;
    }

    /**
     * Format date as YYYY-MM-DD
     */
    private function to_date(): string
    {
        return $this->now->format('Y-m-d');
    }

    /**
     * Format date as UTC ISO-8601 with milliseconds
     */
    private function to_iso(): string
    {
        return $this->now->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.v\Z');
    }

    /**
     * Get next invoice number for tests
     */
    private function gen_next_invoice_number(): string
    {
        return sprintf('KSEFAPI/%05d/%02d/%02d/%04d', $this->invoiceNumber++, (int)$this->now->format('d'),
            (int)$this->now->format('m'), (int)$this->now->format('Y'));
    }

    /**
     * Create an invoice object
     */
    private function create_invoice(): Faktura
    {
        // create new invoice object (adapt the data to your needs)
        $kf = new TKodFormularza();
        $kf->setKodFormularza(TKodFormularza::KOD_FORMULARZA_FA);
        $kf->setKodSystemowy(TKodFormularza::KOD_SYSTEMOWY_FA_V3);
        $kf->setWersjaSchemy(TKodFormularza::WERSJA_SCHEMY__1_0_E);

        $n = new TNaglowek();
        $n->setKodFormularza($kf);
        $n->setWariantFormularza(WariantFormularza::NUMBER_3);
        $n->setDataWytworzeniaFa(DateTime::createFromInterface($this->now));
        $n->setSystemInfo('KSEF API');

        // seller data
        $p1 = new TPodmiot1();
        $p1->setNip($this->sellerNip);
        $p1->setNazwa($this->sellerName);

        $p1a = new TAdres();
        $p1a->setKodKraju(TKodKraju::PL);
        $p1a->setAdresL1('ul. Kwiatowa 1 m. 2');
        $p1a->setAdresL2('00-001 Warszawa');

        $podmiot1 = new Podmiot1();
        $podmiot1->setDaneIdentyfikacyjne($p1);
        $podmiot1->setAdres($p1a);

        // buyer data
        $p2 = new TPodmiot2();
        $p2->setNazwa('F.H.U. Jan Kowalski');
        $p2->setNip('1111111111');

        $p2a = new TAdres();
        $p2a->setKodKraju(TKodKraju::PL);
        $p2a->setAdresL1('ul. Polna 1');
        $p2a->setAdresL2('00-001 Warszawa');

        $podmiot2 = new Podmiot2();
        $podmiot2->setDaneIdentyfikacyjne($p2);
        $podmiot2->setAdres($p2a);
        $podmiot2->setJst(2);
        $podmiot2->setGv(2);

        $z = new Zwolnienie();
        $z->setP19N(1);

        $nst = new NoweSrodkiTransportu();
        $nst->setP22N(1);

        $m = new PMarzy();
        $m->setPPMarzyN(1);

        $ad = new Adnotacje();
        $ad->setP16(2);
        $ad->setP17(2);
        $ad->setP18(2);
        $ad->setP18A(2);
        $ad->setZwolnienie($z);
        $ad->setNoweSrodkiTransportu($nst);
        $ad->setP23(2);
        $ad->setPMarzy($m);

        $pl = new Platnosc();
        $pl->setZaplacono(1);
        $pl->setDataZaplaty(DateTime::createFromInterface($this->now));
        $pl->setFormaPlatnosci(TFormaPlatnosci::NUMBER_6);

        $w1 = new FaWiersz();
        $w1->setNrWierszaFa(1);
        $w1->setUuId('aaaa111133339990');
        $w1->setP7('lodówka Zimnotech mk1');
        $w1->setP8A('szt.');
        $w1->setP8B(1);
        $w1->setP9A(1626.01);
        $w1->setP11(1626.01);
        $w1->setP12(TStawkaPodatku::_23);

        $w2 = new FaWiersz();
        $w2->setNrWierszaFa(2);
        $w2->setUuId('aaaa111133339991');
        $w2->setP7('wniesienie sprzętu');
        $w2->setP8A('szt.');
        $w2->setP8B(1);
        $w2->setP9A(40.65);
        $w2->setP11(40.65);
        $w2->setP12(TStawkaPodatku::_23);

        $w3 = new FaWiersz();
        $w3->setNrWierszaFa(3);
        $w3->setUuId('aaaa111133339992');
        $w3->setP7('promocja lodówka pełna mleka');
        $w3->setP8A('szt.');
        $w3->setP8B(1);
        $w3->setP9A(0.95);
        $w3->setP11(0.95);
        $w3->setP12(TStawkaPodatku::_5);

        $fa = new Fa();
        $fa->setKodWaluty(TKodWaluty::PLN);
        $fa->setP1(DateTime::createFromInterface($this->now)); // date of issue
        $fa->setP1M('Warszawa');
        $fa->setP2($this->gen_next_invoice_number()); // invoice number
        $fa->setP6(DateTime::createFromInterface($this->now)); // date of sale
        $fa->setP131(1666.66); // total net amount
        $fa->setP141(383.33); // total VAT amount
        $fa->setP133(0.95);
        $fa->setP143(0.05);
        $fa->setP15(2051.00); // total gross amount
        $fa->setAdnotacje($ad);
        $fa->setRodzajFaktury(TRodzajFaktury::VAT);
        $fa->setFp(1);
        $fa->setPlatnosc($pl);
        $fa->setFaWiersz([$w1, $w2, $w3]);

        $invoice = new Faktura();
        $invoice->setNaglowek($n);
        $invoice->setPodmiot1($podmiot1);
        $invoice->setPodmiot2($podmiot2);
        $invoice->setFa($fa);

        return $invoice;
    }

    /**
     * Get sample invoice XML
     */
    private function get_invoice_xml(): string
    {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            . "<Faktura xmlns:etd=\"http://crd.gov.pl/xml/schematy/dziedzinowe/mf/2022/01/05/eD/DefinicjeTypy/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
            . "xmlns=\"http://crd.gov.pl/wzor/2025/06/25/13775/\">\n"
            . "\t<Naglowek>\n"
            . "\t\t<KodFormularza kodSystemowy=\"FA (3)\" wersjaSchemy=\"1-0E\">FA</KodFormularza>\n"
            . "\t\t<WariantFormularza>3</WariantFormularza>\n"
            . "\t\t<DataWytworzeniaFa>" . $this->to_iso() . "</DataWytworzeniaFa>\n"
            . "\t\t<SystemInfo>KSEF API</SystemInfo>\n"
            . "\t</Naglowek>\n"
            . "\t<Podmiot1>\n"
            . "\t\t<DaneIdentyfikacyjne>\n"
            . "\t\t\t<NIP>" . htmlspecialchars($this->sellerNip, ENT_XML1) . "</NIP>\n"
            . "\t\t\t<Nazwa>" . htmlspecialchars($this->sellerName, ENT_XML1) . "</Nazwa>\n"
            . "\t\t</DaneIdentyfikacyjne>\n"
            . "\t\t<Adres>\n"
            . "\t\t\t<KodKraju>PL</KodKraju>\n"
            . "\t\t\t<AdresL1>ul. Kwiatowa 1 m. 2</AdresL1>\n"
            . "\t\t\t<AdresL2>00-001 Warszawa</AdresL2>\n"
            . "\t\t</Adres>\n"
            . "\t\t<DaneKontaktowe>\n"
            . "\t\t\t<Email>abc@abc.pl</Email>\n"
            . "\t\t\t<Telefon>667444555</Telefon>\n"
            . "\t\t</DaneKontaktowe>\n"
            . "\t</Podmiot1>\n"
            . "\t<Podmiot2>\n"
            . "\t\t<DaneIdentyfikacyjne>\n"
            . "\t\t\t<NIP>1111111111</NIP>\n"
            . "\t\t\t<Nazwa>F.H.U. Jan Kowalski</Nazwa>\n"
            . "\t\t</DaneIdentyfikacyjne>\n"
            . "\t\t<Adres>\n"
            . "\t\t\t<KodKraju>PL</KodKraju>\n"
            . "\t\t\t<AdresL1>ul. Polna 1</AdresL1>\n"
            . "\t\t\t<AdresL2>00-001 Warszawa</AdresL2>\n"
            . "\t\t</Adres>\n"
            . "\t\t<DaneKontaktowe>\n"
            . "\t\t\t<Email>jan@kowalski.pl</Email>\n"
            . "\t\t\t<Telefon>555777999</Telefon>\n"
            . "\t\t</DaneKontaktowe>\n"
            . "\t\t<NrKlienta>fdfd778343</NrKlienta>\n"
            . "\t\t<JST>2</JST>\n"
            . "\t\t<GV>2</GV>\n"
            . "\t</Podmiot2>\n"
            . "\t<Fa>\n"
            . "\t\t<KodWaluty>PLN</KodWaluty>\n"
            . "\t\t<P_1>" . $this->to_date() . "</P_1>\n"
            . "\t\t<P_1M>Warszawa</P_1M>\n"
            . "\t\t<P_2>" . $this->gen_next_invoice_number() . "</P_2>\n"
            . "\t\t<P_6>" . $this->to_date() . "</P_6>\n"
            . "\t\t<P_13_1>1666.66</P_13_1>\n"
            . "\t\t<P_14_1>383.33</P_14_1>\n"
            . "\t\t<P_13_3>0.95</P_13_3>\n"
            . "\t\t<P_14_3>0.05</P_14_3>\n"
            . "\t\t<P_15>2051</P_15>\n"
            . "\t\t<Adnotacje>\n"
            . "\t\t\t<P_16>2</P_16>\n"
            . "\t\t\t<P_17>2</P_17>\n"
            . "\t\t\t<P_18>2</P_18>\n"
            . "\t\t\t<P_18A>2</P_18A>\n"
            . "\t\t\t<Zwolnienie>\n"
            . "\t\t\t\t<P_19N>1</P_19N>\n"
            . "\t\t\t</Zwolnienie>\n"
            . "\t\t\t<NoweSrodkiTransportu>\n"
            . "\t\t\t\t<P_22N>1</P_22N>\n"
            . "\t\t\t</NoweSrodkiTransportu>\n"
            . "\t\t\t<P_23>2</P_23>\n"
            . "\t\t\t<PMarzy>\n"
            . "\t\t\t\t<P_PMarzyN>1</P_PMarzyN>\n"
            . "\t\t\t</PMarzy>\n"
            . "\t\t</Adnotacje>\n"
            . "\t\t<RodzajFaktury>VAT</RodzajFaktury>\n"
            . "\t\t<FP>1</FP>\n"
            . "\t\t<DodatkowyOpis>\n"
            . "\t\t\t<Klucz>preferowane godziny dowozu</Klucz>\n"
            . "\t\t\t<Wartosc>dni robocze 17:00 - 20:00</Wartosc>\n"
            . "\t\t</DodatkowyOpis>\n"
            . "\t\t<FaWiersz>\n"
            . "\t\t\t<NrWierszaFa>1</NrWierszaFa>\n"
            . "\t\t\t<UU_ID>aaaa111133339990</UU_ID>\n"
            . "\t\t\t<P_7>lodówka Zimnotech mk1</P_7>\n"
            . "\t\t\t<P_8A>szt.</P_8A>\n"
            . "\t\t\t<P_8B>1</P_8B>\n"
            . "\t\t\t<P_9A>1626.01</P_9A>\n"
            . "\t\t\t<P_11>1626.01</P_11>\n"
            . "\t\t\t<P_12>23</P_12>\n"
            . "\t\t</FaWiersz>\n"
            . "\t\t<FaWiersz>\n"
            . "\t\t\t<NrWierszaFa>2</NrWierszaFa>\n"
            . "\t\t\t<UU_ID>aaaa111133339991</UU_ID>\n"
            . "\t\t\t<P_7>wniesienie sprzętu</P_7>\n"
            . "\t\t\t<P_8A>szt.</P_8A>\n"
            . "\t\t\t<P_8B>1</P_8B>\n"
            . "\t\t\t<P_9A>40.65</P_9A>\n"
            . "\t\t\t<P_11>40.65</P_11>\n"
            . "\t\t\t<P_12>23</P_12>\n"
            . "\t\t</FaWiersz>\n"
            . "\t\t<FaWiersz>\n"
            . "\t\t\t<NrWierszaFa>3</NrWierszaFa>\n"
            . "\t\t\t<UU_ID>aaaa111133339992</UU_ID>\n"
            . "\t\t\t<P_7>promocja lodówka pełna mleka</P_7>\n"
            . "\t\t\t<P_8A>szt.</P_8A>\n"
            . "\t\t\t<P_8B>1</P_8B>\n"
            . "\t\t\t<P_9A>0.95</P_9A>\n"
            . "\t\t\t<P_11>0.95</P_11>\n"
            . "\t\t\t<P_12>5</P_12>\n"
            . "\t\t</FaWiersz>\n"
            . "\t\t<Platnosc>\n"
            . "\t\t\t<Zaplacono>1</Zaplacono>\n"
            . "\t\t\t<DataZaplaty>" . $this->to_date() . "</DataZaplaty>\n"
            . "\t\t\t<FormaPlatnosci>6</FormaPlatnosci>\n"
            . "\t\t</Platnosc>\n"
            . "\t\t<WarunkiTransakcji>\n"
            . "\t\t\t<Zamowienia>\n"
            . "\t\t\t\t<DataZamowienia>" . $this->to_date() . "</DataZamowienia>\n"
            . "\t\t\t\t<NrZamowienia>4354343</NrZamowienia>\n"
            . "\t\t\t</Zamowienia>\n"
            . "\t\t</WarunkiTransakcji>\n"
            . "\t</Fa>\n"
            . "\t<Stopka>\n"
            . "\t\t<Informacje>\n"
            . "\t\t\t<StopkaFaktury>Kapitał zakładowy 5 000 000</StopkaFaktury>\n"
            . "\t\t</Informacje>\n"
            . "\t\t<Rejestry>\n"
            . "\t\t\t<KRS>0000099999</KRS>\n"
            . "\t\t\t<REGON>999999999</REGON>\n"
            . "\t\t\t<BDO>000099999</BDO>\n"
            . "\t\t</Rejestry>\n"
            . "\t</Stopka>\n"
            . "</Faktura>\n";
    }

    /**
     * Create new batch file
     */
    private function create_batch(): string
    {
        if (!class_exists('ZipArchive')) {
            throw new RuntimeException('ZipArchive extension is required to create batch examples');
        }

        $path = $this->temp_file('batch-', '.zip');
        $zip = new ZipArchive();

        if ($zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            throw new RuntimeException('Unable to create batch archive: ' . $path);
        }

        for ($i = 1; $i <= 100; $i++) {
            $zip->addFromString(sprintf('invoice-%03d.xml', $i), $this->get_invoice_xml());
        }

        $zip->close();

        return $path;
    }

    /**
     * Print out invoice info
     */
    private function print_invoice_info(InvoiceInfo $info): void
    {
        $status = $info->getStatus();

        out('Invoice status code: ' . $status->getCode());
        out('Invoice status description: ' . $status->getDescription());
        out('Invoice status details: ' . $status->getDetails());

        if ($status->getCode() === 200) {
            out('Invoice number: ' . $info->getInvoiceNumber());
            out('Invoice KSeF number: ' . $info->getKsefNumber());
            out('Invoice acquisition date: ' . $info->getAcquisitionDate()?->format(DateTimeInterface::ATOM));
        }
    }

    /**
     * Upload a single batch part to the storage endpoint returned by the API
     * @param string[] $headers
     */
    private function upload_part(string $method, string $url, array $headers, string $body): void
    {
        $curl = curl_init($url);
        if ($curl === false) {
            throw new RuntimeException('Unable to initialize cURL for part upload');
        }

        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HEADER, true);

        $response = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $error = curl_error($curl);
        curl_close($curl);

        if ($response === false || $status !== 201) {
            throw new RuntimeException('Part upload failed: HTTP ' . $status . ($error ? ' (' . $error . ')' : ''));
        }
    }

    /**
     * Generate init vector and key for symmetric encryption
     */
    private function generate_encryption_data(): void
    {
        out('generate_encryption_data');

        // get new init vector for symmetric encryption
        $this->iv = $this->ksefApi->generateInitVector();
        if ($this->iv === false) {
            $this->fail('generateInitVector failed');
        }
        out('Init vector: ' . base64_encode($this->iv));

        // gen new symmetric key for encryption
        $this->sKey = $this->ksefApi->generateKey();
        if ($this->sKey === false) {
            $this->fail('generateKey failed');
        }
        out('Symmetric key: ' . base64_encode($this->sKey));

        // encrypt symmetric key with KSeF public key
        $publicKey = $this->ksefApi->ksefPublicKey();
        if ($publicKey === false) {
            $this->fail('ksefPublicKey failed');
        }
        out('KSeF public key: ' . printObject($publicKey));

        $this->encKey = $this->ksefApi->encryptKey($publicKey, $this->sKey);
        if ($this->encKey === false) {
            $this->fail('encryptKey failed');
        }
        out('Encrypted symmetric key: ' . base64_encode($this->encKey));
    }

    /**
     * Saves UPO to file
     * @param string $xml UPO XML bytes
     * @return void
     */
    private function save_upo(string $xml): void
    {
        // save xml
        $path = $this->temp_file('upo-', '.xml');
        file_put_contents($path, $xml);

        out('UPO saved to:               ' . $path);

        // get visualization
        $req = new KsefUpoVisualizeRequest();
        $req->setUpoData(base64_encode($xml));
        $req->setOutputFormat(KsefUpoVisualizeRequest::OUTPUT_FORMAT_PDF);
        $req->setOutputLanguage(KsefUpoVisualizeRequest::OUTPUT_LANGUAGE_PL);

        $pdf = $this->ksefApi->ksefUpoVisualize($req);
        if ($pdf === false) {
            $this->fail('ksefUpoVisualize failed');
        }

        $path = $this->temp_file('upo-', '.pdf');
        file_put_contents($path, $pdf);

        out('UPO visualization saved to: ' . $path);
    }

    /**
     * Create invoice XML
     */
    public function create_invoice_xml(): void
    {
        out('create_invoice_xml');

        // create new invoice object
        $invoice = $this->create_invoice();

        // get invoice as xml
        $xml = $this->ksefApi->ksefInvoiceGenerate($invoice);

        if ($xml === false) {
            $this->fail('ksefInvoiceGenerate failed');
        }

        out('Invoice XML: ' . htmlspecialchars($xml));
    }

    /**
     * Validate invoice XML
     */
    public function validate_invoice_xml(): void
    {
        out('validate_invoice_xml');

        // validate xml
        $xml = $this->get_invoice_xml();
        $result = $this->ksefApi->ksefInvoiceValidate($xml);

        if ($result === false) {
            $this->fail('ksefInvoiceValidate failed');
        }

        out('Validation result: ' . printObject($result));
    }

    /**
     * Get sample invoice, encrypt it and send
     */
    public function create_and_send_invoice(): void
    {
        out('create_and_send_invoice');

        // create new invoice object
        $invoice = $this->create_invoice();

        // get invoice as xml
        $xml = $this->ksefApi->ksefInvoiceGenerate($invoice);
        if ($xml === false) {
            $this->fail('ksefInvoiceGenerate failed');
        }
        out('Invoice XML: ' . htmlspecialchars($xml));

        // open new online session
        $ei = new EncryptionInfo();
        $ei->setInitVector(base64_encode($this->iv));
        $ei->setEncryptedKey(base64_encode($this->encKey));

        $soo = new KsefSessionOpenOnlineRequest();
        $soo->setInvoiceVersion(KsefInvoiceVersion::V3);
        $soo->setEncryptionInfo($ei);

        out('KsefSessionOpenOnlineRequest: ' . printObject($soo));

        $soor = $this->ksefApi->ksefSessionOpenOnline($soo);
        if ($soor === false) {
            $this->fail('ksefSessionOpenOnline failed');
        }

        out('KSeF session id: ' . $soor->getId());

        // encrypt an invoice
        $hash = $this->ksefApi->getHash($xml);
        $encData = $this->ksefApi->encryptData($this->iv, $this->sKey, $xml);
        if ($encData === false) {
            $this->fail('encryptData failed');
        }

        // send an encrypted invoice
        $ie = new KsefInvoiceEncrypted();
        $ie->setInvoiceSize(strlen($xml));
        $ie->setInvoiceHash(base64_encode($hash));
        $ie->setEncryptedInvoice(base64_encode($encData));

        $is = new KsefInvoiceSendRequest();
        $is->setSessionId($soor->getId());
        $is->setEncrypted($ie);

        $isr = $this->ksefApi->ksefInvoiceSend($is);
        if ($isr === false) {
            $this->fail('ksefInvoiceSend failed');
        }

        out('KSeF invoice id: ' . $isr->getId());

        // check an invoice status and fetch KSeF number and acquisition date (we’re using a simple loop here,
        // but in real applications you should use a more sophisticated method)
        $str = $this->ksefApi->waitForResult(fn() => $this->ksefApi->ksefInvoiceStatus($isr->getId()));
        if ($str === false) {
            $this->fail('ksefInvoiceStatus failed');
        }

        $this->print_invoice_info($str->getInvoiceInfo());

        // save for other tests
        $this->ksefNumber = $str->getInvoiceInfo()->getKsefNumber();

        // close session
        if (!$this->ksefApi->ksefSessionClose($soor->getId())) {
            $this->fail('ksefSessionClose failed');
        }

        // wait for the UPO
        $ssr = $this->ksefApi->waitForResult(fn() => $this->ksefApi->ksefSessionStatus($soor->getId()));
        if ($ssr === false) {
            $this->fail('ksefSessionStatus failed');
        }

        // get UPO
        $upo = $this->ksefApi->ksefSessionUpo($soor->getId());
        if ($upo === false) {
            $this->fail('ksefSessionUpo failed');
        }

        out('UPO: ' . htmlspecialchars($upo));
        $this->save_upo($upo);
    }

    /**
     * Generate sample batch, encrypt it and send
     */
    public function create_and_send_batch(): void
    {
        out('create_and_send_batch');

        // create new batch
        $batch = $this->create_batch();
        out('Batch file: ' . $batch);

        // encrypt batch (large batch files must be divided into 50 MB parts, with each part encrypted separately)
        $data = file_get_contents($batch);
        if ($data === false) {
            throw new RuntimeException('Unable to read batch file: ' . $batch);
        }

        $dataHash = $this->ksefApi->getHash($data);
        $encData = $this->ksefApi->encryptData($this->iv, $this->sKey, $data);
        if ($encData === false) {
            $this->fail('encryptData failed');
        }

        $encDataHash = $this->ksefApi->getHash($encData);

        // open new batch session
        $ei = new EncryptionInfo();
        $ei->setInitVector(base64_encode($this->iv));
        $ei->setEncryptedKey(base64_encode($this->encKey));

        $bpi = new BatchPartInfo();
        $bpi->setOrdinal(1);
        $bpi->setPartSize(strlen($encData));
        $bpi->setPartHash(base64_encode($encDataHash));

        $bi = new BatchInfo();
        $bi->setBatchSize(strlen($data));
        $bi->setBatchHash(base64_encode($dataHash));
        $bi->setBatchParts([$bpi]);

        $sob = new KsefSessionOpenBatchRequest();
        $sob->setInvoiceVersion(KsefInvoiceVersion::V3);
        $sob->setEncryptionInfo($ei);
        $sob->setOffline(true);
        $sob->setBatchInfo($bi);

        $sobr = $this->ksefApi->ksefSessionOpenBatch($sob);
        if ($sobr === false) {
            $this->fail('ksefSessionOpenBatch failed');
        }

        out('KSeF session id: ' . $sobr->getId());

        // upload all batch parts (using received info)
        foreach ($sobr->getPartUploads() as $pui) {
            out('Uploading part: ' . $pui->getOrdinal());
            out('Upload method: ' . $pui->getMethod());
            out('Upload URL: ' . $pui->getUrl());

            $headers = [];
            foreach ($pui->getHeaders() as $header) {
                $headers[] = $header->getName() . ': ' . $header->getValue();
            }
            out('Upload headers: ' . implode(', ', $headers));

            $this->upload_part($pui->getMethod(), $pui->getUrl(), $headers, $encData);
        }

        out('Upload completed');

        // close session
        if (!$this->ksefApi->ksefSessionClose($sobr->getId())) {
            $this->fail('ksefSessionClose failed');
        }

        // wait for the batch to be processed (we're using a simple loop here, but in real applications
        // you should use a more sophisticated method)
        $ssr = $this->ksefApi->waitForResult(fn() => $this->ksefApi->ksefSessionStatus($sobr->getId()));
        if ($ssr === false) {
            $this->fail('ksefSessionStatus failed');
        }

        out('Total invoices count: ' . $ssr->getSessionInfo()->getInvoiceCount());
        out('Successful invoices count: ' . $ssr->getSessionInfo()->getSuccessfulInvoiceCount());
        out('Failed invoices count: ' . $ssr->getSessionInfo()->getFailedInvoiceCount());

        // get batch invoices statuses (and fetch KSeF numbers and acquisition dates)
        $sir = $this->ksefApi->ksefSessionInvoices($sobr->getId());
        if ($sir === false) {
            $this->fail('ksefSessionInvoices failed');
        }

        foreach ($sir->getInvoices() as $ii) {
            $this->print_invoice_info($ii);
        }

        // get UPO
        $upo = $this->ksefApi->ksefSessionUpo($sobr->getId());
        if ($upo === false) {
            $this->fail('ksefSessionUpo failed');
        }

        out('UPO: ' . htmlspecialchars($upo));
        $this->save_upo($upo);
    }

    /**
     * Get invoice by its KSeF number
     */
    public function get_invoice_by_ksef_number(): void
    {
        out('get_invoice_by_ksef_number');

        if (!$this->ksefNumber) {
            out('get_invoice_by_ksef_number: skipped, no KSeF number available from previous example');
            return;
        }

        // get by number (we're using number from previous test)
        $xml = $this->ksefApi->ksefInvoiceGet($this->ksefNumber);
        if ($xml === false) {
            $this->fail('ksefInvoiceGet failed');
        }

        $path = $this->temp_file('invoice-', '.xml');
        file_put_contents($path, $xml);

        out('Invoice XML: ' . htmlspecialchars($xml));
        out('Invoice saved to: ' . $path);
    }

    /**
     * Get all invoices from specified time range and type
     */
    public function get_invoices_by_time_range(): void
    {
        out('get_invoices_by_time_range');

        // start query (get all invoices from last 3 days)
        $ei = new EncryptionInfo();
        $ei->setInitVector(base64_encode($this->iv));
        $ei->setEncryptedKey(base64_encode($this->encKey));

        $qr = new KsefInvoiceQueryStartRange();
        $qr->setFrom(DateTime::createFromInterface($this->now->modify('-3 days')));
        $qr->setTo(DateTime::createFromInterface($this->now));

        $iqs = new KsefInvoiceQueryStartRequest();
        $iqs->setEncryptionInfo($ei);
        $iqs->setSubjectType(KsefInvoiceQueryStartRequest::SUBJECT_TYPE_SUBJECT1);
        $iqs->setRange($qr);

        $queryId = $this->ksefApi->ksefInvoiceQueryStart($iqs);
        if ($queryId === false) {
            $this->fail('ksefInvoiceQueryStart failed');
        }

        out('Query id: ' . $queryId);

        // wait for the result (we're using a simple loop here, but in real applications
        // you should use a more sophisticated method)
        $iqsr = $this->ksefApi->waitForResult(fn() => $this->ksefApi->ksefInvoiceQueryStatus($queryId));
        if ($iqsr === false) {
            $this->fail('ksefInvoiceQueryStatus failed');
        }

        out('Number of invoices: ' . $iqsr->getNumberOfInvoices());

        // get results
        foreach ($iqsr->getPartNumbers() as $partNumber) {
            $data = $this->ksefApi->ksefInvoiceQueryResult($queryId, $partNumber);
            if ($data === false) {
                $this->fail('ksefInvoiceQueryResult failed');
            }

            $path = $this->temp_file('invoices-', '.zip.enc');
            file_put_contents($path, $data);

            out('Encrypted part saved to: ' . $path);
        }
    }

    /**
     * Generate invoice URL links and QR codes
     * @return void
     */
    public function get_invoice_links(): void
    {
        out('get_invoice_links');

        $xml = $this->get_invoice_xml();
        $hash = $this->ksefApi->getHash($xml);

        // get URLs and QR codes for visualization
        $il = new KsefInvoiceLinksRequest();
        $il->setNip($this->sellerNip);
        $il->setIssueDate(DateTime::createFromInterface($this->now));
        $il->setInvoiceHash(base64_encode($hash));
        if ($this->ksefNumber !== null) {
            $il->setInvoiceKsefNumber($this->ksefNumber);
        }

        $ilr = $this->ksefApi->ksefInvoiceLinks($il);
        if ($ilr === false) {
            $this->fail('ksefInvoiceLinks failed');
        }

        out('Invoice link: ' . $ilr->getInvoice()->getLink());
        out('Invoice QR image: ' . $ilr->getInvoice()->getLink());

        if ($ilr->getCertificate() !== null) {
            out('Certificate link: ' . $ilr->getCertificate()->getLink());
            out('Certificate QR image: ' . $ilr->getCertificate()->getLink());
        }
    }

    /**
     * Generate an invoice visualization
     */
    public function visualize_invoice_xml(): void
    {
        out('visualize_invoice_xml');

        $xml = $this->get_invoice_xml();

        // visualize invoice xml as html (official layout from MF)
        $ivh = new KsefInvoiceVisualizeRequest();
        $ivh->setOffline(!$this->ksefNumber);
        if ($this->ksefNumber !== null) {
            $ivh->setInvoiceKsefNumber($this->ksefNumber);
        }
        $ivh->setInvoiceData(base64_encode($xml));
        $ivh->setOutputFormat(KsefInvoiceVisualizeRequest::OUTPUT_FORMAT_HTML);
        $ivh->setOutputLanguage(KsefInvoiceVisualizeRequest::OUTPUT_LANGUAGE_PL);

        $html = $this->ksefApi->ksefInvoiceVisualize($ivh);
        if ($html === false) {
            $this->fail('ksefInvoiceVisualize(html) failed');
        }

        $htmlPath = $this->temp_file('invoice-', '.html');
        file_put_contents($htmlPath, $html);

        out('HTML saved to: ' . $htmlPath);

        // visualize invoice xml as pdf (still needs improvements)
        $ivp = new KsefInvoiceVisualizeRequest();
        $ivp->setOffline(!$this->ksefNumber);
        if ($this->ksefNumber !== null) {
            $ivp->setInvoiceKsefNumber($this->ksefNumber);
        }
        $ivp->setInvoiceData(base64_encode($xml));
        $ivp->setOutputFormat(KsefInvoiceVisualizeRequest::OUTPUT_FORMAT_PDF);
        $ivp->setOutputLanguage(KsefInvoiceVisualizeRequest::OUTPUT_LANGUAGE_PL);

        $pdf = $this->ksefApi->ksefInvoiceVisualize($ivp);
        if ($pdf === false) {
            $this->fail('ksefInvoiceVisualize(pdf) failed');
        }

        $pdfPath = $this->temp_file('invoice-', '.pdf');
        file_put_contents($pdfPath, $pdf);

        out('PDF saved to: ' . $pdfPath);
    }

    /**
     * Upload a plain unencrypted invoice to KSeF
     */
    public function upload_invoice(): void
    {
        out('upload_invoice');

        // sample invoice
        $xml = $this->get_invoice_xml();

        // this ID should be unique and can be used to link the invoice to any event in the user's system
        // (e.g., an order number)
        $uploadId = bin2hex(random_bytes(16));

        $req = new BoxUploadInvoiceRequest();
        $req->setUploadId($uploadId);
        $req->setOffline(false);
        $req->setNotify(false);
        $req->setUpo(true);
        $req->setInvoiceData(base64_encode($xml));

        $ok = $this->ksefApi->boxUploadInvoice($req);
        if (!$ok) {
            $this->fail('boxUploadInvoice failed');
        }

        // wait for the result (we're using a simple loop here, but in real applications
        // you should use a more sophisticated method)
        $res = $this->ksefApi->waitForResult(fn() => $this->ksefApi->boxUploadInvoiceStatus($uploadId));
        if ($res === false) {
            $this->fail('boxUploadInvoiceStatus failed');
        }

        $this->print_invoice_info($res->getInvoiceInfo());
        out('Session id: ' . $res->getSessionId());

        if ($res->getUpo() !== null) {
            $upo = base64_decode($res->getUpo());
            out('UPO: ' . htmlspecialchars($upo));
            $this->save_upo($upo);
        }
    }

    /**
     * Upload a ZIP file (batch) with plain unencrypted invoices to KSeF
     */
    public function upload_batch(): void
    {
        out('upload_batch');

        // sample batch
        $batch = $this->create_batch();
        out('Batch file: ' . $batch);

        $data = file_get_contents($batch);
        if ($data === false) {
            throw new RuntimeException('Unable to read batch file: ' . $batch);
        }

        // this ID should be unique and can be used to link the invoice to any event in the user's system
        // (e.g., an order number)
        $uploadId = bin2hex(random_bytes(16));

        $req = new BoxUploadBatchRequest();
        $req->setUploadId($uploadId);
        $req->setOffline(false);
        $req->setNotify(false);
        $req->setUpo(true);
        $req->setInvoiceVersion(KsefInvoiceVersion::V3);

        $ok = $this->ksefApi->boxUploadBatch($req, $data);
        if (!$ok) {
            $this->fail('boxUploadBatch failed');
        }

        // wait for the result (we're using a simple loop here, but in real applications
        // you should use a more sophisticated method)
        $res = $this->ksefApi->waitForResult(fn() => $this->ksefApi->boxUploadBatchStatus($uploadId));
        if ($res === false) {
            $this->fail('boxUploadBatchStatus failed');
        }

        foreach ($res->getInvoiceInfo() as $ii) {
            $this->print_invoice_info($ii);
        }

        out('Session id: ' . $res->getSessionId());

        if ($res->getUpo() !== null) {
            $upo = base64_decode($res->getUpo());
            out('UPO: ' . htmlspecialchars($upo));
            $this->save_upo($upo);
        }
    }

    /**
     * Download all invoices for specified type and time range from KSeF
     */
    public function download_invoices(): void
    {
        out('download_invoices');

        // this ID should be unique and can be used to link the invoice to any event in the user's system
        $downloadId = bin2hex(random_bytes(16));

        $range = new KsefInvoiceQueryStartRange();
        $range->setFrom(DateTime::createFromInterface($this->now->modify('-3 days')));
        $range->setTo(DateTime::createFromInterface($this->now));

        $req = new BoxDownloadInvoicesRequest();
        $req->setDownloadId($downloadId);
        $req->setNotify(false);
        $req->setSubjectType(BoxDownloadInvoicesRequest::SUBJECT_TYPE_SUBJECT1);
        $req->setRange($range);

        $ok = $this->ksefApi->boxDownloadInvoices($req);
        if (!$ok) {
            $this->fail('boxDownloadInvoices failed');
        }

        // wait for the result (we're using a simple loop here, but in real applications
        // you should use a more sophisticated method)
        $res = $this->ksefApi->waitForResult(fn() => $this->ksefApi->boxDownloadInvoicesResult($downloadId));
        if ($res === false) {
            $this->fail('boxDownloadInvoicesResult failed');
        }

        // res buffer contains the bytes of a plain, unencrypted ZIP archive that includes the invoices
        // and a metadata file
        $path = $this->temp_file('invoices-', '.zip');
        file_put_contents($path, $res);

        out('Invoices saved to: ' . $path);
    }
}

try {
    $prog = new Program();

    // test some typical use cases

    // basic functions
    $prog->create_invoice_xml();
    $prog->validate_invoice_xml();

    $prog->create_and_send_invoice();
    $prog->create_and_send_batch();

    $prog->get_invoice_links();
    $prog->visualize_invoice_xml();

    $prog->get_invoice_by_ksef_number();
    $prog->get_invoices_by_time_range();

    // black-box functions
    $prog->upload_invoice();
    $prog->upload_batch();

    $prog->download_invoices();
} catch (Throwable $e) {
    out('ERR: ' . $e);
}

?>
</body>
</html>
