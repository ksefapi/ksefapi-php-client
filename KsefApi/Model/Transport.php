<?php
/**
 * Transport
 *
 * PHP version 5
 *
 * @category Class
 * @package  KsefApi
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */

/**
 * KSeF API
 *
 * API do systemu KSeF
 *
 * OpenAPI spec version: 1.2.3
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 * Swagger Codegen version: 3.0.52
 */
/**
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen
 * Do not edit the class manually.
 */

namespace KsefApi\Model;

use \ArrayAccess;
use \KsefApi\ObjectSerializer;

/**
 * Transport Class Doc Comment
 *
 * @category Class
 * @package  KsefApi
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */
class Transport implements ModelInterface, ArrayAccess
{
    const DISCRIMINATOR = null;

    /**
      * The original name of the model.
      *
      * @var string
      */
    protected static $swaggerModelName = 'Transport';

    /**
      * Array of property to type mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerTypes = [
        'rodzaj_transportu' => '\KsefApi\Model\TRodzajTransportu',
        'transport_inny' => '\KsefApi\Model\TWybor1',
        'opis_innego_transportu' => '\KsefApi\Model\TZnakowy50',
        'przewoznik' => '\KsefApi\Model\Przewoznik',
        'nr_zlecenia_transportu' => '\KsefApi\Model\TZnakowy',
        'opis_ladunku' => '\KsefApi\Model\TLadunek',
        'ladunek_inny' => '\KsefApi\Model\TWybor1',
        'opis_innego_ladunku' => '\KsefApi\Model\TZnakowy50',
        'jednostka_opakowania' => '\KsefApi\Model\TZnakowy',
        'data_godz_rozp_transportu' => '\KsefApi\Model\TDataCzas',
        'data_godz_zak_transportu' => '\KsefApi\Model\TDataCzas',
        'wysylka_z' => '\KsefApi\Model\TAdres',
        'wysylka_przez' => '\KsefApi\Model\TAdres[]',
        'wysylka_do' => '\KsefApi\Model\TAdres'
    ];

    /**
      * Array of property to format mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerFormats = [
        'rodzaj_transportu' => null,
        'transport_inny' => null,
        'opis_innego_transportu' => null,
        'przewoznik' => null,
        'nr_zlecenia_transportu' => null,
        'opis_ladunku' => null,
        'ladunek_inny' => null,
        'opis_innego_ladunku' => null,
        'jednostka_opakowania' => null,
        'data_godz_rozp_transportu' => null,
        'data_godz_zak_transportu' => null,
        'wysylka_z' => null,
        'wysylka_przez' => null,
        'wysylka_do' => null
    ];

    /**
     * Array of property to type mappings. Used for (de)serialization
     *
     * @return array
     */
    public static function swaggerTypes()
    {
        return self::$swaggerTypes;
    }

    /**
     * Array of property to format mappings. Used for (de)serialization
     *
     * @return array
     */
    public static function swaggerFormats()
    {
        return self::$swaggerFormats;
    }

    /**
     * Array of attributes where the key is the local name,
     * and the value is the original name
     *
     * @var string[]
     */
    protected static $attributeMap = [
        'rodzaj_transportu' => 'RodzajTransportu',
        'transport_inny' => 'TransportInny',
        'opis_innego_transportu' => 'OpisInnegoTransportu',
        'przewoznik' => 'Przewoznik',
        'nr_zlecenia_transportu' => 'NrZleceniaTransportu',
        'opis_ladunku' => 'OpisLadunku',
        'ladunek_inny' => 'LadunekInny',
        'opis_innego_ladunku' => 'OpisInnegoLadunku',
        'jednostka_opakowania' => 'JednostkaOpakowania',
        'data_godz_rozp_transportu' => 'DataGodzRozpTransportu',
        'data_godz_zak_transportu' => 'DataGodzZakTransportu',
        'wysylka_z' => 'WysylkaZ',
        'wysylka_przez' => 'WysylkaPrzez',
        'wysylka_do' => 'WysylkaDo'
    ];

    /**
     * Array of attributes to setter functions (for deserialization of responses)
     *
     * @var string[]
     */
    protected static $setters = [
        'rodzaj_transportu' => 'setRodzajTransportu',
        'transport_inny' => 'setTransportInny',
        'opis_innego_transportu' => 'setOpisInnegoTransportu',
        'przewoznik' => 'setPrzewoznik',
        'nr_zlecenia_transportu' => 'setNrZleceniaTransportu',
        'opis_ladunku' => 'setOpisLadunku',
        'ladunek_inny' => 'setLadunekInny',
        'opis_innego_ladunku' => 'setOpisInnegoLadunku',
        'jednostka_opakowania' => 'setJednostkaOpakowania',
        'data_godz_rozp_transportu' => 'setDataGodzRozpTransportu',
        'data_godz_zak_transportu' => 'setDataGodzZakTransportu',
        'wysylka_z' => 'setWysylkaZ',
        'wysylka_przez' => 'setWysylkaPrzez',
        'wysylka_do' => 'setWysylkaDo'
    ];

    /**
     * Array of attributes to getter functions (for serialization of requests)
     *
     * @var string[]
     */
    protected static $getters = [
        'rodzaj_transportu' => 'getRodzajTransportu',
        'transport_inny' => 'getTransportInny',
        'opis_innego_transportu' => 'getOpisInnegoTransportu',
        'przewoznik' => 'getPrzewoznik',
        'nr_zlecenia_transportu' => 'getNrZleceniaTransportu',
        'opis_ladunku' => 'getOpisLadunku',
        'ladunek_inny' => 'getLadunekInny',
        'opis_innego_ladunku' => 'getOpisInnegoLadunku',
        'jednostka_opakowania' => 'getJednostkaOpakowania',
        'data_godz_rozp_transportu' => 'getDataGodzRozpTransportu',
        'data_godz_zak_transportu' => 'getDataGodzZakTransportu',
        'wysylka_z' => 'getWysylkaZ',
        'wysylka_przez' => 'getWysylkaPrzez',
        'wysylka_do' => 'getWysylkaDo'
    ];

    /**
     * Array of attributes where the key is the local name,
     * and the value is the original name
     *
     * @return array
     */
    public static function attributeMap()
    {
        return self::$attributeMap;
    }

    /**
     * Array of attributes to setter functions (for deserialization of responses)
     *
     * @return array
     */
    public static function setters()
    {
        return self::$setters;
    }

    /**
     * Array of attributes to getter functions (for serialization of requests)
     *
     * @return array
     */
    public static function getters()
    {
        return self::$getters;
    }

    /**
     * The original name of the model.
     *
     * @return string
     */
    public function getModelName()
    {
        return self::$swaggerModelName;
    }



    /**
     * Associative array for storing property values
     *
     * @var mixed[]
     */
    protected $container = [];

    /**
     * Constructor
     *
     * @param mixed[] $data Associated array of property values
     *                      initializing the model
     */
    public function __construct(array $data = null)
    {
        $this->container['rodzaj_transportu'] = isset($data['rodzaj_transportu']) ? $data['rodzaj_transportu'] : null;
        $this->container['transport_inny'] = isset($data['transport_inny']) ? $data['transport_inny'] : null;
        $this->container['opis_innego_transportu'] = isset($data['opis_innego_transportu']) ? $data['opis_innego_transportu'] : null;
        $this->container['przewoznik'] = isset($data['przewoznik']) ? $data['przewoznik'] : null;
        $this->container['nr_zlecenia_transportu'] = isset($data['nr_zlecenia_transportu']) ? $data['nr_zlecenia_transportu'] : null;
        $this->container['opis_ladunku'] = isset($data['opis_ladunku']) ? $data['opis_ladunku'] : null;
        $this->container['ladunek_inny'] = isset($data['ladunek_inny']) ? $data['ladunek_inny'] : null;
        $this->container['opis_innego_ladunku'] = isset($data['opis_innego_ladunku']) ? $data['opis_innego_ladunku'] : null;
        $this->container['jednostka_opakowania'] = isset($data['jednostka_opakowania']) ? $data['jednostka_opakowania'] : null;
        $this->container['data_godz_rozp_transportu'] = isset($data['data_godz_rozp_transportu']) ? $data['data_godz_rozp_transportu'] : null;
        $this->container['data_godz_zak_transportu'] = isset($data['data_godz_zak_transportu']) ? $data['data_godz_zak_transportu'] : null;
        $this->container['wysylka_z'] = isset($data['wysylka_z']) ? $data['wysylka_z'] : null;
        $this->container['wysylka_przez'] = isset($data['wysylka_przez']) ? $data['wysylka_przez'] : null;
        $this->container['wysylka_do'] = isset($data['wysylka_do']) ? $data['wysylka_do'] : null;
    }

    /**
     * Show all the invalid properties with reasons.
     *
     * @return array invalid properties with reasons
     */
    public function listInvalidProperties()
    {
        $invalidProperties = [];

        return $invalidProperties;
    }

    /**
     * Validate all the properties in the model
     * return true if all passed
     *
     * @return bool True if all properties are valid
     */
    public function valid()
    {
        return count($this->listInvalidProperties()) === 0;
    }


    /**
     * Gets rodzaj_transportu
     *
     * @return \KsefApi\Model\TRodzajTransportu
     */
    public function getRodzajTransportu()
    {
        return $this->container['rodzaj_transportu'];
    }

    /**
     * Sets rodzaj_transportu
     *
     * @param \KsefApi\Model\TRodzajTransportu $rodzaj_transportu rodzaj_transportu
     *
     * @return $this
     */
    public function setRodzajTransportu($rodzaj_transportu)
    {
        $this->container['rodzaj_transportu'] = $rodzaj_transportu;

        return $this;
    }

    /**
     * Gets transport_inny
     *
     * @return \KsefApi\Model\TWybor1
     */
    public function getTransportInny()
    {
        return $this->container['transport_inny'];
    }

    /**
     * Sets transport_inny
     *
     * @param \KsefApi\Model\TWybor1 $transport_inny transport_inny
     *
     * @return $this
     */
    public function setTransportInny($transport_inny)
    {
        $this->container['transport_inny'] = $transport_inny;

        return $this;
    }

    /**
     * Gets opis_innego_transportu
     *
     * @return \KsefApi\Model\TZnakowy50
     */
    public function getOpisInnegoTransportu()
    {
        return $this->container['opis_innego_transportu'];
    }

    /**
     * Sets opis_innego_transportu
     *
     * @param \KsefApi\Model\TZnakowy50 $opis_innego_transportu opis_innego_transportu
     *
     * @return $this
     */
    public function setOpisInnegoTransportu($opis_innego_transportu)
    {
        $this->container['opis_innego_transportu'] = $opis_innego_transportu;

        return $this;
    }

    /**
     * Gets przewoznik
     *
     * @return \KsefApi\Model\Przewoznik
     */
    public function getPrzewoznik()
    {
        return $this->container['przewoznik'];
    }

    /**
     * Sets przewoznik
     *
     * @param \KsefApi\Model\Przewoznik $przewoznik przewoznik
     *
     * @return $this
     */
    public function setPrzewoznik($przewoznik)
    {
        $this->container['przewoznik'] = $przewoznik;

        return $this;
    }

    /**
     * Gets nr_zlecenia_transportu
     *
     * @return \KsefApi\Model\TZnakowy
     */
    public function getNrZleceniaTransportu()
    {
        return $this->container['nr_zlecenia_transportu'];
    }

    /**
     * Sets nr_zlecenia_transportu
     *
     * @param \KsefApi\Model\TZnakowy $nr_zlecenia_transportu nr_zlecenia_transportu
     *
     * @return $this
     */
    public function setNrZleceniaTransportu($nr_zlecenia_transportu)
    {
        $this->container['nr_zlecenia_transportu'] = $nr_zlecenia_transportu;

        return $this;
    }

    /**
     * Gets opis_ladunku
     *
     * @return \KsefApi\Model\TLadunek
     */
    public function getOpisLadunku()
    {
        return $this->container['opis_ladunku'];
    }

    /**
     * Sets opis_ladunku
     *
     * @param \KsefApi\Model\TLadunek $opis_ladunku opis_ladunku
     *
     * @return $this
     */
    public function setOpisLadunku($opis_ladunku)
    {
        $this->container['opis_ladunku'] = $opis_ladunku;

        return $this;
    }

    /**
     * Gets ladunek_inny
     *
     * @return \KsefApi\Model\TWybor1
     */
    public function getLadunekInny()
    {
        return $this->container['ladunek_inny'];
    }

    /**
     * Sets ladunek_inny
     *
     * @param \KsefApi\Model\TWybor1 $ladunek_inny ladunek_inny
     *
     * @return $this
     */
    public function setLadunekInny($ladunek_inny)
    {
        $this->container['ladunek_inny'] = $ladunek_inny;

        return $this;
    }

    /**
     * Gets opis_innego_ladunku
     *
     * @return \KsefApi\Model\TZnakowy50
     */
    public function getOpisInnegoLadunku()
    {
        return $this->container['opis_innego_ladunku'];
    }

    /**
     * Sets opis_innego_ladunku
     *
     * @param \KsefApi\Model\TZnakowy50 $opis_innego_ladunku opis_innego_ladunku
     *
     * @return $this
     */
    public function setOpisInnegoLadunku($opis_innego_ladunku)
    {
        $this->container['opis_innego_ladunku'] = $opis_innego_ladunku;

        return $this;
    }

    /**
     * Gets jednostka_opakowania
     *
     * @return \KsefApi\Model\TZnakowy
     */
    public function getJednostkaOpakowania()
    {
        return $this->container['jednostka_opakowania'];
    }

    /**
     * Sets jednostka_opakowania
     *
     * @param \KsefApi\Model\TZnakowy $jednostka_opakowania jednostka_opakowania
     *
     * @return $this
     */
    public function setJednostkaOpakowania($jednostka_opakowania)
    {
        $this->container['jednostka_opakowania'] = $jednostka_opakowania;

        return $this;
    }

    /**
     * Gets data_godz_rozp_transportu
     *
     * @return \KsefApi\Model\TDataCzas
     */
    public function getDataGodzRozpTransportu()
    {
        return $this->container['data_godz_rozp_transportu'];
    }

    /**
     * Sets data_godz_rozp_transportu
     *
     * @param \KsefApi\Model\TDataCzas $data_godz_rozp_transportu data_godz_rozp_transportu
     *
     * @return $this
     */
    public function setDataGodzRozpTransportu($data_godz_rozp_transportu)
    {
        $this->container['data_godz_rozp_transportu'] = $data_godz_rozp_transportu;

        return $this;
    }

    /**
     * Gets data_godz_zak_transportu
     *
     * @return \KsefApi\Model\TDataCzas
     */
    public function getDataGodzZakTransportu()
    {
        return $this->container['data_godz_zak_transportu'];
    }

    /**
     * Sets data_godz_zak_transportu
     *
     * @param \KsefApi\Model\TDataCzas $data_godz_zak_transportu data_godz_zak_transportu
     *
     * @return $this
     */
    public function setDataGodzZakTransportu($data_godz_zak_transportu)
    {
        $this->container['data_godz_zak_transportu'] = $data_godz_zak_transportu;

        return $this;
    }

    /**
     * Gets wysylka_z
     *
     * @return \KsefApi\Model\TAdres
     */
    public function getWysylkaZ()
    {
        return $this->container['wysylka_z'];
    }

    /**
     * Sets wysylka_z
     *
     * @param \KsefApi\Model\TAdres $wysylka_z wysylka_z
     *
     * @return $this
     */
    public function setWysylkaZ($wysylka_z)
    {
        $this->container['wysylka_z'] = $wysylka_z;

        return $this;
    }

    /**
     * Gets wysylka_przez
     *
     * @return \KsefApi\Model\TAdres[]
     */
    public function getWysylkaPrzez()
    {
        return $this->container['wysylka_przez'];
    }

    /**
     * Sets wysylka_przez
     *
     * @param \KsefApi\Model\TAdres[] $wysylka_przez wysylka_przez
     *
     * @return $this
     */
    public function setWysylkaPrzez($wysylka_przez)
    {
        $this->container['wysylka_przez'] = $wysylka_przez;

        return $this;
    }

    /**
     * Gets wysylka_do
     *
     * @return \KsefApi\Model\TAdres
     */
    public function getWysylkaDo()
    {
        return $this->container['wysylka_do'];
    }

    /**
     * Sets wysylka_do
     *
     * @param \KsefApi\Model\TAdres $wysylka_do wysylka_do
     *
     * @return $this
     */
    public function setWysylkaDo($wysylka_do)
    {
        $this->container['wysylka_do'] = $wysylka_do;

        return $this;
    }
    /**
     * Returns true if offset exists. False otherwise.
     *
     * @param integer $offset Offset
     *
     * @return boolean
     */
    #[\ReturnTypeWillChange]
    public function offsetExists($offset)
    {
        return isset($this->container[$offset]);
    }

    /**
     * Gets offset.
     *
     * @param integer $offset Offset
     *
     * @return mixed
     */
    #[\ReturnTypeWillChange]
    public function offsetGet($offset)
    {
        return isset($this->container[$offset]) ? $this->container[$offset] : null;
    }

    /**
     * Sets value based on offset.
     *
     * @param integer $offset Offset
     * @param mixed   $value  Value to be set
     *
     * @return void
     */
    #[\ReturnTypeWillChange]
    public function offsetSet($offset, $value)
    {
        if (is_null($offset)) {
            $this->container[] = $value;
        } else {
            $this->container[$offset] = $value;
        }
    }

    /**
     * Unsets offset.
     *
     * @param integer $offset Offset
     *
     * @return void
     */
    #[\ReturnTypeWillChange]
    public function offsetUnset($offset)
    {
        unset($this->container[$offset]);
    }

    /**
     * Gets the string presentation of the object
     *
     * @return string
     */
    public function __toString()
    {
        if (defined('JSON_PRETTY_PRINT')) { // use JSON pretty print
            return json_encode(
                ObjectSerializer::sanitizeForSerialization($this),
                JSON_PRETTY_PRINT
            );
        }

        return json_encode(ObjectSerializer::sanitizeForSerialization($this));
    }
}
