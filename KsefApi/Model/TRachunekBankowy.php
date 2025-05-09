<?php
/**
 * TRachunekBankowy
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
 * TRachunekBankowy Class Doc Comment
 *
 * @category Class
 * @description Informacje o rachunku
 * @package  KsefApi
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */
class TRachunekBankowy implements ModelInterface, ArrayAccess
{
    const DISCRIMINATOR = null;

    /**
      * The original name of the model.
      *
      * @var string
      */
    protected static $swaggerModelName = 'TRachunekBankowy';

    /**
      * Array of property to type mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerTypes = [
        'nr_rb' => '\KsefApi\Model\TNrRB',
        'swift' => '\KsefApi\Model\SWIFTType',
        'rachunek_wlasny_banku' => '\KsefApi\Model\TRachunekWlasnyBanku',
        'nazwa_banku' => '\KsefApi\Model\TZnakowy',
        'opis_rachunku' => '\KsefApi\Model\TZnakowy'
    ];

    /**
      * Array of property to format mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerFormats = [
        'nr_rb' => null,
        'swift' => null,
        'rachunek_wlasny_banku' => null,
        'nazwa_banku' => null,
        'opis_rachunku' => null
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
        'nr_rb' => 'NrRB',
        'swift' => 'SWIFT',
        'rachunek_wlasny_banku' => 'RachunekWlasnyBanku',
        'nazwa_banku' => 'NazwaBanku',
        'opis_rachunku' => 'OpisRachunku'
    ];

    /**
     * Array of attributes to setter functions (for deserialization of responses)
     *
     * @var string[]
     */
    protected static $setters = [
        'nr_rb' => 'setNrRb',
        'swift' => 'setSwift',
        'rachunek_wlasny_banku' => 'setRachunekWlasnyBanku',
        'nazwa_banku' => 'setNazwaBanku',
        'opis_rachunku' => 'setOpisRachunku'
    ];

    /**
     * Array of attributes to getter functions (for serialization of requests)
     *
     * @var string[]
     */
    protected static $getters = [
        'nr_rb' => 'getNrRb',
        'swift' => 'getSwift',
        'rachunek_wlasny_banku' => 'getRachunekWlasnyBanku',
        'nazwa_banku' => 'getNazwaBanku',
        'opis_rachunku' => 'getOpisRachunku'
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
        $this->container['nr_rb'] = isset($data['nr_rb']) ? $data['nr_rb'] : null;
        $this->container['swift'] = isset($data['swift']) ? $data['swift'] : null;
        $this->container['rachunek_wlasny_banku'] = isset($data['rachunek_wlasny_banku']) ? $data['rachunek_wlasny_banku'] : null;
        $this->container['nazwa_banku'] = isset($data['nazwa_banku']) ? $data['nazwa_banku'] : null;
        $this->container['opis_rachunku'] = isset($data['opis_rachunku']) ? $data['opis_rachunku'] : null;
    }

    /**
     * Show all the invalid properties with reasons.
     *
     * @return array invalid properties with reasons
     */
    public function listInvalidProperties()
    {
        $invalidProperties = [];

        if ($this->container['nr_rb'] === null) {
            $invalidProperties[] = "'nr_rb' can't be null";
        }
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
     * Gets nr_rb
     *
     * @return \KsefApi\Model\TNrRB
     */
    public function getNrRb()
    {
        return $this->container['nr_rb'];
    }

    /**
     * Sets nr_rb
     *
     * @param \KsefApi\Model\TNrRB $nr_rb nr_rb
     *
     * @return $this
     */
    public function setNrRb($nr_rb)
    {
        $this->container['nr_rb'] = $nr_rb;

        return $this;
    }

    /**
     * Gets swift
     *
     * @return \KsefApi\Model\SWIFTType
     */
    public function getSwift()
    {
        return $this->container['swift'];
    }

    /**
     * Sets swift
     *
     * @param \KsefApi\Model\SWIFTType $swift swift
     *
     * @return $this
     */
    public function setSwift($swift)
    {
        $this->container['swift'] = $swift;

        return $this;
    }

    /**
     * Gets rachunek_wlasny_banku
     *
     * @return \KsefApi\Model\TRachunekWlasnyBanku
     */
    public function getRachunekWlasnyBanku()
    {
        return $this->container['rachunek_wlasny_banku'];
    }

    /**
     * Sets rachunek_wlasny_banku
     *
     * @param \KsefApi\Model\TRachunekWlasnyBanku $rachunek_wlasny_banku rachunek_wlasny_banku
     *
     * @return $this
     */
    public function setRachunekWlasnyBanku($rachunek_wlasny_banku)
    {
        $this->container['rachunek_wlasny_banku'] = $rachunek_wlasny_banku;

        return $this;
    }

    /**
     * Gets nazwa_banku
     *
     * @return \KsefApi\Model\TZnakowy
     */
    public function getNazwaBanku()
    {
        return $this->container['nazwa_banku'];
    }

    /**
     * Sets nazwa_banku
     *
     * @param \KsefApi\Model\TZnakowy $nazwa_banku nazwa_banku
     *
     * @return $this
     */
    public function setNazwaBanku($nazwa_banku)
    {
        $this->container['nazwa_banku'] = $nazwa_banku;

        return $this;
    }

    /**
     * Gets opis_rachunku
     *
     * @return \KsefApi\Model\TZnakowy
     */
    public function getOpisRachunku()
    {
        return $this->container['opis_rachunku'];
    }

    /**
     * Sets opis_rachunku
     *
     * @param \KsefApi\Model\TZnakowy $opis_rachunku opis_rachunku
     *
     * @return $this
     */
    public function setOpisRachunku($opis_rachunku)
    {
        $this->container['opis_rachunku'] = $opis_rachunku;

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
