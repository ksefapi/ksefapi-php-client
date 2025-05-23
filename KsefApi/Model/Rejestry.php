<?php
/**
 * Rejestry
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
 * Rejestry Class Doc Comment
 *
 * @category Class
 * @description Numery podmiotu lub grupy podmiotów w innych rejestrach i bazach danych
 * @package  KsefApi
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */
class Rejestry implements ModelInterface, ArrayAccess
{
    const DISCRIMINATOR = null;

    /**
      * The original name of the model.
      *
      * @var string
      */
    protected static $swaggerModelName = 'Rejestry';

    /**
      * Array of property to type mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerTypes = [
        'pelna_nazwa' => '\KsefApi\Model\TZnakowy',
        'krs' => '\KsefApi\Model\TNrKRS',
        'regon' => '\KsefApi\Model\TNrREGON',
        'bdo' => '\KsefApi\Model\BDO'
    ];

    /**
      * Array of property to format mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerFormats = [
        'pelna_nazwa' => null,
        'krs' => null,
        'regon' => null,
        'bdo' => null
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
        'pelna_nazwa' => 'PelnaNazwa',
        'krs' => 'KRS',
        'regon' => 'REGON',
        'bdo' => 'BDO'
    ];

    /**
     * Array of attributes to setter functions (for deserialization of responses)
     *
     * @var string[]
     */
    protected static $setters = [
        'pelna_nazwa' => 'setPelnaNazwa',
        'krs' => 'setKrs',
        'regon' => 'setRegon',
        'bdo' => 'setBdo'
    ];

    /**
     * Array of attributes to getter functions (for serialization of requests)
     *
     * @var string[]
     */
    protected static $getters = [
        'pelna_nazwa' => 'getPelnaNazwa',
        'krs' => 'getKrs',
        'regon' => 'getRegon',
        'bdo' => 'getBdo'
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
        $this->container['pelna_nazwa'] = isset($data['pelna_nazwa']) ? $data['pelna_nazwa'] : null;
        $this->container['krs'] = isset($data['krs']) ? $data['krs'] : null;
        $this->container['regon'] = isset($data['regon']) ? $data['regon'] : null;
        $this->container['bdo'] = isset($data['bdo']) ? $data['bdo'] : null;
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
     * Gets pelna_nazwa
     *
     * @return \KsefApi\Model\TZnakowy
     */
    public function getPelnaNazwa()
    {
        return $this->container['pelna_nazwa'];
    }

    /**
     * Sets pelna_nazwa
     *
     * @param \KsefApi\Model\TZnakowy $pelna_nazwa pelna_nazwa
     *
     * @return $this
     */
    public function setPelnaNazwa($pelna_nazwa)
    {
        $this->container['pelna_nazwa'] = $pelna_nazwa;

        return $this;
    }

    /**
     * Gets krs
     *
     * @return \KsefApi\Model\TNrKRS
     */
    public function getKrs()
    {
        return $this->container['krs'];
    }

    /**
     * Sets krs
     *
     * @param \KsefApi\Model\TNrKRS $krs krs
     *
     * @return $this
     */
    public function setKrs($krs)
    {
        $this->container['krs'] = $krs;

        return $this;
    }

    /**
     * Gets regon
     *
     * @return \KsefApi\Model\TNrREGON
     */
    public function getRegon()
    {
        return $this->container['regon'];
    }

    /**
     * Sets regon
     *
     * @param \KsefApi\Model\TNrREGON $regon regon
     *
     * @return $this
     */
    public function setRegon($regon)
    {
        $this->container['regon'] = $regon;

        return $this;
    }

    /**
     * Gets bdo
     *
     * @return \KsefApi\Model\BDO
     */
    public function getBdo()
    {
        return $this->container['bdo'];
    }

    /**
     * Sets bdo
     *
     * @param \KsefApi\Model\BDO $bdo bdo
     *
     * @return $this
     */
    public function setBdo($bdo)
    {
        $this->container['bdo'] = $bdo;

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
