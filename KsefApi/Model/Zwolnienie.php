<?php
/**
 * Zwolnienie
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
 * Zwolnienie Class Doc Comment
 *
 * @category Class
 * @package  KsefApi
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */
class Zwolnienie implements ModelInterface, ArrayAccess
{
    const DISCRIMINATOR = null;

    /**
      * The original name of the model.
      *
      * @var string
      */
    protected static $swaggerModelName = 'Zwolnienie';

    /**
      * Array of property to type mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerTypes = [
        'p_19' => '\KsefApi\Model\TWybor1',
        'p_19_a' => '\KsefApi\Model\TZnakowy',
        'p_19_b' => '\KsefApi\Model\TZnakowy',
        'p_19_c' => '\KsefApi\Model\TZnakowy',
        'p_19_n' => '\KsefApi\Model\TWybor1'
    ];

    /**
      * Array of property to format mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerFormats = [
        'p_19' => null,
        'p_19_a' => null,
        'p_19_b' => null,
        'p_19_c' => null,
        'p_19_n' => null
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
        'p_19' => 'P_19',
        'p_19_a' => 'P_19A',
        'p_19_b' => 'P_19B',
        'p_19_c' => 'P_19C',
        'p_19_n' => 'P_19N'
    ];

    /**
     * Array of attributes to setter functions (for deserialization of responses)
     *
     * @var string[]
     */
    protected static $setters = [
        'p_19' => 'setP19',
        'p_19_a' => 'setP19A',
        'p_19_b' => 'setP19B',
        'p_19_c' => 'setP19C',
        'p_19_n' => 'setP19N'
    ];

    /**
     * Array of attributes to getter functions (for serialization of requests)
     *
     * @var string[]
     */
    protected static $getters = [
        'p_19' => 'getP19',
        'p_19_a' => 'getP19A',
        'p_19_b' => 'getP19B',
        'p_19_c' => 'getP19C',
        'p_19_n' => 'getP19N'
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
        $this->container['p_19'] = isset($data['p_19']) ? $data['p_19'] : null;
        $this->container['p_19_a'] = isset($data['p_19_a']) ? $data['p_19_a'] : null;
        $this->container['p_19_b'] = isset($data['p_19_b']) ? $data['p_19_b'] : null;
        $this->container['p_19_c'] = isset($data['p_19_c']) ? $data['p_19_c'] : null;
        $this->container['p_19_n'] = isset($data['p_19_n']) ? $data['p_19_n'] : null;
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
     * Gets p_19
     *
     * @return \KsefApi\Model\TWybor1
     */
    public function getP19()
    {
        return $this->container['p_19'];
    }

    /**
     * Sets p_19
     *
     * @param \KsefApi\Model\TWybor1 $p_19 p_19
     *
     * @return $this
     */
    public function setP19($p_19)
    {
        $this->container['p_19'] = $p_19;

        return $this;
    }

    /**
     * Gets p_19_a
     *
     * @return \KsefApi\Model\TZnakowy
     */
    public function getP19A()
    {
        return $this->container['p_19_a'];
    }

    /**
     * Sets p_19_a
     *
     * @param \KsefApi\Model\TZnakowy $p_19_a p_19_a
     *
     * @return $this
     */
    public function setP19A($p_19_a)
    {
        $this->container['p_19_a'] = $p_19_a;

        return $this;
    }

    /**
     * Gets p_19_b
     *
     * @return \KsefApi\Model\TZnakowy
     */
    public function getP19B()
    {
        return $this->container['p_19_b'];
    }

    /**
     * Sets p_19_b
     *
     * @param \KsefApi\Model\TZnakowy $p_19_b p_19_b
     *
     * @return $this
     */
    public function setP19B($p_19_b)
    {
        $this->container['p_19_b'] = $p_19_b;

        return $this;
    }

    /**
     * Gets p_19_c
     *
     * @return \KsefApi\Model\TZnakowy
     */
    public function getP19C()
    {
        return $this->container['p_19_c'];
    }

    /**
     * Sets p_19_c
     *
     * @param \KsefApi\Model\TZnakowy $p_19_c p_19_c
     *
     * @return $this
     */
    public function setP19C($p_19_c)
    {
        $this->container['p_19_c'] = $p_19_c;

        return $this;
    }

    /**
     * Gets p_19_n
     *
     * @return \KsefApi\Model\TWybor1
     */
    public function getP19N()
    {
        return $this->container['p_19_n'];
    }

    /**
     * Sets p_19_n
     *
     * @param \KsefApi\Model\TWybor1 $p_19_n p_19_n
     *
     * @return $this
     */
    public function setP19N($p_19_n)
    {
        $this->container['p_19_n'] = $p_19_n;

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
