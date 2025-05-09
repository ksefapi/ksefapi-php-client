<?php
/**
 * KsefInvoiceVisualizeRequest
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
 * KsefInvoiceVisualizeRequest Class Doc Comment
 *
 * @category Class
 * @package  KsefApi
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */
class KsefInvoiceVisualizeRequest implements ModelInterface, ArrayAccess
{
    const DISCRIMINATOR = null;

    /**
      * The original name of the model.
      *
      * @var string
      */
    protected static $swaggerModelName = 'KsefInvoiceVisualizeRequest';

    /**
      * Array of property to type mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerTypes = [
        'include_logo' => 'bool',
        'include_qr_code' => 'bool',
        'output_format' => 'string',
        'output_language' => 'string',
        'invoice_ksef_number' => 'string',
        'invoice_data' => 'string'
    ];

    /**
      * Array of property to format mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerFormats = [
        'include_logo' => null,
        'include_qr_code' => null,
        'output_format' => null,
        'output_language' => null,
        'invoice_ksef_number' => null,
        'invoice_data' => 'byte'
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
        'include_logo' => 'includeLogo',
        'include_qr_code' => 'includeQrCode',
        'output_format' => 'outputFormat',
        'output_language' => 'outputLanguage',
        'invoice_ksef_number' => 'invoiceKsefNumber',
        'invoice_data' => 'invoiceData'
    ];

    /**
     * Array of attributes to setter functions (for deserialization of responses)
     *
     * @var string[]
     */
    protected static $setters = [
        'include_logo' => 'setIncludeLogo',
        'include_qr_code' => 'setIncludeQrCode',
        'output_format' => 'setOutputFormat',
        'output_language' => 'setOutputLanguage',
        'invoice_ksef_number' => 'setInvoiceKsefNumber',
        'invoice_data' => 'setInvoiceData'
    ];

    /**
     * Array of attributes to getter functions (for serialization of requests)
     *
     * @var string[]
     */
    protected static $getters = [
        'include_logo' => 'getIncludeLogo',
        'include_qr_code' => 'getIncludeQrCode',
        'output_format' => 'getOutputFormat',
        'output_language' => 'getOutputLanguage',
        'invoice_ksef_number' => 'getInvoiceKsefNumber',
        'invoice_data' => 'getInvoiceData'
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

    const OUTPUT_FORMAT_HTML = 'html';
    const OUTPUT_FORMAT_PDF = 'pdf';
    const OUTPUT_LANGUAGE_PL = 'pl';

    /**
     * Gets allowable values of the enum
     *
     * @return string[]
     */
    public function getOutputFormatAllowableValues()
    {
        return [
            self::OUTPUT_FORMAT_HTML,
            self::OUTPUT_FORMAT_PDF,
        ];
    }
    /**
     * Gets allowable values of the enum
     *
     * @return string[]
     */
    public function getOutputLanguageAllowableValues()
    {
        return [
            self::OUTPUT_LANGUAGE_PL,
        ];
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
        $this->container['include_logo'] = isset($data['include_logo']) ? $data['include_logo'] : null;
        $this->container['include_qr_code'] = isset($data['include_qr_code']) ? $data['include_qr_code'] : null;
        $this->container['output_format'] = isset($data['output_format']) ? $data['output_format'] : null;
        $this->container['output_language'] = isset($data['output_language']) ? $data['output_language'] : null;
        $this->container['invoice_ksef_number'] = isset($data['invoice_ksef_number']) ? $data['invoice_ksef_number'] : null;
        $this->container['invoice_data'] = isset($data['invoice_data']) ? $data['invoice_data'] : null;
    }

    /**
     * Show all the invalid properties with reasons.
     *
     * @return array invalid properties with reasons
     */
    public function listInvalidProperties()
    {
        $invalidProperties = [];

        if ($this->container['include_logo'] === null) {
            $invalidProperties[] = "'include_logo' can't be null";
        }
        if ($this->container['include_qr_code'] === null) {
            $invalidProperties[] = "'include_qr_code' can't be null";
        }
        if ($this->container['output_format'] === null) {
            $invalidProperties[] = "'output_format' can't be null";
        }
        $allowedValues = $this->getOutputFormatAllowableValues();
        if (!is_null($this->container['output_format']) && !in_array($this->container['output_format'], $allowedValues, true)) {
            $invalidProperties[] = sprintf(
                "invalid value for 'output_format', must be one of '%s'",
                implode("', '", $allowedValues)
            );
        }

        if ($this->container['output_language'] === null) {
            $invalidProperties[] = "'output_language' can't be null";
        }
        $allowedValues = $this->getOutputLanguageAllowableValues();
        if (!is_null($this->container['output_language']) && !in_array($this->container['output_language'], $allowedValues, true)) {
            $invalidProperties[] = sprintf(
                "invalid value for 'output_language', must be one of '%s'",
                implode("', '", $allowedValues)
            );
        }

        if ($this->container['invoice_ksef_number'] === null) {
            $invalidProperties[] = "'invoice_ksef_number' can't be null";
        }
        if ($this->container['invoice_data'] === null) {
            $invalidProperties[] = "'invoice_data' can't be null";
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
     * Gets include_logo
     *
     * @return bool
     */
    public function getIncludeLogo()
    {
        return $this->container['include_logo'];
    }

    /**
     * Sets include_logo
     *
     * @param bool $include_logo include_logo
     *
     * @return $this
     */
    public function setIncludeLogo($include_logo)
    {
        $this->container['include_logo'] = $include_logo;

        return $this;
    }

    /**
     * Gets include_qr_code
     *
     * @return bool
     */
    public function getIncludeQrCode()
    {
        return $this->container['include_qr_code'];
    }

    /**
     * Sets include_qr_code
     *
     * @param bool $include_qr_code include_qr_code
     *
     * @return $this
     */
    public function setIncludeQrCode($include_qr_code)
    {
        $this->container['include_qr_code'] = $include_qr_code;

        return $this;
    }

    /**
     * Gets output_format
     *
     * @return string
     */
    public function getOutputFormat()
    {
        return $this->container['output_format'];
    }

    /**
     * Sets output_format
     *
     * @param string $output_format output_format
     *
     * @return $this
     */
    public function setOutputFormat($output_format)
    {
        $allowedValues = $this->getOutputFormatAllowableValues();
        if (!in_array($output_format, $allowedValues, true)) {
            throw new \InvalidArgumentException(
                sprintf(
                    "Invalid value for 'output_format', must be one of '%s'",
                    implode("', '", $allowedValues)
                )
            );
        }
        $this->container['output_format'] = $output_format;

        return $this;
    }

    /**
     * Gets output_language
     *
     * @return string
     */
    public function getOutputLanguage()
    {
        return $this->container['output_language'];
    }

    /**
     * Sets output_language
     *
     * @param string $output_language output_language
     *
     * @return $this
     */
    public function setOutputLanguage($output_language)
    {
        $allowedValues = $this->getOutputLanguageAllowableValues();
        if (!in_array($output_language, $allowedValues, true)) {
            throw new \InvalidArgumentException(
                sprintf(
                    "Invalid value for 'output_language', must be one of '%s'",
                    implode("', '", $allowedValues)
                )
            );
        }
        $this->container['output_language'] = $output_language;

        return $this;
    }

    /**
     * Gets invoice_ksef_number
     *
     * @return string
     */
    public function getInvoiceKsefNumber()
    {
        return $this->container['invoice_ksef_number'];
    }

    /**
     * Sets invoice_ksef_number
     *
     * @param string $invoice_ksef_number invoice_ksef_number
     *
     * @return $this
     */
    public function setInvoiceKsefNumber($invoice_ksef_number)
    {
        $this->container['invoice_ksef_number'] = $invoice_ksef_number;

        return $this;
    }

    /**
     * Gets invoice_data
     *
     * @return string
     */
    public function getInvoiceData()
    {
        return $this->container['invoice_data'];
    }

    /**
     * Sets invoice_data
     *
     * @param string $invoice_data invoice_data
     *
     * @return $this
     */
    public function setInvoiceData($invoice_data)
    {
        $this->container['invoice_data'] = $invoice_data;

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
