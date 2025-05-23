<?php
/**
 * TKodKraju
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
use \KsefApi\ObjectSerializer;

/**
 * TKodKraju Class Doc Comment
 *
 * @category Class
 * @description Słownik kodów krajów
 * @package  KsefApi
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */
class TKodKraju
{
    /**
     * Possible values of this enum
     */
    const AF = 'AF';
    const AX = 'AX';
    const AL = 'AL';
    const DZ = 'DZ';
    const AD = 'AD';
    const AO = 'AO';
    const AI = 'AI';
    const AQ = 'AQ';
    const AG = 'AG';
    const AN = 'AN';
    const SA = 'SA';
    const AR = 'AR';
    const AM = 'AM';
    const AW = 'AW';
    const AU = 'AU';
    const AT = 'AT';
    const AZ = 'AZ';
    const BS = 'BS';
    const BH = 'BH';
    const BD = 'BD';
    const BB = 'BB';
    const BE = 'BE';
    const BZ = 'BZ';
    const BJ = 'BJ';
    const BM = 'BM';
    const BT = 'BT';
    const BY = 'BY';
    const BO = 'BO';
    const BQ = 'BQ';
    const BA = 'BA';
    const BW = 'BW';
    const BR = 'BR';
    const BN = 'BN';
    const IO = 'IO';
    const BG = 'BG';
    const BF = 'BF';
    const BI = 'BI';
    const XC = 'XC';
    const CL = 'CL';
    const CN = 'CN';
    const HR = 'HR';
    const CW = 'CW';
    const CY = 'CY';
    const TD = 'TD';
    const ME = 'ME';
    const DK = 'DK';
    const DM = 'DM';
    const _DO = 'DO';
    const DJ = 'DJ';
    const EG = 'EG';
    const EC = 'EC';
    const ER = 'ER';
    const EE = 'EE';
    const ET = 'ET';
    const FK = 'FK';
    const FJ = 'FJ';
    const PH = 'PH';
    const FI = 'FI';
    const FR = 'FR';
    const TF = 'TF';
    const GA = 'GA';
    const GM = 'GM';
    const GH = 'GH';
    const GI = 'GI';
    const GR = 'GR';
    const GD = 'GD';
    const GL = 'GL';
    const GE = 'GE';
    const GU = 'GU';
    const GG = 'GG';
    const GY = 'GY';
    const GF = 'GF';
    const GP = 'GP';
    const GT = 'GT';
    const GN = 'GN';
    const GQ = 'GQ';
    const GW = 'GW';
    const HT = 'HT';
    const ES = 'ES';
    const HN = 'HN';
    const HK = 'HK';
    const IN = 'IN';
    const ID = 'ID';
    const IQ = 'IQ';
    const IR = 'IR';
    const IE = 'IE';
    const IS = 'IS';
    const IL = 'IL';
    const JM = 'JM';
    const JP = 'JP';
    const YE = 'YE';
    const JE = 'JE';
    const JO = 'JO';
    const KY = 'KY';
    const KH = 'KH';
    const CM = 'CM';
    const CA = 'CA';
    const QA = 'QA';
    const KZ = 'KZ';
    const KE = 'KE';
    const KG = 'KG';
    const KI = 'KI';
    const CO = 'CO';
    const KM = 'KM';
    const CG = 'CG';
    const CD = 'CD';
    const KP = 'KP';
    const XK = 'XK';
    const CR = 'CR';
    const CU = 'CU';
    const KW = 'KW';
    const LA = 'LA';
    const LS = 'LS';
    const LB = 'LB';
    const LR = 'LR';
    const LY = 'LY';
    const LI = 'LI';
    const LT = 'LT';
    const LV = 'LV';
    const LU = 'LU';
    const MK = 'MK';
    const MG = 'MG';
    const YT = 'YT';
    const MO = 'MO';
    const MW = 'MW';
    const MV = 'MV';
    const MY = 'MY';
    const ML = 'ML';
    const MT = 'MT';
    const MP = 'MP';
    const MA = 'MA';
    const MQ = 'MQ';
    const MR = 'MR';
    const MU = 'MU';
    const MX = 'MX';
    const XL = 'XL';
    const FM = 'FM';
    const UM = 'UM';
    const MD = 'MD';
    const MC = 'MC';
    const MN = 'MN';
    const MS = 'MS';
    const MZ = 'MZ';
    const MM = 'MM';
    const NA = 'NA';
    const NR = 'NR';
    const NP = 'NP';
    const NL = 'NL';
    const DE = 'DE';
    const NE = 'NE';
    const NG = 'NG';
    const NI = 'NI';
    const NU = 'NU';
    const NF = 'NF';
    const FALSE = 'false';
    const NC = 'NC';
    const NZ = 'NZ';
    const PS = 'PS';
    const OM = 'OM';
    const PK = 'PK';
    const PW = 'PW';
    const PA = 'PA';
    const PG = 'PG';
    const PY = 'PY';
    const PE = 'PE';
    const PN = 'PN';
    const PF = 'PF';
    const PL = 'PL';
    const GS = 'GS';
    const PT = 'PT';
    const PR = 'PR';
    const CF = 'CF';
    const CZ = 'CZ';
    const KR = 'KR';
    const ZA = 'ZA';
    const RE = 'RE';
    const RU = 'RU';
    const RO = 'RO';
    const RW = 'RW';
    const EH = 'EH';
    const BL = 'BL';
    const KN = 'KN';
    const LC = 'LC';
    const MF = 'MF';
    const VC = 'VC';
    const SV = 'SV';
    const WS = 'WS';
    const _AS = 'AS';
    const SM = 'SM';
    const SN = 'SN';
    const RS = 'RS';
    const SC = 'SC';
    const SL = 'SL';
    const SG = 'SG';
    const SK = 'SK';
    const SI = 'SI';
    const SO = 'SO';
    const LK = 'LK';
    const PM = 'PM';
    const US = 'US';
    const SZ = 'SZ';
    const SD = 'SD';
    const SS = 'SS';
    const SR = 'SR';
    const SJ = 'SJ';
    const SH = 'SH';
    const SY = 'SY';
    const CH = 'CH';
    const SE = 'SE';
    const TJ = 'TJ';
    const TH = 'TH';
    const TW = 'TW';
    const TZ = 'TZ';
    const TG = 'TG';
    const TK = 'TK';
    const TO = 'TO';
    const TT = 'TT';
    const TN = 'TN';
    const TR = 'TR';
    const TM = 'TM';
    const TV = 'TV';
    const UG = 'UG';
    const UA = 'UA';
    const UY = 'UY';
    const UZ = 'UZ';
    const VU = 'VU';
    const WF = 'WF';
    const VA = 'VA';
    const HU = 'HU';
    const VE = 'VE';
    const GB = 'GB';
    const VN = 'VN';
    const IT = 'IT';
    const TL = 'TL';
    const CI = 'CI';
    const BV = 'BV';
    const CX = 'CX';
    const IM = 'IM';
    const SX = 'SX';
    const CK = 'CK';
    const VI = 'VI';
    const VG = 'VG';
    const HM = 'HM';
    const CC = 'CC';
    const MH = 'MH';
    const FO = 'FO';
    const SB = 'SB';
    const ST = 'ST';
    const TC = 'TC';
    const ZM = 'ZM';
    const CV = 'CV';
    const ZW = 'ZW';
    const AE = 'AE';
    const XI = 'XI';
    /**
     * Gets allowable values of the enum
     * @return string[]
     */
    public static function getAllowableEnumValues()
    {
        return [
            self::AF
            self::AX
            self::AL
            self::DZ
            self::AD
            self::AO
            self::AI
            self::AQ
            self::AG
            self::AN
            self::SA
            self::AR
            self::AM
            self::AW
            self::AU
            self::AT
            self::AZ
            self::BS
            self::BH
            self::BD
            self::BB
            self::BE
            self::BZ
            self::BJ
            self::BM
            self::BT
            self::BY
            self::BO
            self::BQ
            self::BA
            self::BW
            self::BR
            self::BN
            self::IO
            self::BG
            self::BF
            self::BI
            self::XC
            self::CL
            self::CN
            self::HR
            self::CW
            self::CY
            self::TD
            self::ME
            self::DK
            self::DM
            self::_DO
            self::DJ
            self::EG
            self::EC
            self::ER
            self::EE
            self::ET
            self::FK
            self::FJ
            self::PH
            self::FI
            self::FR
            self::TF
            self::GA
            self::GM
            self::GH
            self::GI
            self::GR
            self::GD
            self::GL
            self::GE
            self::GU
            self::GG
            self::GY
            self::GF
            self::GP
            self::GT
            self::GN
            self::GQ
            self::GW
            self::HT
            self::ES
            self::HN
            self::HK
            self::IN
            self::ID
            self::IQ
            self::IR
            self::IE
            self::IS
            self::IL
            self::JM
            self::JP
            self::YE
            self::JE
            self::JO
            self::KY
            self::KH
            self::CM
            self::CA
            self::QA
            self::KZ
            self::KE
            self::KG
            self::KI
            self::CO
            self::KM
            self::CG
            self::CD
            self::KP
            self::XK
            self::CR
            self::CU
            self::KW
            self::LA
            self::LS
            self::LB
            self::LR
            self::LY
            self::LI
            self::LT
            self::LV
            self::LU
            self::MK
            self::MG
            self::YT
            self::MO
            self::MW
            self::MV
            self::MY
            self::ML
            self::MT
            self::MP
            self::MA
            self::MQ
            self::MR
            self::MU
            self::MX
            self::XL
            self::FM
            self::UM
            self::MD
            self::MC
            self::MN
            self::MS
            self::MZ
            self::MM
            self::NA
            self::NR
            self::NP
            self::NL
            self::DE
            self::NE
            self::NG
            self::NI
            self::NU
            self::NF
            self::FALSE
            self::NC
            self::NZ
            self::PS
            self::OM
            self::PK
            self::PW
            self::PA
            self::PG
            self::PY
            self::PE
            self::PN
            self::PF
            self::PL
            self::GS
            self::PT
            self::PR
            self::CF
            self::CZ
            self::KR
            self::ZA
            self::RE
            self::RU
            self::RO
            self::RW
            self::EH
            self::BL
            self::KN
            self::LC
            self::MF
            self::VC
            self::SV
            self::WS
            self::_AS
            self::SM
            self::SN
            self::RS
            self::SC
            self::SL
            self::SG
            self::SK
            self::SI
            self::SO
            self::LK
            self::PM
            self::US
            self::SZ
            self::SD
            self::SS
            self::SR
            self::SJ
            self::SH
            self::SY
            self::CH
            self::SE
            self::TJ
            self::TH
            self::TW
            self::TZ
            self::TG
            self::TK
            self::TO
            self::TT
            self::TN
            self::TR
            self::TM
            self::TV
            self::UG
            self::UA
            self::UY
            self::UZ
            self::VU
            self::WF
            self::VA
            self::HU
            self::VE
            self::GB
            self::VN
            self::IT
            self::TL
            self::CI
            self::BV
            self::CX
            self::IM
            self::SX
            self::CK
            self::VI
            self::VG
            self::HM
            self::CC
            self::MH
            self::FO
            self::SB
            self::ST
            self::TC
            self::ZM
            self::CV
            self::ZW
            self::AE
            self::XI
        ];
    }
}
