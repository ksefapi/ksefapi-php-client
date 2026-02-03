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

/**
 * KSEF API errors
 */
class ClientError
{
    const CLI_INPUT        = 5001;
	const CLI_CONNECT      = 5002;
    const CLI_AUTH         = 5003;
	const CLI_RESPONSE     = 5004;
	const CLI_EXCEPTION    = 5005;
    const CLI_SEND         = 5006;
    const CLI_PKEY_ALG     = 5007;
    const CLI_PKEY_FORMAT  = 5008;
    const CLI_RSA_ENCRYPT  = 5009;
    const CLI_AES_ENCRYPT  = 5010;
    const CLI_AES_DECRYPT  = 5011;
    const CLI_JSON         = 5012;

	private static array $codes = array(
        self::CLI_INPUT        => 'Nieprawidłowy parametr wejściowy funkcji',
		self::CLI_CONNECT      => 'Nie udało się nawiązać połączenia z serwisem KSEF API',
        self::CLI_AUTH         => 'Niepoprawne dane do autoryzacji użytkownika',
        self::CLI_RESPONSE     => 'Odpowiedź serwisu KSEF API ma nieprawidłowy format',
		self::CLI_EXCEPTION    => 'Funkcja wygenerowała wyjątek',
        self::CLI_SEND         => 'Nie udało się wysłać zapytania do serwisu KSEF API',
        self::CLI_PKEY_ALG     => 'Nieprawidłowy typ algorytmu klucza publicznego KSeF',
        self::CLI_PKEY_FORMAT  => 'Nieprawidłowy format klucza publicznego KSeF',
        self::CLI_RSA_ENCRYPT  => 'Nie udało się zaszyfrować klucza symetrycznego kluczem publicznym KSeF',
        self::CLI_AES_ENCRYPT  => 'Nie udało się zaszyfrować danych kluczem symetrycznym',
        self::CLI_AES_DECRYPT  => 'Nie udało się odszyfrować danych kluczem symetrycznym',
        self::CLI_JSON         => 'Nie udała się konwersja JSON na obiekt modelu lub odwrotna'
    );

    /**
     * Get error message
     * @param int $code error code
     * @return string|null error message
     */
	public static function message(int $code): ?string
    {
	    if ($code < self::CLI_INPUT || $code > self::CLI_JSON) {
	        return null;
        }

		return self::$codes[$code];
	}
}

/* EOF */
