<?php
declare(strict_types=1);

// golemio klic (api.golemio.cz/api-keys)
$GOLEMIO_API_KEY = '';

// povoleny domeny napr. ['https://fitko.cz'], prazdny = bez omezeni
$ALLOWED_ORIGINS = [];

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

function sendJsonError(int $status, string $code, string $message, ?string $details = null): void {
    http_response_code($status);
    $payload = [
        'ok' => false,
        'code' => $code,
        'message' => $message,
    ];
    if ($details !== null && $details !== '') {
        $payload['details'] = $details;
    }
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

// origin / referer check
if (!empty($ALLOWED_ORIGINS)) {
    $origin = isset($_SERVER['HTTP_ORIGIN']) ? rtrim(strtolower((string)$_SERVER['HTTP_ORIGIN']), '/') : '';
    $referer = isset($_SERVER['HTTP_REFERER']) ? strtolower((string)$_SERVER['HTTP_REFERER']) : '';

    $candidate = $origin;
    if ($candidate === '' && $referer !== '') {
        $parts = parse_url($referer);
        if (is_array($parts) && isset($parts['scheme'], $parts['host'])) {
            $candidate = $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        }
    }

    $allowedNormalized = array_map(static function ($item) {
        return rtrim(strtolower((string)$item), '/');
    }, $ALLOWED_ORIGINS);

    $isAllowed = false;
    if ($candidate !== '') {
        $candidateHost = (string)(parse_url($candidate, PHP_URL_HOST) ?? '');
        foreach ($allowedNormalized as $rule) {
            if ($candidate === $rule || ($candidateHost !== '' && $candidateHost === $rule)) {
                $isAllowed = true;
                break;
            }
        }
    }

    if (!$isAllowed) {
        sendJsonError(403, 'FORBIDDEN_ORIGIN', 'Přístup k API je omezen pouze na povolené domény.');
    }

    if ($origin !== '') {
        header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
        header('Vary: Origin');
    }
}

// klic z promenny nebo env
$apiKey = trim((string)$GOLEMIO_API_KEY);
if ($apiKey === '') {
    $envKey = getenv('GOLEMIO_API_KEY');
    if (is_string($envKey)) {
        $apiKey = trim($envKey);
    }
}

if ($apiKey === '') {
    sendJsonError(
        503,
        'MISSING_API_KEY',
        'V souboru api/boards.php chybí vložený Golemio API klíč ($GOLEMIO_API_KEY).'
    );
}

// gtfs route_type mapovani
function mapGtfsRouteType($type): string {
    switch ((int)$type) {
        case 0:
            return 'tram';
        case 1:
            return 'metro';
        case 2:
            return 'train';
        case 3:
            return 'bus';
        case 11:
            return 'trolleybus';
        default:
            return 'other';
    }
}

function formatPragueHm(?string $iso): string {
    if ($iso === null || $iso === '') {
        return '--:--';
    }
    try {
        $dt = new DateTimeImmutable($iso);
        $dt = $dt->setTimezone(new DateTimeZone('Europe/Prague'));
        return $dt->format('H:i');
    } catch (Throwable $e) {
        return '--:--';
    }
}

function fetchStopDepartures(string $stopName, string $apiKey, int $limit = 14): array {
    // 15s file cache kvuli rate limitu
    $cacheFile = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'golemio_board_' . md5($stopName . '_' . $limit) . '.json';
    $cacheTtlSeconds = 15;

    if (is_file($cacheFile) && (time() - (int)filemtime($cacheFile)) < $cacheTtlSeconds) {
        $cachedRaw = @file_get_contents($cacheFile);
        if (is_string($cachedRaw)) {
            $cached = json_decode($cachedRaw, true);
            if (is_array($cached) && isset($cached['departures'], $cached['fetchedAt'])) {
                $cached['cached'] = true;
                return $cached;
            }
        }
    }

    $query = http_build_query([
        'names' => $stopName,
        'minutesBefore' => 0,
        'minutesAfter' => 180,
        'limit' => $limit,
        'mode' => 'departures',
        'order' => 'real',
        'filter' => 'none',
        'includeMetroTrains' => 'true',
        'preferredTimezone' => 'Europe/Prague',
    ]);

    $url = 'https://api.golemio.cz/v2/pid/departureboards?' . $query;
    $statusCode = 0;
    $responseBody = false;

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json; charset=utf-8',
                'X-Access-Token: ' . $apiKey,
            ],
        ]);
        $responseBody = curl_exec($ch);
        $statusCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($responseBody === false) {
            sendJsonError(502, 'UPSTREAM_ERROR', 'Nepodařilo se spojit se serverem Golemio API.', $curlError);
        }
    } else {
        // fallback kdyz nejde curl
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 10,
                'ignore_errors' => true,
                'header' => "Content-Type: application/json; charset=utf-8\r\nX-Access-Token: " . $apiKey . "\r\n",
            ],
        ]);
        $responseBody = @file_get_contents($url, false, $context);
        if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
            $statusCode = (int)$m[1];
        }
        if ($responseBody === false) {
            sendJsonError(502, 'UPSTREAM_ERROR', 'Nepodařilo se spojit se serverem Golemio API (allow_url_fopen / cURL).');
        }
    }

    if ($statusCode === 401 || $statusCode === 403) {
        sendJsonError(401, 'INVALID_API_KEY', 'Golemio API odmítlo zadaný klíč (X-Access-Token).', 'HTTP ' . $statusCode);
    }
    if ($statusCode === 429) {
        sendJsonError(429, 'RATE_LIMITED', 'Překročen limit požadavků Golemio API. Zkuste to za chvíli.', 'HTTP 429');
    }
    if ($statusCode < 200 || $statusCode >= 300) {
        sendJsonError(502, 'UPSTREAM_ERROR', 'Golemio API vrátilo chybu (HTTP ' . $statusCode . ').', substr((string)$responseBody, 0, 200));
    }

    $decoded = json_decode((string)$responseBody, true);
    $rawList = is_array($decoded) && isset($decoded['departures']) && is_array($decoded['departures'])
        ? $decoded['departures']
        : [];

    $normalized = [];
    foreach ($rawList as $idx => $item) {
        $ts = $item['departure_timestamp'] ?? [];
        $scheduledIso = (string)($ts['scheduled'] ?? $ts['predicted'] ?? '');
        $predictedIso = (string)($ts['predicted'] ?? $scheduledIso);
        if ($scheduledIso === '' && $predictedIso === '') {
            continue;
        }

        $delay = $item['delay'] ?? [];
        $delayAvailable = !empty($delay['is_available']);
        $delaySeconds = $delayAvailable ? (int)($delay['seconds'] ?? 0) : 0;
        $delayMinutes = $delayAvailable
            ? (isset($delay['minutes']) ? (int)$delay['minutes'] : (int)round($delaySeconds / 60))
            : 0;

        $route = $item['route'] ?? [];
        $stop = $item['stop'] ?? [];
        $trip = $item['trip'] ?? [];
        $lastStop = $item['last_stop'] ?? [];

        $platform = isset($stop['platform_code']) && (string)$stop['platform_code'] !== ''
            ? (string)$stop['platform_code']
            : null;

        $normalized[] = [
            'id' => (string)($trip['id'] ?? 'trip') . '_' . (string)($stop['id'] ?? 'stop') . '_' . $scheduledIso . '_' . $idx,
            'line' => (string)($route['short_name'] ?? '?'),
            'routeType' => isset($route['type']) ? mapGtfsRouteType($route['type']) : 'other',
            'isNight' => !empty($route['is_night']),
            'isRegional' => !empty($route['is_regional']),
            'isSubstituteTransport' => !empty($route['is_substitute_transport']),
            'headsign' => (string)($trip['headsign'] ?? $lastStop['name'] ?? 'Neznámý cíl'),
            'lastStopName' => isset($lastStop['name']) ? (string)$lastStop['name'] : null,
            'stopName' => isset($stop['name']) ? (string)$stop['name'] : null,
            'platformCode' => $platform,
            'scheduledIso' => $scheduledIso,
            'predictedIso' => $predictedIso,
            'scheduledTime' => formatPragueHm($scheduledIso),
            'predictedTime' => formatPragueHm($predictedIso),
            'delayAvailable' => $delayAvailable,
            'delayMinutes' => $delayMinutes,
            'delaySeconds' => $delaySeconds,
            'isCanceled' => !empty($trip['is_canceled']),
            'isWheelchairAccessible' => !empty($trip['is_wheelchair_accessible']),
            'isAirConditioned' => !empty($trip['is_air_conditioned']),
            'isAtStop' => !empty($trip['is_at_stop']),
        ];
    }

    // seradit podle realneho odjezdu
    usort($normalized, static function ($a, $b) {
        return strtotime($a['predictedIso']) <=> strtotime($b['predictedIso']);
    });

    $result = [
        'departures' => $normalized,
        'fetchedAt' => gmdate('c'),
        'cached' => false,
    ];

    @file_put_contents($cacheFile, json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

    return $result;
}

$vrsovice = fetchStopDepartures('Praha-Vršovice', $apiKey, 14);
$horky = fetchStopDepartures('Horky', $apiKey, 14);

echo json_encode([
    'ok' => true,
    'serverTime' => gmdate('c'),
    'cached' => $vrsovice['cached'] && $horky['cached'],
    'vrsovice' => [
        'stationKey' => 'vrsovice',
        'stationTitle' => 'Praha-Vršovice',
        'stationSubtitle' => 'Železniční stanice',
        'walkMinutes' => 7,
        'queriedNames' => ['Praha-Vršovice'],
        'departures' => $vrsovice['departures'],
        'fetchedAt' => $vrsovice['fetchedAt'],
    ],
    'horky' => [
        'stationKey' => 'horky',
        'stationTitle' => 'Horky',
        'stationSubtitle' => 'Tramvajová zastávka',
        'walkMinutes' => 2,
        'queriedNames' => ['Horky'],
        'departures' => $horky['departures'],
        'fetchedAt' => $horky['fetchedAt'],
    ],
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
