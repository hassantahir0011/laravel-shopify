<?php

namespace Oseintow\Shopify;

use GuzzleHttp\Client;
use Oseintow\Shopify\Exceptions\ShopifyApiException;
use Oseintow\Shopify\Exceptions\ShopifyApiResourceNotFoundException;

class Shopify
{
    protected $key;
    protected $secret;
    protected $shopDomain;
    protected $accessToken;
    protected $requestHeaders = [];
    protected $responseHeaders = [];
    protected $client;
    protected $responseStatusCode;
    protected $reasonPhrase;

    public function __construct(Client $client)
    {
        $this->client = $client;
        $this->key = config('shopify.key');
        $this->secret = config('shopify.secret');
    }

    /*
     * Set Shop  Url;
     */
    public function setShopUrl($shopUrl)
    {
        $url = parse_url($shopUrl);
        $this->shopDomain = isset($url['host']) ? $url['host'] : $this->removeProtocol($shopUrl);

        return $this;
    }

    private function baseUrl()
    {
        return "https://{$this->shopDomain}/";
    }

    // Get the URL required to request authorization
    public function getAuthorizeUrl($scope = [] || '', $redirect_url='',$nonce='')
    {
        if (is_array($scope)) $scope = implode(",", $scope);

        $url = "https://{$this->shopDomain}/admin/oauth/authorize?client_id={$this->key}&scope=" . urlencode($scope);
        
        if ($redirect_url != '') $url .= "&redirect_uri=" . urlencode($redirect_url);

        if ($nonce!='') $url .= "&state=" . urlencode($nonce);
        
        return $url;
    }

    public function getAccessToken($code)
    {
        $uri = "admin/oauth/access_token";
        $payload = ["client_id" => $this->key, 'client_secret' => $this->secret, 'code' => $code];
        $response = $this->makeRequest('POST', $uri, $payload);

        return $response ?? '';
    }

    // expiring=1 authorization-code grant. Uses requestOAuthToken, not makeRequest — makeRequest array_shifts
    // the body and would drop refresh_token.
    public function getExpiringAccessToken($code)
    {
        return $this->requestOAuthToken([
            'client_id'     => $this->key,
            'client_secret' => $this->secret,
            'code'          => $code,
            'expiring'      => 1,
        ]);
    }

    // One-time exchange of a non-expiring offline token for an expiring one; Shopify revokes the old token.
    public function exchangeForExpiringToken($offlineToken)
    {
        return $this->requestOAuthToken([
            'client_id'           => $this->key,
            'client_secret'       => $this->secret,
            'grant_type'          => 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token'       => $offlineToken,
            'subject_token_type'  => 'urn:shopify:params:oauth:token-type:offline-access-token',
            'requested_token_type'=> 'urn:shopify:params:oauth:token-type:offline-access-token',
            'expiring'            => 1,
        ]);
    }

    // Rotate the access token; Shopify also rotates the refresh token, so callers must persist the new one.
    public function refreshAccessToken($refreshToken)
    {
        return $this->requestOAuthToken([
            'client_id'     => $this->key,
            'client_secret' => $this->secret,
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
        ]);
    }

    // Own OAuth path (not makeRequest): makeRequest array_shifts the body, dropping refresh_token, and
    // throws on non-2xx. Returns the full response and never throws.
    private function requestOAuthToken($payload)
    {
        $result = [
            'ok'                       => false,
            'access_token'             => null,
            'refresh_token'            => null,
            'expires_in'               => null,
            'refresh_token_expires_in' => null,
            'scope'                    => null,
            'status'                   => null,
            'error_type'               => null,
            'error'                    => null,
            'retry_after'              => null,
        ];

        try {
            $response = $this->client->request('POST', $this->baseUrl() . 'admin/oauth/access_token', [
                'form_params'     => $payload,
                'timeout'         => 15.0,
                'connect_timeout' => 10.0,
                'http_errors'     => false,
                'verify'          => false,
            ]);
        } catch (\Throwable $e) {
            $result['error_type'] = 'network';
            $result['error'] = $e->getMessage();
            return $result;
        }

        $status = $response->getStatusCode();
        $result['status'] = $status;
        $body = json_decode($response->getBody(), true);

        if ($status == 429) {
            $result['error_type'] = 'rate_limited';
            $retryAfter = $response->getHeader('Retry-After');
            $result['retry_after'] = isset($retryAfter[0]) ? (int) $retryAfter[0] : 10;
            return $result;
        }

        if ($status >= 500) {
            $result['error_type'] = 'server_error';
            $result['error'] = is_array($body) ? json_encode($body) : (string) $response->getBody();
            return $result;
        }

        if (!is_array($body)) {
            $result['error_type'] = 'invalid_response';
            $result['error'] = (string) $response->getBody();
            return $result;
        }

        if ($status >= 400 || isset($body['error'])) {
            $errorCode = $body['error'] ?? '';
            // Terminal cases only. A dead refresh token (expired, replaced, revoked, uninstalled) is always
            // 401 {"error":"invalid_request"}; a dead exchange subject is 400 invalid_subject_token. Anything
            // else is transient and retried with the same token.
            $needsReauth = $status == 401
                || in_array($errorCode, ['invalid_grant', 'invalid_subject_token', 'invalid_token'], true);
            $result['error_type'] = $needsReauth ? 'invalid_grant' : 'server_error';
            $result['error'] = json_encode($body);
            return $result;
        }

        if (empty($body['access_token'])) {
            $result['error_type'] = 'invalid_response';
            $result['error'] = json_encode($body);
            return $result;
        }

        $result['ok'] = true;
        $result['access_token'] = $body['access_token'];
        $result['refresh_token'] = $body['refresh_token'] ?? null;
        $result['expires_in'] = $body['expires_in'] ?? null;
        $result['refresh_token_expires_in'] = $body['refresh_token_expires_in'] ?? null;
        $result['scope'] = $body['scope'] ?? null;

        return $result;
    }

    public function setAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;

        return $this;
    }
    
    public function setKey($key)
    {
        $this->key = $key;

        return $this;
    }
    
    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    private function setXShopifyAccessToken()
    {
        return ['X-Shopify-Access-Token' => $this->accessToken];
    }

    public function addHeader($key, $value)
    {
        $this->requestHeaders = array_merge($this->requestHeaders, [$key => $value]);

        return $this;
    }

    public function removeHeaders()
    {
        $this->requestHeaders = [];

        return $this;
    }

    /*
     *  $args[0] is for route uri and $args[1] is either request body or query strings
     */
    public function __call($method, $args)
    {
        list($uri, $params) = [ltrim($args[0],"/"), $args[1] ?? []];
        $response = $this->makeRequest($method, $uri, $params, $this->setXShopifyAccessToken());

        return (is_array($response)) ? $this->convertResponseToCollection($response) : $response;
    }

    private function convertResponseToCollection($response)
    {
        return collect(json_decode(json_encode($response)));
    }

    private function makeRequest($method, $uri, $params = [], $headers = [])
    {
        $query = in_array($method, ['get','delete']) ? "query" : "json";

        $rateLimit = explode("/", $this->getHeader("X-Shopify-Shop-Api-Call-Limit"));

        if($rateLimit[0] >= 38 ) sleep(15);

        $response = $this->client->request(strtoupper($method), $this->baseUrl().$uri, [
                'headers' => array_merge($headers, $this->requestHeaders),
                $query => $params,
                'timeout' => 120.0,
                'connect_timeout' => 120.0,
                'http_errors' => false,
                "verify" => false
            ]);

        $this->parseResponse($response);
        $responseBody = $this->responseBody($response);
        $response_for_mutation = $responseBody;
        $userErrors = isset($response_for_mutation['data']) && is_array($response_for_mutation['data']) ? array_shift($response_for_mutation['data']) : [];

        $errors = '';
        if (isset($responseBody['errors']) || (!empty($userErrors['userErrors'] ?? null)) || $response->getStatusCode() >= 400) {
            if(isset($responseBody['errors']))
                $errors .= is_array($responseBody['errors']) ? json_encode($responseBody['errors']) : $responseBody['errors'];
            if((!empty($userErrors['userErrors'] ?? null)))
                $errors .= is_array($userErrors['userErrors']) ? json_encode($userErrors['userErrors']): $userErrors['userErrors'];
            if($response->getStatusCode()  == 404) {
                throw new ShopifyApiResourceNotFoundException(
                    !empty($errors) ? $errors : $response->getReasonPhrase(),
                    $response->getStatusCode()
                );
            }

            throw new ShopifyApiException(
                !empty($errors) ? $errors : $response->getReasonPhrase(),
                $response->getStatusCode()
            );
        }

        if(isset($responseBody['extensions']))
            $responseBody['data']['extensions'] = $responseBody['extensions'];

        return (is_array($responseBody) && (count($responseBody) > 0)) ? array_shift($responseBody) : $responseBody;
    }

    private function parseResponse($response)
    {
        $this->parseHeaders($response->getHeaders());
        $this->setStatusCode($response->getStatusCode());
        $this->setReasonPhrase($response->getReasonPhrase());
    }

    public function verifyRequest($queryParams)
    {
        if (is_string($queryParams)) {
            $data = [];

            $queryParams = explode('&', $queryParams);
            foreach($queryParams as $queryParam)
            {
                list($key, $value) = explode('=', $queryParam);
                $data[$key] = urldecode($value);
            }

            $queryParams = $data;
        }

        $hmac = $queryParams['hmac'] ?? '';

        unset($queryParams['signature'], $queryParams['hmac']);

        ksort($queryParams);

        $params = collect($queryParams)->map(function($value, $key){
            $key   = strtr($key, ['&' => '%26', '%' => '%25', '=' => '%3D']);
            $value = strtr($value, ['&' => '%26', '%' => '%25']);

            return $key . '=' . $value;
        })->implode("&");

        $calculatedHmac = hash_hmac('sha256', $params, $this->secret);

        return hash_equals($hmac, $calculatedHmac);
    }

    public function verifyWebHook($data, $hmacHeader)
    {
        $calculatedHmac = base64_encode(hash_hmac('sha256', $data, $this->secret, true));

        return ($hmacHeader == $calculatedHmac);
    }

    private function setStatusCode($code)
    {
        $this->responseStatusCode = $code;
    }

    public function getStatusCode()
    {
        return $this->responseStatusCode;
    }

    private function setReasonPhrase($message)
    {
        $this->reasonPhrase = $message;
    }

    public function getReasonPhrase()
    {
        return $this->reasonPhrase;
    }

    private function parseHeaders($headers)
    {
        foreach ($headers as $name => $values) {
            $this->responseHeaders = array_merge($this->responseHeaders, [$name => implode(', ', $values)]);
        }
    }

    public function getHeaders()
    {
        return $this->responseHeaders;
    }

    public function getHeader($header)
    {
        return $this->hasHeader($header) ? $this->responseHeaders[$header] : '';
    }

    public function hasHeader($header)
    {
        return array_key_exists($header, $this->responseHeaders);
    }

    private function responseBody($response)
    {
        return json_decode($response->getBody(), true);
    }

    public function removeProtocol($url)
    {
        $disallowed = ['http://', 'https://','http//','ftp://','ftps://'];
        foreach ($disallowed as $d) {
            if (strpos($url, $d) === 0) {
                return str_replace($d, '', $url);
            }
        }

        return $url;
    }

}
