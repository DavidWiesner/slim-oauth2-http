<?php
namespace Chadicus\Slim\OAuth2\Http;

/**
 * Static utility class for bridging Slim Requests/Response to OAuth2 Requests/Response.
 */
class MessageBridge
{
    /**
     * Returns a new instance of \OAuth2\Request based on the given \Slim\Http\Request
     *
     * @param \Slim\Http\Request $request The slim framework request.
     *
     * @return \OAuth2\Request
     */
    public static function newOauth2Request(\Slim\Http\Request $request)
    {
        $post = $request->getParsedBody();
        $post = ($post === false || $post === null) ? [] : $post;
        return new \OAuth2\Request(
            $request->getQueryParams(),
            $post,
            $request->getAttributes(),
            $request->getCookieParams(),
            [],
            $request->getServerParams(),
            $request->getBody(),
            self::cleanupHeaders($request->getHeaders())
        );
    }

    /**
     * Copies values from the given \Oauth2\Response to the given \Slim\Http\Response.
     *
     * @param \OAuth2\ResponseInterface $oauth2Response The OAuth2 server response.
     * @param \Slim\Http\Response $slimResponse The slim framework response.
     *
     * @return void
     */
    public static function mapResponse(\OAuth2\Response $oauth2Response, \Slim\Http\Response &$slimResponse)
    {
        foreach ($oauth2Response->getHttpHeaders() as $key => $value) {
            $slimResponse = $slimResponse->withHeader($key, $value);
        }
        $slimResponse = $slimResponse->withStatus($oauth2Response->getStatusCode(), $oauth2Response->getStatusText());
        $body = $slimResponse->getBody();
        $body->write($oauth2Response->getResponseBody());
        $body->rewind();
    }

    /**
     * Helper method to clean header keys.
     *
     * Slim will convert all headers to Camel-Case style. There are certain headers such as PHP_AUTH_USER that the
     * OAuth2 library requires CAPS_CASE format. This method will adjust those headers as needed.
     *
     * @param \Slim\Http\Headers|array $uncleanHeaders The headers to be cleaned.
     *
     * @return array The cleaned headers
     */
    private static function cleanupHeaders($uncleanHeaders)
    {
        $cleanHeaders = [];
        $headerMap = [
            'Php-Auth-User' => 'PHP_AUTH_USER',
            'Php-Auth-Pw' => 'PHP_AUTH_PW',
            'Php-Auth-Digest' => 'PHP_AUTH_DIGEST',
            'Auth-Type' => 'AUTH_TYPE',
        ];
        foreach ($uncleanHeaders as $key => $value) {
            if (!array_key_exists($key, $headerMap)) {
                $cleanHeaders[$key] = self::reduceHeader($value);
                continue;
            }

            $cleanHeaders[$headerMap[$key]] = self::reduceHeader($value);
        }

        return $cleanHeaders;
    }

    /**
     * reduce an array to a none array representation.
     * If value is an array with size 1 element will replace with the value of the first element e.g.:
     * [123] => 123
     * If element is an array with more than one element, element will be replace with ',' imploded string e.g.:
     * ['1','2'] => '1,2'
     * @param $value
     * @return mixed
     */
    private static function reduceHeader($value)
    {
        if (is_array($value)) {
            return count($value) == 1 ? $value[0] : implode(',', $value);
        }
        return $value;
    }
}
