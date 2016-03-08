<?php

namespace ChadicusTest\Slim\OAuth2\Http;

use Chadicus\Slim\OAuth2\Http\MessageBridge;
use ReflectionProperty;

/**
 * Unit tests for the \Chadicus\Slim\OAuth2\Http\MessageBridge class.
 *
 * @coversDefaultClass \Chadicus\Slim\OAuth2\Http\MessageBridge
 * @covers ::<private>
 */
final class MessageBridgeTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Verify basic behavior of newOAuth2Request()
     *
     * @test
     * @covers ::newOAuth2Request
     *
     * @return void
     */
    public function newOAuth2Request()
    {
        $body = 'foo=bar&abc=123';
        $env = \Slim\Http\Environment::mock(
            [
                'REQUEST_METHOD' => 'POST',
                'QUERY_STRING' => 'one=1&two=2&three=3',
                'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
                'CONTENT_LENGTH' => 15,
            ]
        );

        $slimRequest = \Slim\Http\Request::createFromEnvironment($env);
        $bodyStream = $slimRequest->getBody();
        $bodyStream->write($body);
        $bodyStream->rewind();
        $slimRequest = $slimRequest->withBody($bodyStream);
        $prop = new ReflectionProperty($slimRequest, 'bodyParsed');
        $prop->setAccessible(true);
        $prop->setValue($slimRequest, false);

        $this->assertSame(15, $slimRequest->getContentLength());
        $this->assertSame('application/x-www-form-urlencoded', $slimRequest->getContentType());
        $this->assertSame('123', $slimRequest->getParsedBodyParam('abc'));
        $this->assertSame('bar', $slimRequest->getParsedBodyParam('foo'));
        $this->assertSame('2', $slimRequest->getQueryParam('two'));
        $this->assertSame('POST', $slimRequest->getMethod());


        $oauth2Request = MessageBridge::newOauth2Request($slimRequest);

        $this->assertSame(15, $oauth2Request->headers('Content_Length'));
        $this->assertSame('application/x-www-form-urlencoded', $oauth2Request->headers('Content_Type'));
        $this->assertSame('123', $oauth2Request->request('abc'));
        $this->assertSame('bar', $oauth2Request->request('foo'));
        $this->assertSame('2', $oauth2Request->query('two'));
        $this->assertSame('POST', $oauth2Request->server('REQUEST_METHOD'));
    }

    /**
     * Verify behavior of newOAuth2Request() with application/json content type
     *
     * @test
     * @covers ::newOAuth2Request
     *
     * @return void
     */
    public function newOAuth2RequestJsonContentType()
    {
        $json = json_encode(
            [
                'foo' => 'bar',
                'abc' => '123',
            ]
        );
        $env = \Slim\Http\Environment::mock(
            [
                'REQUEST_METHOD' => 'POST',
                'CONTENT_LENGTH' => strlen($json),
                'CONTENT_TYPE' => 'application/json',
            ]
        );

        $slimRequest = \Slim\Http\Request::createFromEnvironment($env);
        $bodyStream = $slimRequest->getBody();
        $bodyStream->write($json);
        $bodyStream->rewind();

        $oauth2Request = MessageBridge::newOauth2Request($slimRequest);

        $this->assertSame(strlen($json), $oauth2Request->headers('Content_Length'));
        $this->assertSame('application/json', $oauth2Request->headers('Content_Type'));
        $this->assertSame('bar', $oauth2Request->request('foo'));
        $this->assertSame('123', $oauth2Request->request('abc'));
    }

    /**
     * Verify basic behavior of mapResponse()
     *
     * @test
     * @covers ::mapResponse
     *
     * @return void
     */
    public function mapResponse()
    {
        $oauth2Response = new \OAuth2\Response(
            ['foo' => 'bar', 'abc' => '123'],
            200,
            ['content-type' => 'application/json', 'fizz' => 'buzz']
        );
        $body = new \Slim\Http\RequestBody();
        $body->write('will be over written');
        $body->rewind();
        $slimResponse = new \Slim\Http\Response(500, null, $body);

        MessageBridge::mapResponse($oauth2Response, $slimResponse);

        $this->assertSame(200, $slimResponse->getStatusCode());
        $this->assertSame(
            ['content-type' => 'application/json', 'fizz' => 'buzz'],
            self::reduceHeaders($slimResponse->getHeaders())
        );

        $this->assertSame(json_encode(['foo' => 'bar', 'abc' => '123']), $slimResponse->getBody()->getContents());
    }

    /**
     * Verify behavior of newOAuth2Request() with application/json content type and empty body
     *
     * @test
     * @covers ::newOAuth2Request
     *
     * @return void
     */
    public function newOAuth2RequestJsonContentTypeEmptyBody()
    {
        $env = \Slim\Http\Environment::mock(
            [
                'REQUEST_METHOD' => 'POST',
                'slim.input' => '',
                'CONTENT_LENGTH' => 0,
                'CONTENT_TYPE' => 'application/json',
            ]
        );

        $slimRequest = \Slim\Http\Request::createFromEnvironment($env);

        $oauth2Request = MessageBridge::newOauth2Request($slimRequest);

        $this->assertSame(0, $oauth2Request->headers('Content_Length'));
        $this->assertSame('application/json', $oauth2Request->headers('Content_Type'));
    }

    /**
     * Verify behavior of replacing bad header key names
     *
     * @test
     * @covers ::newOAuth2Request
     *
     * @return void
     */
    public function newOAuth2RequestHeaderKeyNames()
    {
        $env = \Slim\Http\Environment::mock(
            [
                'REQUEST_METHOD' => 'POST',
                'QUERY_STRING' => 'one=1&two=2&three=3',
                'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
                'CONTENT_LENGTH' => 15,
                'PHP_AUTH_USER' => 'test_client_id',
                'PHP_AUTH_PW' => 'test_secret'
            ]
        );

        $slimRequest = \Slim\Http\Request::createFromEnvironment($env);
        $bodyStream = $slimRequest->getBody();
        $bodyStream->write('foo=bar&abc=123');
        $bodyStream->rewind();
        $prop = new ReflectionProperty($slimRequest, 'bodyParsed');
        $prop->setAccessible(true);
        $prop->setValue($slimRequest, false);

        $oauth2Request = MessageBridge::newOauth2Request($slimRequest);

        $this->assertSame(15, $oauth2Request->headers('Content_Length'));
        $this->assertSame('application/x-www-form-urlencoded', $oauth2Request->headers('Content_Type'));
        $this->assertSame('123', $oauth2Request->request('abc'));
        $this->assertSame('2', $oauth2Request->query('two'));
        $this->assertSame('test_client_id', $oauth2Request->headers('PHP_AUTH_USER'));
        $this->assertSame('test_secret', $oauth2Request->headers('PHP_AUTH_PW'));
        $this->assertNull($oauth2Request->headers('Php-Auth-User'));
        $this->assertNull($oauth2Request->headers('Php-Auth-Pw'));
    }

    /**
     * reduce Slim Headers depth. Each array element will be reduce to a none array representation.
     * If element is an array with size 1 element will replace with the value of the first element e.g.:
     * $HEADER['KEY']=[123]; => $HEADER['KEY']=123;
     * If element is an array with more than one value, element will be replace with ',' imploded string e.g.:
     * $HEADER['KEY']=['1','2']; => $HEADER['KEY']='1,2';
     * @param $slimHeaders
     * @return mixed
     */
    private static function reduceHeaders($slimHeaders)
    {
        foreach ($slimHeaders as $key => $value) {
            $slimHeaders[$key] = !is_array($value) ? $value : (count($value) == 1 ? $value[0] : implode(',', $value));
        }
        return $slimHeaders;
    }

}
