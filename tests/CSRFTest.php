<?php
declare(strict_types=1);

namespace Tests;

use Middlewares\Utils\Dispatcher;
use Middlewares\Utils\Factory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class CSRFTest extends TestCase
{
    const ATTRIBUTE = 'custom-attribute';

    /**
     * @covers \Zakirullin\Middlewares\CSRF
     */
    public function testAttribute()
    {
        $csrfMiddleware = $this->getCSRFMiddleware();
        $assertMiddleware = function (ServerRequestInterface $request) {
            $this->assertTrue($request->getAttribute(static::ATTRIBUTE) !== null);
        };

        Dispatcher::run(
            [
                $csrfMiddleware,
                $assertMiddleware
            ]
        );
    }

    /**
     * @covers \Zakirullin\Middlewares\CSRF
     */
    public function testNonWrite()
    {
        $csrfMiddleware = $this->getCSRFMiddleware();
        $appMiddleware = function (ServerRequestInterface $request) {
            $response = Factory::createResponse(200);
            $response->getBody()->write('success');

            return $response;
        };

        $response = Dispatcher::run(
            [
                $csrfMiddleware,
                $appMiddleware
            ]
        );

        $this->assertEquals('success', (string)$response->getBody());
    }

    /**
     * @covers \Zakirullin\Middlewares\CSRF
     */
    public function testMissingToken()
    {
        $request = Factory::createServerRequest([], 'POST');

        $csrfMiddleware = $this->getCSRFMiddleware();
        $assertMiddleware = function (ServerRequestInterface $request) {
            $this->assertTrue(false);
        };

        $response = Dispatcher::run(
            [
                $csrfMiddleware,
                $assertMiddleware
            ],
            $request
        );

        $this->assertEquals($response->getStatusCode(), 403);
        $this->assertContains('Invalid', (string)$response->getBody());
    }

    /**
     * @covers \Zakirullin\Middlewares\CSRF
     */
    public function testInvalidToken()
    {
        $request = Factory::createServerRequest([], 'POST');
        $request = $request->withParsedBody(['csrf' => 'invalid']);

        $csrfMiddleware = $this->getCSRFMiddleware();
        $assertMiddleware = function (ServerRequestInterface $request) {
            $this->assertTrue(false);
        };

        $response = Dispatcher::run(
            [
                $csrfMiddleware,
                $assertMiddleware
            ],
            $request
        );

        $this->assertEquals($response->getStatusCode(), 403);
        $this->assertContains('Invalid', (string)$response->getBody());
    }

    /**
     * @covers \Zakirullin\Middlewares\CSRF
     */
    public function testExpiredToken()
    {
        $request = Factory::createServerRequest([], 'POST');
        $token = implode(':', [0, '0d163df2868bcc2dd15e1a7ae72528ed130354d3']);
        $request = $request->withParsedBody([static::ATTRIBUTE => $token]);

        $csrfMiddleware = $this->getCSRFMiddleware();
        $assertMiddleware = function (ServerRequestInterface $request) {
            $this->assertTrue(false);
        };

        $response = Dispatcher::run(
            [
                $csrfMiddleware,
                $assertMiddleware
            ],
            $request
        );

        $this->assertEquals($response->getStatusCode(), 403);
        $this->assertContains($response->getBody()->getContents(), 'Invalid');
    }

    /**
     * @covers \Zakirullin\Middlewares\CSRF
     */
    public function testValidToken()
    {
        $request = Factory::createServerRequest([], 'POST');
        $token = implode(':', [PHP_INT_MAX, 'e14a5ae5132d4e4b489d74698144104055c25f4c']);
        $request = $request->withParsedBody([static::ATTRIBUTE => $token]);

        $csrfMiddleware = $this->getCSRFMiddleware();
        $assertMiddleware = function (ServerRequestInterface $request) {
            $this->assertTrue(true);
        };
        $appMiddleware = function (ServerRequestInterface $request, RequestHandlerInterface $handler) {
            $response = Factory::createResponse();
            $response->getBody()->write('success');

            return $response;
        };

        $response = Dispatcher::run(
            [
                $csrfMiddleware,
                $assertMiddleware,
                $appMiddleware
            ],
            $request
        );

        $this->assertEquals($response->getStatusCode(), 200);
        $this->assertContains((string)$response->getBody(), 'success');
    }

    protected function getCSRFMiddleware()
    {
        $csrfMiddleware = new \Zakirullin\Middlewares\CSRF(
            'identity',
            'secret',
            static::ATTRIBUTE
        );

        return $csrfMiddleware;
    }
}
