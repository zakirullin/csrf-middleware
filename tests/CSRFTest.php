<?php
declare(strict_types=1);

namespace Tests;

use Middlewares\Utils\Dispatcher;
use Middlewares\Utils\Factory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zakirullin\Middlewares\CSRF;

class CSRFTest extends TestCase
{
    const ATTRIBUTE = 'custom-attribute';

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

    public function testNoProtection()
    {
        $request = Factory::createServerRequest([], 'POST');
        $request = $request->withAttribute('handler', 'LoginController');

        $csrfMiddleware = $this->getCSRFMiddleware(
            function (ServerRequestInterface $request) {
                return $request->getAttribute('handler', null) != 'LoginController';
            }
        );
        $assertMiddleware = function (ServerRequestInterface $request, RequestHandlerInterface $handler) {
            $this->assertNull($request->getAttribute(static::ATTRIBUTE));

            return $handler->handle($request);
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

        $this->assertEquals((string)$response->getBody(), 'success');
    }

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

    protected function getCSRFMiddleware(callable $getIdentity = null)
    {
        if ($getIdentity === null) {
            $getIdentity = function () {
                return true;
            };
        }

        $csrfMiddleware = new \Zakirullin\Middlewares\CSRF(
            $getIdentity,
            function () {
                return ['identity'];
            },
            'secret',
            static::ATTRIBUTE
        );

        return $csrfMiddleware;
    }

}
