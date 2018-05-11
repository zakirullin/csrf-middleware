<?php

namespace Tests;

use Middlewares\Utils\Dispatcher;
use Middlewares\Utils\Factory;
use Middlewares\Utils\Factory\ServerRequestFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

class CSRFTest extends TestCase
{
    const ATTRIBUTE = 'custom-attribute';

    public function testAttribute()
    {
        $csrfMiddleware = new \Zakirullin\Middlewares\CSRF(
            function () {
                return true;
            },
            function () {
                return ['identity'];
            },
            'secret',
            static::ATTRIBUTE
        );
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

    public function testMissingToken()
    {
        $request = Factory::createServerRequest([], 'POST');

        $csrfMiddleware = new \Zakirullin\Middlewares\CSRF(
            function () {
                return true;
            },
            function () {
                return ['identity'];
            },
            'secret',
            static::ATTRIBUTE
        );
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
        $this->assertContains($response->getBody()->getContents(), 'invalid');
    }
}
