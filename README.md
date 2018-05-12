# zakirullin/csrf-middleware

[![Build Status](https://travis-ci.org/zakirullin/csrf-middleware.svg)](https://travis-ci.org/zakirullin/csrf-middleware)
[![Packagist](https://img.shields.io/packagist/v/zakirullin/csrf-middleware.svg)](https://packagist.org/packages/zakirullin/csrf-middlware)
[![Total Downloads](https://img.shields.io/packagist/dt/zakirullin/csrf-middleware.svg)](https://packagist.org/packages/zakirullin/csrf-middleware)
![PHP from Packagist](https://img.shields.io/packagist/php-v/zakirullin/csrf-middleware.svg)
![GitHub commits](https://img.shields.io/github/commits-since/zakirullin/csrf-middleware/0.1.0.svg)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)

PSR-15 middleware to handle CSRF-token verification

## Requirements

* PHP >= 7.0
* A [PSR-7](https://packagist.org/providers/psr/http-message-implementation) http message implementation ([Diactoros](https://github.com/zendframework/zend-diactoros), [Guzzle](https://github.com/guzzle/psr7), [Slim](https://github.com/slimphp/Slim), etc...)
* A [PSR-15 middleware dispatcher](https://github.com/middlewares/awesome-psr15-middlewares#dispatcher)

## Installation

This package is installable and autoloadable via Composer as [zakirullin/csrf-middleware](https://packagist.org/packages/zakirullin/csrf-middleware).

```sh
composer require zakirullin/csrf-middleware 
```

## Example

```php

<?php
return [
    \Zakirullin\Middlewares\CSRF::class => function (\App\Interfaces\ConfigInterface $config) {
        $shouldProtect = function (\Psr\Http\Message\ServerRequestInterface $request) {
            $handler = $request->getAttribute(\App\Entities\RequestAttribute::HANDLER);
            list($controller,) = $handler;
            return in_array(
                $controller,
                [
                    \App\Controllers\Admin\VideoController::class,
                    \App\Controllers\Admin\UserController::class
                ]
            );
        };
        $getIdentity = function (\Psr\Http\Message\ServerRequestInterface $request) {
            $session = $request->getAttribute(\App\Entities\RequestAttribute::SESSION);
            if ($session instanceof \PSR7Sessions\Storageless\Session\SessionInterface) {
                $userId = (int)$session->get(\App\Entities\Session::AUTH, 0);
                if ($userId > 0) {
                    $handler = $request->getAttribute(\App\Entities\RequestAttribute::HANDLER);
                    list($controller, $action) = $handler;
                    return [$userId, $controller, $action];
                }
            }
            return false;
        };
        return new \App\Middlewares\CSRF(
            $shouldProtect, $getIdentity, $config->get('csrf.secret'), \App\Entities\RequestAttribute::CSRF
        );
    }
];
```

## Options

```php 
__construct(
    callable $shouldProtect,
    callable $getIdentity,
    string $secret,
    string $attribute = self::ATTRIBUTE,
    int $ttl = self::TTL,
    string $algorithm = self::ALGORITHM
)
```

#### `name(string $name)`

The session name. If it's not defined, the default `PHPSESSID` will be used.

#### `attribute(string $attribute)`

The attribute name used to store the session in the server request. By default is `session`.

---

Please see [CHANGELOG](CHANGELOG.md) for more information about recent changes and [CONTRIBUTING](CONTRIBUTING.md) for contributing details.

The MIT License (MIT). Please see [LICENSE](LICENSE) for more information.
