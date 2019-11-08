# zakirullin/csrf-middleware

[![Build Status](https://img.shields.io/travis/zakirullin/csrf-middleware.svg?style=flat-square)](https://travis-ci.org/zakirullin/csrf-middleware)
[![Scrutinizer](https://img.shields.io/scrutinizer/g/zakirullin/csrf-middleware.svg?style=flat-square)](https://scrutinizer-ci.com/g/zakirullin/csrf-middleware/)
![PHP from Packagist](https://img.shields.io/packagist/php-v/zakirullin/csrf-middleware.svg?style=flat-square)
![GitHub commits](https://img.shields.io/github/commits-since/zakirullin/csrf-middleware/0.1.0.svg?style=flat-square)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)

A PSR-15 middleware to automate CSRF-token verification process

## Requirements

* PHP >= 7.1
* A [PSR-7](https://packagist.org/providers/psr/http-message-implementation) http message implementation ([Diactoros](https://github.com/zendframework/zend-diactoros), [Guzzle](https://github.com/guzzle/psr7), [Slim](https://github.com/slimphp/Slim), etc...)
* A [PSR-15 middleware dispatcher](https://github.com/middlewares/awesome-psr15-middlewares#dispatcher)

## Installation

This package is installable and autoloadable via Composer as [zakirullin/csrf-middleware](https://packagist.org/packages/zakirullin/csrf-middleware).

```sh
composer require zakirullin/csrf-middleware 
```

## PHP

```php
$getIdentity = function (\Psr\Http\Message\ServerRequestInterface $request) {
    $session = $request->getAttribute('session');
    return $session->get('id');
};

$dispatcher = new Dispatcher([
    ...
    new \Zakirullin\Middlewares\CSRF($getIdentity, 'secret'),
    ...
]);
```

## HTML

```html
<form method="POST" action="/dangerous/action">
    ...
    <input type="hidden" name="csrf" value="<?= $request->getAttribute('csrf') ?>">
    ...
</form>
```

## Options

```php 
__construct(
    callable $getIdentity,
    string $secret,
    string $attribute = self::ATTRIBUTE,
    int $ttl = self::TTL,
    string $algorithm = self::ALGORITHM
)
```

#### `$getIdentity(ServerRequestInterface $request)`

A callback that should return a string containing some per-user unique identity. For example - `session id`.

---

The MIT License (MIT). Please see [LICENSE](LICENSE) for more information.
