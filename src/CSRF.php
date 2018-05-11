<?php

namespace Zakirullin\Middlewares;

use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Middlewares\Utils\Factory;

class CSRF implements MiddlewareInterface
{
    /**
     * @var callable
     */
    protected $shouldProtect;

    /**
     * @var callable
     */
    protected $getIdentity;

    /**
     * @var string
     */
    protected $secret;

    /**
     * @var string
     */
    protected $attribute;

    /**
     * @var int
     */
    protected $ttl;

    /**
     * @var string
     */
    protected $algorithm;

    protected const METHODS = ['POST'];
    protected const STATUS_ON_ERROR = 403;
    protected const CERTIFICATE_SEPARATOR = ':';
    protected const TTL = 60 * 20;
    protected const ALGORITHM = 'ripemd160';

    /**
     * @param callable $shouldProtect
     * @param callable $getIdentity
     * @param string $secret
     * @param string $attribute
     * @param int $ttl
     * @param string $algorithm
     */
    public function __construct(
        callable $shouldProtect,
        callable $getIdentity,
        string $secret,
        string $attribute,
        int $ttl = self::TTL,
        string $algorithm = self::ALGORITHM
    ) {
        $this->shouldProtect = $shouldProtect;
        $this->getIdentity = $getIdentity;
        $this->secret = $secret;
        $this->attribute = $attribute;
        $this->ttl = $ttl;
        $this->algorithm = $algorithm;
    }

    /**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $shouldProtect = call_user_func($this->shouldProtect, $request);
        if ($shouldProtect) {
            $shouldProtectMethod = in_array($request->getMethod(), static::METHODS);
            if ($shouldProtectMethod) {
                if (!$this->verify($request)) {
                    $response = Factory::createResponse(static::STATUS_ON_ERROR);
                    $response->getBody()->write('Invalid or missing CSRF token!');

                    return $response;
                }
            }

            $request = $this->add($request);
        }

        return $handler->handle($request);
    }

    /**
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface $request
     */
    protected function add(ServerRequestInterface $request): ServerRequestInterface
    {
        $identity = call_user_func($this->getIdentity, $request);
        if (is_array($identity)) {
            $expireAt = time() + $this->ttl;
            $certificate = $this->createCertificate($identity, $expireAt);
            $signature = hash_hmac($this->algorithm, $certificate, $this->secret);

            $request = $request->withAttribute($this->attribute, $expireAt . static::CERTIFICATE_SEPARATOR . $signature);
        }

        return $request;
    }

    /**
     * @param ServerRequestInterface $request
     * @return bool
     */
    protected function verify(ServerRequestInterface $request): bool
    {
        $token = $request->getParsedBody()[$this->attribute] ?? null;
        $parts = explode(static::CERTIFICATE_SEPARATOR, $token);
        if (count($parts) > 1) {
            list($expireAt, $signature) = explode(static::CERTIFICATE_SEPARATOR, $token);
            $identity = call_user_func($this->getIdentity, $request);
            $certificate = $this->createCertificate($identity, $expireAt);

            $actualSignature = hash_hmac($this->algorithm, $certificate, $this->secret);
            $isSignatureValid = hash_equals($actualSignature, $signature);
            $isNotExpired = $expireAt > time();
            if ($isSignatureValid && $isNotExpired) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array $identity
     * @param int $expireAt
     * @return string
     */
    protected function createCertificate(array $identity, int $expireAt): string
    {
        $identity[] = $expireAt;

        return implode(static::CERTIFICATE_SEPARATOR, $identity);
    }
}
