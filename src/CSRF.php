<?php
declare(strict_types = 1);

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
    protected $getIdentityCallback;

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

    protected const READ_METHODS = ['HEAD', 'GET', 'OPTIONS'];
    protected const STATUS_ON_ERROR = 403;
    protected const CERTIFICATE_SEPARATOR = ':';
    protected const ATTRIBUTE = 'csrf';
    protected const TTL = 60 * 20;
    protected const ALGORITHM = 'ripemd160';

    /**
     * @param callable $getIdentityCallback
     * @param string $secret
     * @param string $attribute
     * @param int $ttl
     * @param string $algorithm
     */
    public function __construct(
        callable $getIdentityCallback,
        string $secret,
        string $attribute = self::ATTRIBUTE,
        int $ttl = self::TTL,
        string $algorithm = self::ALGORITHM
    ) {
        $this->getIdentityCallback = $getIdentityCallback;
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
        $isWriteMethod = !in_array($request->getMethod(), static::READ_METHODS);
        if ($isWriteMethod && !$this->isValid($request)) {
            $response = Factory::createResponse(static::STATUS_ON_ERROR);
            $response->getBody()->write('Invalid or missing CSRF token!');

            return $response;
        }

        $request = $this->add($request);

        return $handler->handle($request);
    }

    /**
     * @param ServerRequestInterface $request
     * @return ServerRequestInterface $request
     */
    protected function add(ServerRequestInterface $request): ServerRequestInterface
    {
        $identity = call_user_func($this->getIdentityCallback, $request);
        if (!empty($identity)) {
            $expireAt = time() + $this->ttl;
            $certificate = $this->createCertificate($identity, $expireAt);
            $signature = $this->signCertificate($certificate);
            $signatureWithExpiration = implode(static::CERTIFICATE_SEPARATOR, [$expireAt, $signature]);

            $request = $request->withAttribute($this->attribute, $signatureWithExpiration);
        }

        return $request;
    }

    /**
     * @param ServerRequestInterface $request
     * @return bool
     */
    protected function isValid(ServerRequestInterface $request): bool
    {
        $token = trim($request->getParsedBody()[$this->attribute] ?? '');
        $parts = explode(static::CERTIFICATE_SEPARATOR, $token);
        if (count($parts) > 1) {
            list($expireAt, $signature) = explode(static::CERTIFICATE_SEPARATOR, $token);
            $identity = call_user_func($this->getIdentityCallback, $request);
            $certificate = $this->createCertificate($identity, (int)$expireAt);
            $actualSignature = $this->signCertificate($certificate);
            $isSignatureValid = hash_equals($actualSignature, $signature);
            $isNotExpired = $expireAt > time();
            if ($isSignatureValid && $isNotExpired) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $identity
     * @param int $expireAt
     * @return string
     */
    protected function createCertificate(string $identity, int $expireAt): string
    {
        return implode(static::CERTIFICATE_SEPARATOR, [$identity, $expireAt]);
    }

    /**
     * @param string $certificate
     * @return string
     */
    protected function signCertificate(string $certificate)
    {
        return hash_hmac($this->algorithm, $certificate, $this->secret);
    }
}
