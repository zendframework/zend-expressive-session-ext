<?php
/**
 * @see       https://github.com/zendframework/zend-expressive-session-ext for the canonical source repository
 * @copyright Copyright (c) 2017 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   https://github.com/zendframework/zend-expressive-session-ext/blob/master/LICENSE.md New BSD License
 */

namespace ZendTest\Expressive\Session\Ext;

use Dflydev\FigCookies\Cookie;
use Dflydev\FigCookies\FigRequestCookies;
use Dflydev\FigCookies\FigResponseCookies;
use Dflydev\FigCookies\SetCookie;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;
use Zend\Expressive\Session\Ext\PhpSessionPersistence;
use Zend\Expressive\Session\Session;

use function ini_get;
use function session_id;
use function session_name;
use function session_start;
use function session_status;
use function time;
use function gmdate;

use const PHP_SESSION_ACTIVE;
use const PHP_SESSION_NONE;

/**
 * @runTestsInSeparateProcesses
 */
class PhpSessionPersistenceTest extends TestCase
{
    /**
     * @var PhpSessionPersistence
     */
    private $persistence;

    public function setUp()
    {
        $this->persistence = new PhpSessionPersistence();
    }

    public function startSession(string $id = null, array $options = [])
    {
        $id = $id ?: 'testing';
        session_id($id);
        session_start([
            'use_cookies'      => false,
            'use_only_cookies' => true,
        ] + $options);
    }

    public function testInitializeSessionFromRequestInitializesSessionWithGeneratedIdentifierIfNoSessionCookiePresent()
    {
        $this->assertSame(PHP_SESSION_NONE, session_status());

        $request = new ServerRequest();
        $session = $this->persistence->initializeSessionFromRequest($request);

        $this->assertSame(PHP_SESSION_ACTIVE, session_status());
        $this->assertInstanceOf(Session::class, $session);
        $this->assertSame($_SESSION, $session->toArray());
        $id = session_id();
        $this->assertRegExp('/^[a-f0-9]{32}$/i', $id);
    }

    public function testInitializeSessionFromRequestUsesSessionCookieFromRequest()
    {
        $this->assertSame(PHP_SESSION_NONE, session_status());
        $sessionName = session_name();

        /** @var ServerRequestInterface $request */
        $request = FigRequestCookies::set(
            new ServerRequest(),
            Cookie::create($sessionName, 'use-this-id')
        );

        $session = $this->persistence->initializeSessionFromRequest($request);

        $this->assertSame(PHP_SESSION_ACTIVE, session_status());
        $this->assertInstanceOf(Session::class, $session);
        $this->assertSame($_SESSION, $session->toArray());
        $id = session_id();
        $this->assertSame('use-this-id', $id);
    }

    public function testPersistSessionGeneratesCookieWithNewSessionIdIfSessionWasRegenerated()
    {
        $sessionName = 'regenerated-session';
        session_name($sessionName);
        /** @var ServerRequestInterface $request */
        $request = FigRequestCookies::set(
            new ServerRequest(),
            Cookie::create($sessionName, 'use-this-id')
        );

        // first request of original session cookie
        $session = $this->persistence->initializeSessionFromRequest($request);
        $response = new Response();
        $this->persistence->persistSession($session, $response);

        $session = $session->regenerate();

        // emulate second request that would usually occur once session has been regenerated
        $returnedResponse = $this->persistence->persistSession($session, $response);
        $this->assertNotSame($response, $returnedResponse);

        $setCookie = FigResponseCookies::get($returnedResponse, session_name());
        $this->assertInstanceOf(SetCookie::class, $setCookie);
        $this->assertNotSame('original-id', $setCookie->getValue());
        $this->assertSame(session_id(), $setCookie->getValue());

        $this->assertSame($session->toArray(), $_SESSION);
    }

    /**
     * If Session COOKIE is present, persistSession() method must return the original Response
     */
    public function testPersistSessionReturnsOriginalResposneIfSessionCookiePresent()
    {
        $sessionName = session_name();

        /** @var ServerRequestInterface $request */
        $request = FigRequestCookies::set(
            new ServerRequest(),
            Cookie::create($sessionName, 'use-this-id')
        );

        $session = $this->persistence->initializeSessionFromRequest($request);
        $response = new Response();
        $returnedResponse = $this->persistence->persistSession($session, $response);
        $this->assertSame($response, $returnedResponse);
    }

    /**
     * If Session COOKIE is not present, persistSession() method must return Response with Set-Cookie header
     */
    public function testPersistSessionReturnsResponseWithSetCookieHeaderIfNoSessionCookiePresent()
    {
        $this->startSession();
        $session = new Session([]);
        $response = new Response();

        $returnedResponse = $this->persistence->persistSession($session, $response);
        $this->assertNotSame($response, $returnedResponse);

        $setCookie = FigResponseCookies::get($returnedResponse, session_name());
        $this->assertInstanceOf(SetCookie::class, $setCookie);
        $this->assertSame(session_id(), $setCookie->getValue());
        $this->assertSame(ini_get('session.cookie_path'), $setCookie->getPath());
    }

    public function testPersistSessionIfSessionHasContents()
    {
        $this->startSession();
        $session = new Session(['foo' => 'bar']);
        $this->persistence->persistSession($session, new Response);
        $this->assertSame($session->toArray(), $_SESSION);
    }

    public function testPersistSessionReturnsExpectedResponseWithCacheHeadersIfCacheLimiterIsNocache()
    {
        $this->startSession(null, [
            'cache_limiter' => 'nocache',
        ]);

        $persistence = new PhpSessionPersistence();

        $session  = new Session(['foo' => 'bar']);
        $response = $persistence->persistSession($session, new Response());

        $this->assertSame($response->getHeaderLine('Expires'), PhpSessionPersistence::CACHE_PAST_DATE);
        $this->assertSame($response->getHeaderLine('Cache-Control'), 'no-store, no-cache, must-revalidate');
        $this->assertSame($response->getHeaderLine('Pragma'), 'no-cache');
    }

    public function testPersistSessionReturnsExpectedResponseWithCacheHeadersIfCacheLimiterIsPublic()
    {
        $expire = 111;
        $maxAge = 60 * $expire;

        $this->startSession(null, [
            'cache_limiter' => 'public',
            'cache_expire'  => $expire,
        ]);

        $persistence = new PhpSessionPersistence();

        $session  = new Session(['foo' => 'bar']);

        $expiresMin = time() + $maxAge;
        $response = $persistence->persistSession($session, new Response());
        $expiresMax = time() + $maxAge;

        $control = sprintf('public, max-age=%d', $maxAge);
        $expires = $response->getHeaderLine('Expires');
        $expires = strtotime($expires);

        $this->assertTrue($expires >= $expiresMin);
        $this->assertTrue($expires <= $expiresMax);
        $this->assertSame($response->getHeaderLine('Cache-Control'), $control);
    }

    public function testPersistSessionReturnsExpectedResponseWithCacheHeadersIfCacheLimiterIsPrivate()
    {
        $expire = 222;
        $maxAge = 60 * $expire;

        $this->startSession(null, [
            'cache_limiter' => 'private',
            'cache_expire'  => $expire,
        ]);

        $persistence = new PhpSessionPersistence();

        $session  = new Session(['foo' => 'bar']);
        $response = $persistence->persistSession($session, new Response());

        $expires = PhpSessionPersistence::CACHE_PAST_DATE;
        $control = sprintf('private, max-age=%d', $maxAge);

        $this->assertSame($response->getHeaderLine('Expires'), $expires);
        $this->assertSame($response->getHeaderLine('Cache-Control'), $control);
    }

    public function testPersistSessionReturnsExpectedResponseWithCacheHeadersIfCacheLimiterIsPrivateNoExpire()
    {
        $expire = 333;
        $maxAge = 60 * $expire;

        $this->startSession(null, [
            'cache_limiter' => 'private_no_expire',
            'cache_expire'  => $expire,
        ]);

        $persistence = new PhpSessionPersistence();

        $session  = new Session(['foo' => 'bar']);
        $response = $persistence->persistSession($session, new Response());

        $control = sprintf('private, max-age=%d', $maxAge);

        $this->assertSame($response->getHeaderLine('Expires'), '');
        $this->assertSame($response->getHeaderLine('Cache-Control'), $control);
    }

    public function testPersistSessionReturnsExpectedResponseWithoutAddedHeadersIfAlreadyHasAny()
    {
        $this->startSession(null, [
            'cache_limiter' => 'nocache',
        ]);

        $persistence = new PhpSessionPersistence();

        $response = new Response('php://memory', 200, [
            'Last-Modified' => gmdate(PhpSessionPersistence::HTTP_DATE_FORMAT),
        ]);

        $session  = new Session(['foo' => 'bar']);
        $response = $persistence->persistSession($session, $response);

        $this->assertSame($response->getHeaderLine('Pragma'), '');
        $this->assertSame($response->getHeaderLine('Expires'), '');
        $this->assertSame($response->getHeaderLine('Cache-Control'), '');
    }

    public function testPersistSessionReturnsExpectedResponseWithoutAddedCacheHeadersIfEmptyCacheLimiter()
    {
        $this->startSession(null, [
            'cache_limiter' => '',
        ]);

        $persistence = new PhpSessionPersistence();

        $session  = new Session(['foo' => 'bar']);
        $response = $persistence->persistSession($session, new Response());

        $this->assertSame($response->getHeaderLine('Pragma'), '');
        $this->assertSame($response->getHeaderLine('Expires'), '');
        $this->assertSame($response->getHeaderLine('Cache-Control'), '');
    }
}
