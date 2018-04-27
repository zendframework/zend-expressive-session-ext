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
use function gmdate;
use function session_id;
use function session_name;
use function session_start;
use function session_status;
use function time;

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

    /**
     * @return ServerRequestInterface
     */
    private function createSessionCookieRequest(string $sessionName = null, $sessionId = null, array $serverParams = [])
    {
        return FigRequestCookies::set(
            new ServerRequest($serverParams),
            Cookie::create(
                $sessionName ?: session_name(),
                $sessionId ?: 'testing'
            )
        );
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
     * If Session COOKIE is present, persistSession() method must return Response with Set-Cookie header
     */
    public function testPersistSessionReturnsResponseWithSetCookieHeaderIfSessionCookiePresent()
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
        $this->assertNotSame($response, $returnedResponse);

        $setCookie = FigResponseCookies::get($returnedResponse, session_name());
        $this->assertInstanceOf(SetCookie::class, $setCookie);
        $this->assertSame(session_id(), $setCookie->getValue());
        $this->assertSame(ini_get('session.cookie_path'), $setCookie->getPath());
    }

    /**
     * If Session COOKIE is not present, persistSession() method must return the original Response
     */
    public function testPersistSessionReturnsOriginalResponseIfNoSessionCookiePresent()
    {
        $this->startSession();
        $session = new Session([]);
        $response = new Response();

        $returnedResponse = $this->persistence->persistSession($session, $response);
        $this->assertSame($response, $returnedResponse);
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
        $ini = ini_get('session.cache_limiter');
        ini_set('session.cache_limiter', 'nocache');

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $response = $persistence->persistSession($session, new Response());

        $this->assertSame($response->getHeaderLine('Expires'), PhpSessionPersistence::CACHE_PAST_DATE);
        $this->assertSame($response->getHeaderLine('Cache-Control'), 'no-store, no-cache, must-revalidate');
        $this->assertSame($response->getHeaderLine('Pragma'), 'no-cache');

        ini_set('session.cache_limiter', $ini);
    }

    public function testPersistSessionReturnsExpectedResponseWithCacheHeadersIfCacheLimiterIsPublic()
    {
        $expire = 111;
        $maxAge = 60 * $expire;

        $ini_limiter = ini_get('session.cache_limiter');
        $ini_expire  = ini_get('session.cache_expire');
        ini_set('session.cache_limiter', 'public');
        ini_set('session.cache_expire', $expire);

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);

        $expiresMin = time() + $maxAge;
        $response = $persistence->persistSession($session, new Response());
        $expiresMax = time() + $maxAge;

        $control = sprintf('public, max-age=%d', $maxAge);
        $expires = $response->getHeaderLine('Expires');
        $expires = strtotime($expires);

        $this->assertGreaterThanOrEqual($expires, $expiresMin);
        $this->assertLessThanOrEqual($expires, $expiresMax);
        $this->assertSame($response->getHeaderLine('Cache-Control'), $control);

        ini_set('session.cache_limiter', $ini_limiter);
        ini_set('session.cache_expire', $ini_expire);
    }

    public function testPersistSessionReturnsExpectedResponseWithCacheHeadersIfCacheLimiterIsPrivate()
    {
        $expire = 222;
        $maxAge = 60 * $expire;

        $ini_limiter = ini_get('session.cache_limiter');
        $ini_expire  = ini_get('session.cache_expire');
        ini_set('session.cache_limiter', 'private');
        ini_set('session.cache_expire', $expire);

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $response = $persistence->persistSession($session, new Response());

        $expires = PhpSessionPersistence::CACHE_PAST_DATE;
        $control = sprintf('private, max-age=%d', $maxAge);

        $this->assertSame($response->getHeaderLine('Expires'), $expires);
        $this->assertSame($response->getHeaderLine('Cache-Control'), $control);

        ini_set('session.cache_limiter', $ini_limiter);
        ini_set('session.cache_expire', $ini_expire);
    }

    public function testPersistSessionReturnsExpectedResponseWithCacheHeadersIfCacheLimiterIsPrivateNoExpire()
    {
        $expire = 333;
        $maxAge = 60 * $expire;

        $ini_limiter = ini_get('session.cache_limiter');
        $ini_expire  = ini_get('session.cache_expire');
        ini_set('session.cache_limiter', 'private_no_expire');
        ini_set('session.cache_expire', $expire);

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $response = $persistence->persistSession($session, new Response());

        $control = sprintf('private, max-age=%d', $maxAge);

        $this->assertFalse($response->hasHeader('Expires'));
        $this->assertSame('', $response->getHeaderLine('Expires'));
        $this->assertSame($control, $response->getHeaderLine('Cache-Control'));

        ini_set('session.cache_limiter', $ini_limiter);
        ini_set('session.cache_expire', $ini_expire);
    }

    public function testPersistSessionReturnsExpectedResponseWithoutAddedHeadersIfAlreadyHasAny()
    {
        $ini = ini_get('session.cache_limiter');
        ini_set('session.cache_limiter', 'nocache');

        $response = new Response('php://memory', 200, [
            'Last-Modified' => gmdate(PhpSessionPersistence::HTTP_DATE_FORMAT),
        ]);

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $response = $persistence->persistSession($session, $response);

        $this->assertFalse($response->hasHeader('Pragma'));
        $this->assertFalse($response->hasHeader('Expires'));
        $this->assertFalse($response->hasHeader('Cache-Control'));

        ini_set('session.cache_limiter', $ini);
    }

    public function testPersistSessionInjectsExpectedLastModifiedHeaderIfScriptFilenameProvided()
    {
        // temporarily set session.cache_limiter to 'public'
        $ini = ini_get('session.cache_limiter');
        ini_set('session.cache_limiter', 'public');

        $persistence = new PhpSessionPersistence();

        // mocked request with script file set to current file
        $request  = $this->createSessionCookieRequest(null, null, ['SCRIPT_FILENAME' => __FILE__]);
        $session  = $persistence->initializeSessionFromRequest($request);
        $response = $persistence->persistSession($session, new Response());

        $lastModified = gmdate(PhpSessionPersistence::HTTP_DATE_FORMAT, filemtime(__FILE__));

        $this->assertSame($response->getHeaderLine('Last-Modified'), $lastModified);

        // restore original ini setting
        ini_set('session.cache_limiter', $ini);
    }

    public function testPersistSessionInjectsExpectedLastModifiedHeaderWithClassFileMtimeIfNoScriptFilenameProvided()
    {
        // temporarily set session.cache_limiter to 'public'
        $ini = ini_get('session.cache_limiter');
        ini_set('session.cache_limiter', 'public');

        $persistence = new PhpSessionPersistence();

        // mocked request without script file
        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $response = $persistence->persistSession($session, new Response());

        $reflection = new \ReflectionClass($persistence);
        $classFile  = $reflection->getFileName();

        $lastModified = gmdate(PhpSessionPersistence::HTTP_DATE_FORMAT, filemtime($classFile));

        $this->assertSame($response->getHeaderLine('Last-Modified'), $lastModified);

        // restore original ini setting
        ini_set('session.cache_limiter', $ini);
    }

    public function testPersistSessionDoesNotInjectLastModifiedHeaderIfUnableToDetermineFileMtime()
    {
        // temporarily set session.cache_limiter to 'public'
        $ini = ini_get('session.cache_limiter');
        ini_set('session.cache_limiter', 'public');

        $persistence = new PhpSessionPersistence();

        // mocked request with non-existing script file
        $request  = $this->createSessionCookieRequest(null, null, ['SCRIPT_FILENAME' => 'n0n3x15t3nt!']);
        $session  = $persistence->initializeSessionFromRequest($request);
        $response = $persistence->persistSession($session, new Response());

        $this->assertFalse($response->hasHeader('Last-Modified'));

        // restore original ini setting
        ini_set('session.cache_limiter', $ini);
    }

    public function testPersistSessionReturnsExpectedResponseWithoutAddedCacheHeadersIfEmptyCacheLimiter()
    {
        // temporarily set session.cache_limiter to ''
        $ini = ini_get('session.cache_limiter');
        ini_set('session.cache_limiter', '');

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $response = $persistence->persistSession($session, new Response());

        $this->assertFalse($response->hasHeader('Pragma'));
        $this->assertFalse($response->hasHeader('Expires'));
        $this->assertFalse($response->hasHeader('Cache-Control'));

        // restore original ini setting
        ini_set('session.cache_limiter', $ini);
    }

    public function testPersistSessionReturnsExpectedResponseWithoutAddedCacheHeadersIfUnsupportedCacheLimiter()
    {
        // temporarily set session.cache_limiter to 'unsupported'
        $ini = ini_get('session.cache_limiter');
        ini_set('session.cache_limiter', 'unsupported');

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $response = $persistence->persistSession($session, new Response());

        $this->assertFalse($response->hasHeader('Pragma'));
        $this->assertFalse($response->hasHeader('Expires'));
        $this->assertFalse($response->hasHeader('Cache-Control'));

        // restore original ini setting
        ini_set('session.cache_limiter', $ini);
    }
}
