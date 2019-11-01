<?php
/**
 * @see       https://github.com/zendframework/zend-expressive-session-ext for the canonical source repository
 * @copyright Copyright (c) 2017-2018 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   https://github.com/zendframework/zend-expressive-session-ext/blob/master/LICENSE.md New BSD License
 */

namespace ZendTest\Expressive\Session\Ext;

use Dflydev\FigCookies\Cookie;
use Dflydev\FigCookies\FigRequestCookies;
use Dflydev\FigCookies\FigResponseCookies;
use Dflydev\FigCookies\SetCookie;
use Dflydev\FigCookies\SetCookies;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClass;
use ReflectionMethod;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;
use Zend\Expressive\Session\Ext\PhpSessionPersistence;
use Zend\Expressive\Session\Session;
use Zend\Expressive\Session\SessionCookiePersistenceInterface;
use function filemtime;
use function getlastmod;
use function gmdate;
use function ini_get;
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

    /**
     * @var array
     */
    private $originalSessionSettings;

    /**
     * @var string
     */
    private $sessionSavePath;

    public function setUp()
    {
        $this->sessionSavePath = sys_get_temp_dir() . "/zend-expressive-session-ext";

        $this->originalSessionSettings = $this->applyCustomSessionOptions([
            'save_path' => $this->sessionSavePath,
        ]);

        // create a temp session save path
        if (! is_dir($this->sessionSavePath)) {
            mkdir($this->sessionSavePath);
        }

        $this->persistence = new PhpSessionPersistence();
    }

    public function tearDown()
    {
        session_write_close();
        $this->restoreOriginalSessionIniSettings($this->originalSessionSettings);

        // remove old session test files if any
        $files = glob("{$this->sessionSavePath}/sess_*");
        if ($files) {
            foreach ($files as $file) {
                unlink($file);
            }
        }
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
    private function createSessionCookieRequest($sessionId = null, string $sessionName = null, array $serverParams = [])
    {
        return FigRequestCookies::set(
            new ServerRequest($serverParams),
            Cookie::create(
                $sessionName ?: session_name(),
                $sessionId ?: 'testing'
            )
        );
    }

    /**
     * @param array $options Custom session options (without the "session" namespace)
     * @return array Return the original (and overwritten) namespaced ini settings
     */
    private function applyCustomSessionOptions(array $options)
    {
        $ini = [];
        foreach ($options as $key => $value) {
            $ini_key = "session.{$key}";
            $ini[$ini_key] = ini_get($ini_key);
            ini_set($ini_key, strval(is_bool($value) ? intval($value) : $value));
        }

        return $ini;
    }

    /**
     * @param array $ini The original session namespaced ini settings
     */
    private function restoreOriginalSessionIniSettings(array $ini)
    {
        foreach ($ini as $key => $value) {
            ini_set($key, $value);
        }
    }

    private function assertPersistedSessionsCount(int $expectedCount): void
    {
        $files = glob("{$this->sessionSavePath}/sess_*");
        $this->assertCount($expectedCount, $files);
    }

    public function testInitializeSessionFromRequestDoesNotStartPhpSessionIfNoSessionCookiePresent()
    {
        $this->assertSame(PHP_SESSION_NONE, session_status());

        $request = new ServerRequest();
        $session = $this->persistence->initializeSessionFromRequest($request);

        $this->assertSame(PHP_SESSION_NONE, session_status());
        $this->assertSame('', session_id());
        $this->assertInstanceOf(Session::class, $session);
        $this->assertFalse(isset($_SESSION));
    }

    public function testInitializeSessionFromRequestUsesSessionCookieFromRequest()
    {
        $this->assertSame(PHP_SESSION_NONE, session_status());

        $request = $this->createSessionCookieRequest('use-this-id');
        $session = $this->persistence->initializeSessionFromRequest($request);

        $this->assertSame(PHP_SESSION_ACTIVE, session_status());
        $this->assertInstanceOf(Session::class, $session);
        $this->assertSame($_SESSION, $session->toArray());
        $this->assertSame('use-this-id', session_id());
    }

    public function testPersistSessionStartsPhpSessionEvenIfNoSessionCookiePresentButSessionChanged()
    {
        // request without session-cookie
        $request = new ServerRequest();

        // first request of original session cookie
        $session = $this->persistence->initializeSessionFromRequest($request);

        // no php session here
        $this->assertSame(PHP_SESSION_NONE, session_status());
        $this->assertFalse(isset($_SESSION));

        // alter session
        $session->set('foo', 'bar');

        $response = new Response();
        $returnedResponse = $this->persistence->persistSession($session, $response);

        // check that php-session was started and $session data persisted into it
        $this->assertTrue(isset($_SESSION));
        $this->assertRegExp('/^[a-f0-9]{32}$/i', session_id());
        $this->assertSame($session->toArray(), $_SESSION);

        // check the returned response
        $this->assertNotSame($response, $returnedResponse);
        $setCookie = FigResponseCookies::get($returnedResponse, session_name());
        $this->assertInstanceOf(SetCookie::class, $setCookie);
        $this->assertNotEquals('', $setCookie->getValue());
        $this->assertSame(session_id(), $setCookie->getValue());
    }

    public function testPersistSessionGeneratesCookieWithNewSessionIdIfSessionWasRegenerated()
    {
        $sessionName = 'regenerated-session';
        session_name($sessionName);

        $request = $this->createSessionCookieRequest('original-id', $sessionName);

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
        $request = $this->createSessionCookieRequest('use-this-id');
        $session = $this->persistence->initializeSessionFromRequest($request);
        $session->set('foo', __METHOD__);

        $response = new Response();
        $returnedResponse = $this->persistence->persistSession($session, $response);
        $this->assertNotSame($response, $returnedResponse);

        $setCookie = FigResponseCookies::get($returnedResponse, session_name());
        $this->assertInstanceOf(SetCookie::class, $setCookie);
        $this->assertSame(session_id(), $setCookie->getValue());
        $this->assertSame(ini_get('session.cookie_path'), $setCookie->getPath());

        // @see https://github.com/zendframework/zend-expressive-session-ext/pull/31
        $this->assertSame(ini_get('session.cookie_domain') ?: null, $setCookie->getDomain());
        $this->assertSame((bool) ini_get('session.cookie_secure'), $setCookie->getSecure());
        $this->assertSame((bool) ini_get('session.cookie_httponly'), $setCookie->getHttpOnly());
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
        $this->persistence->persistSession($session, new Response());
        $this->assertSame($session->toArray(), $_SESSION);
    }

    public function testPersistSessionReturnsExpectedResponseWithCacheHeadersIfCacheLimiterIsNocache()
    {
        $ini = $this->applyCustomSessionOptions([
            'cache_limiter' => 'nocache',
        ]);

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $session->set('foo', __METHOD__);

        $response = $persistence->persistSession($session, new Response());

        // expected values
        $expires = PhpSessionPersistence::CACHE_PAST_DATE;
        $control = 'no-store, no-cache, must-revalidate';
        $pragma  = 'no-cache';

        $this->assertSame($expires, $response->getHeaderLine('Expires'));
        $this->assertSame($control, $response->getHeaderLine('Cache-Control'));
        $this->assertSame($pragma, $response->getHeaderLine('Pragma'));

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testPersistSessionReturnsExpectedResponseWithCacheHeadersIfCacheLimiterIsPublic()
    {
        $expire = 111;
        $maxAge = 60 * $expire;

        $ini = $this->applyCustomSessionOptions([
            'cache_limiter' => 'public',
            'cache_expire'  => $expire,
        ]);

        $persistence = new PhpSessionPersistence();

        $request = $this->createSessionCookieRequest();
        $session = $persistence->initializeSessionFromRequest($request);
        $session->set('foo', __METHOD__);

        // expected expire min timestamp value
        $expiresMin = time() + $maxAge;
        $response   = $persistence->persistSession($session, new Response());
        // expected expire max timestamp value
        $expiresMax = time() + $maxAge;

        // expected cache-control value
        $control = sprintf('public, max-age=%d', $maxAge);
        // actual expire timestamp value
        $expires = $response->getHeaderLine('Expires');
        $expires = strtotime($expires);

        $this->assertGreaterThanOrEqual($expiresMin, $expires);
        $this->assertLessThanOrEqual($expiresMax, $expires);
        $this->assertSame($control, $response->getHeaderLine('Cache-Control'));

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testPersistSessionReturnsExpectedResponseWithCacheHeadersIfCacheLimiterIsPrivate()
    {
        $expire = 222;
        $maxAge = 60 * $expire;

        $ini = $this->applyCustomSessionOptions([
            'cache_limiter' => 'private',
            'cache_expire'  => $expire,
        ]);

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $session->set('foo', __METHOD__);

        $response = $persistence->persistSession($session, new Response());

        // expected values
        $expires = PhpSessionPersistence::CACHE_PAST_DATE;
        $control = sprintf('private, max-age=%d', $maxAge);

        $this->assertSame($expires, $response->getHeaderLine('Expires'));
        $this->assertSame($control, $response->getHeaderLine('Cache-Control'));

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testPersistSessionReturnsExpectedResponseWithCacheHeadersIfCacheLimiterIsPrivateNoExpire()
    {
        $expire = 333;
        $maxAge = 60 * $expire;

        $ini = $this->applyCustomSessionOptions([
            'cache_limiter' => 'private_no_expire',
            'cache_expire'  => $expire,
        ]);

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $session->set('foo', __METHOD__);

        $response = $persistence->persistSession($session, new Response());

        $control = sprintf('private, max-age=%d', $maxAge);

        $this->assertFalse($response->hasHeader('Expires'));
        $this->assertSame('', $response->getHeaderLine('Expires'));
        $this->assertSame($control, $response->getHeaderLine('Cache-Control'));

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testPersistSessionReturnsExpectedResponseWithoutAddedHeadersIfAlreadyHasAny()
    {
        $ini = $this->applyCustomSessionOptions([
            'cache_limiter' => 'nocache',
        ]);

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

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testPersistSessionInjectsExpectedLastModifiedHeader()
    {
        $ini = $this->applyCustomSessionOptions([
            'cache_limiter' => 'public',
        ]);

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $session->set('foo', __METHOD__);

        $response = $persistence->persistSession($session, new Response());

        $lastmod = getlastmod();
        if (false === $lastmod) {
            $rc = new ReflectionClass($persistence);
            $classFile = $rc->getFileName();
            $lastmod = filemtime($classFile);
        }

        $lastModified = $lastmod ? gmdate(PhpSessionPersistence::HTTP_DATE_FORMAT, $lastmod) : false;

        $expectedHeaderLine = false === $lastModified ? '' : $lastModified;

        $this->assertSame($expectedHeaderLine, $response->getHeaderLine('Last-Modified'));
        if (false === $lastModified) {
            $this->assertFalse($response->hasHeader('Last-Modified'));
        }

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testPersistSessionReturnsExpectedResponseWithoutAddedCacheHeadersIfEmptyCacheLimiter()
    {
        $ini = $this->applyCustomSessionOptions([
            'cache_limiter' => '',
        ]);

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $response = $persistence->persistSession($session, new Response());

        $this->assertFalse($response->hasHeader('Pragma'));
        $this->assertFalse($response->hasHeader('Expires'));
        $this->assertFalse($response->hasHeader('Cache-Control'));

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testPersistSessionReturnsExpectedResponseWithoutAddedCacheHeadersIfUnsupportedCacheLimiter()
    {
        $ini = $this->applyCustomSessionOptions([
            'cache_limiter' => 'unsupported',
        ]);

        $persistence = new PhpSessionPersistence();

        $request  = $this->createSessionCookieRequest();
        $session  = $persistence->initializeSessionFromRequest($request);
        $response = $persistence->persistSession($session, new Response());

        $this->assertFalse($response->hasHeader('Pragma'));
        $this->assertFalse($response->hasHeader('Expires'));
        $this->assertFalse($response->hasHeader('Cache-Control'));

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testCookiesNotSetWithoutRegenerate()
    {
        $persistence = new PhpSessionPersistence();
        $request = new ServerRequest();
        $session = $persistence->initializeSessionFromRequest($request);

        $response = new Response();
        $response = $persistence->persistSession($session, $response);

        $this->assertFalse($response->hasHeader('Set-Cookie'));
    }

    public function testCookiesSetWithoutRegenerate()
    {
        $persistence = new PhpSessionPersistence();
        $request = new ServerRequest();
        $session = $persistence->initializeSessionFromRequest($request);

        $session->set('foo', 'bar');

        $response = new Response();
        $response = $persistence->persistSession($session, $response);

        $this->assertNotEmpty($response->getHeaderLine('Set-Cookie'));
    }

    public function testCookiesSetWithDefaultLifetime()
    {
        $persistence = new PhpSessionPersistence();
        $request = new ServerRequest();
        $session = $persistence->initializeSessionFromRequest($request);

        $session->set('foo', 'bar');

        $response = $persistence->persistSession($session, new Response());

        $setCookie = FigResponseCookies::get($response, session_name());

        $this->assertNotEmpty($response->getHeaderLine('Set-Cookie'));
        $this->assertInstanceOf(SetCookie::class, $setCookie);
        $this->assertSame(0, $setCookie->getExpires());
    }

    public function testCookiesSetWithCustomLifetime()
    {
        $lifetime = 300;

        $ini = $this->applyCustomSessionOptions([
            'cookie_lifetime' => $lifetime,
        ]);

        $persistence = new PhpSessionPersistence();
        $request = new ServerRequest();
        $session = $persistence->initializeSessionFromRequest($request);

        $session->set('foo', 'bar');

        $expiresMin = time() + $lifetime;
        $response = $persistence->persistSession($session, new Response());
        $expiresMax = time() + $lifetime;

        $setCookie = FigResponseCookies::get($response, session_name());
        $this->assertInstanceOf(SetCookie::class, $setCookie);

        $expires = $setCookie->getExpires();

        $this->assertGreaterThanOrEqual($expiresMin, $expires);
        $this->assertLessThanOrEqual($expiresMax, $expires);

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testAllowsSessionToSpecifyLifetime()
    {
        $originalLifetime = ini_get('session.cookie_lifetime');

        $persistence = new PhpSessionPersistence();
        $request = new ServerRequest();
        $session = $persistence->initializeSessionFromRequest($request);

        $lifetime = 300;
        $session->persistSessionFor($lifetime);

        $expiresMin = time() + $lifetime;
        $response = $persistence->persistSession($session, new Response());
        $expiresMax = time() + $lifetime;

        $setCookie = FigResponseCookies::get($response, session_name());
        $this->assertInstanceOf(SetCookie::class, $setCookie);

        $expires = $setCookie->getExpires();

        $this->assertGreaterThanOrEqual($expiresMin, $expires);
        $this->assertLessThanOrEqual($expiresMax, $expires);

        // reset lifetime
        session_set_cookie_params($originalLifetime);
    }

    public function testAllowsSessionToOverrideDefaultLifetime()
    {
        $ini = $this->applyCustomSessionOptions([
            'cookie_lifetime' => 600,
        ]);

        $persistence = new PhpSessionPersistence();
        $request = new ServerRequest();
        $session = $persistence->initializeSessionFromRequest($request);

        $lifetime = 300;
        $session->persistSessionFor($lifetime);

        $expiresMin = time() + $lifetime;
        $response = $persistence->persistSession($session, new Response());
        $expiresMax = time() + $lifetime;

        $setCookie = FigResponseCookies::get($response, session_name());
        $this->assertInstanceOf(SetCookie::class, $setCookie);

        $expires = $setCookie->getExpires();

        $this->assertGreaterThanOrEqual($expiresMin, $expires);
        $this->assertLessThanOrEqual($expiresMax, $expires);

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testSavedSessionLifetimeOverridesDefaultLifetime()
    {
        $ini = $this->applyCustomSessionOptions([
            'cookie_lifetime' => 600,
        ]);
        $lifetime = 300;

        $persistence = new PhpSessionPersistence();
        $session = new Session([
            SessionCookiePersistenceInterface::SESSION_LIFETIME_KEY => $lifetime,
            'foo' => 'bar',
        ], 'abcdef123456');
        $session->set('foo', __METHOD__);

        $expiresMin = time() + $lifetime;
        $response = $persistence->persistSession($session, new Response());
        $expiresMax = time() + $lifetime;

        $setCookie = FigResponseCookies::get($response, session_name());
        $this->assertInstanceOf(SetCookie::class, $setCookie);

        $expires = $setCookie->getExpires();

        $this->assertGreaterThanOrEqual($expiresMin, $expires);
        $this->assertLessThanOrEqual($expiresMax, $expires);

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testStartSessionDoesNotOverrideRequiredSettings()
    {
        $persistence = new PhpSessionPersistence();

        $method = new ReflectionMethod($persistence, 'startSession');
        $method->setAccessible(true);

        // try to override required settings
        $method->invokeArgs($persistence, [
            'my-session-id',
            [
                'use_cookies'      => true,      // FALSE is required
                'use_only_cookies' => false,     // TRUE is required
                'cache_limiter'    => 'nocache', // '' is required
            ]
        ]);

        $filter = FILTER_VALIDATE_BOOLEAN;
        $flags  = FILTER_NULL_ON_FAILURE;

        $session_use_cookies      = filter_var(ini_get('session.use_cookies'), $filter, $flags);
        $session_use_only_cookies = filter_var(ini_get('session.use_only_cookies'), $filter, $flags);
        $session_cache_limiter    = ini_get('session.cache_limiter');

        $this->assertFalse($session_use_cookies);
        $this->assertTrue($session_use_only_cookies);
        $this->assertSame('', $session_cache_limiter);
    }

    public function testNoMultipleEmptySessionFilesAreCreatedIfNoSessionCookiePresent()
    {
        $sessionName = 'NOSESSIONCOOKIESESSID';
        $ini = $this->applyCustomSessionOptions([
            'name' => $sessionName,
        ]);

        $persistence = new PhpSessionPersistence();

        // initial sessioncookie-less request
        $request = new ServerRequest();

        for ($i = 0; $i < 3; $i += 1) {
            $session  = $persistence->initializeSessionFromRequest($request);
            $response = $persistence->persistSession($session, new Response());

            // new request: start w/o session cookie
            $request = new ServerRequest();

            // Add the latest response session cookie value to the new request, if any
            $setCookies = SetCookies::fromResponse($response);
            if ($setCookies->has($sessionName)) {
                $setCookie = $setCookies->get($sessionName);
            }
            if (isset($setCookie)) {
                $cookie = new Cookie($sessionName, $setCookie->getValue());
                $request = FigRequestCookies::set($request, $cookie);
            }
        }

        $this->assertPersistedSessionsCount(0);

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function testOnlyOneSessionFileIsCreatedIfNoSessionCookiePresentINFirstRequestButSessionDataChanged()
    {
        $sessionName = 'NOSESSIONCOOKIESESSID';
        $ini = $this->applyCustomSessionOptions([
            'name' => $sessionName,
        ]);

        $persistence = new PhpSessionPersistence();

        // initial sessioncookie-less request
        $request = new ServerRequest();

        for ($i = 0; $i < 3; $i += 1) {
            $session  = $persistence->initializeSessionFromRequest($request);
            $session->set('foo' . $i, 'bar' . $i);
            $response = $persistence->persistSession($session, new Response());

            // new request: start w/o session cookie
            $request = new ServerRequest();

            // Add the latest response session cookie value to the new request, if any
            $setCookies = SetCookies::fromResponse($response);
            if ($setCookies->has($sessionName)) {
                $setCookie = $setCookies->get($sessionName);
            }
            if (isset($setCookie)) {
                $cookie = new Cookie($sessionName, $setCookie->getValue());
                $request = FigRequestCookies::set($request, $cookie);
            }
        }

        $this->assertPersistedSessionsCount(1);

        $this->restoreOriginalSessionIniSettings($ini);
    }

    /**
     * @dataProvider cookieSettingsProvider
     * @param string|int|bool $secureIni
     * @param string|int|bool $httpOnlyIni
     */
    public function testThatSetCookieCorrectlyInterpretsIniSettings(
        $secureIni,
        $httpOnlyIni,
        bool $expectedSecure,
        bool $expectedHttpOnly
    ) {
        $ini = $this->applyCustomSessionOptions([
            'cookie_secure'   => $secureIni,
            'cookie_httponly' => $httpOnlyIni,
        ]);

        $persistence = new PhpSessionPersistence();

        $createSessionCookie = new ReflectionMethod($persistence, 'createSessionCookie');
        $createSessionCookie->setAccessible(true);

        $setCookie = $createSessionCookie->invokeArgs(
            $persistence,
            ['SETCOOKIESESSIONID', 'set-cookie-test-value']
        );

        $this->assertSame($expectedSecure, $setCookie->getSecure());
        $this->assertSame($expectedHttpOnly, $setCookie->getHttpOnly());

        $this->restoreOriginalSessionIniSettings($ini);
    }

    public function cookieSettingsProvider()
    {
        // @codingStandardsIgnoreStart
        // phpcs:disable
        return [
            // Each case has:
            // - session.cookie_secure INI flag value
            // - session.cookie_httponly INI flag value
            // - expected value for session.cookie_secure after registration
            // - expected value for session.cookie_httponly after registration
            'boolean-false-false' => [false, false, false, false],
            'int-zero-false'      => [    0,     0, false, false],
            'string-zero-false'   => [  '0',   '0', false, false],
            'string-empty-false'  => [   '',    '', false, false],
            'string-off-false'    => ['off', 'off', false, false],
            'string-Off-false'    => ['Off', 'Off', false, false],
            'boolean-true-true'   => [ true,  true,  true,  true],
            'int-one-true'        => [    1,     1,  true,  true],
            'string-one-true'     => [   '1',  '1',  true,  true],
            'string-on-true'      => [  'on',  'on', true,  true],
            'string-On-true'      => [  'On',  'On', true,  true],
        ];
        // phpcs:enable
        // @codingStandardsIgnoreEnd
    }

    public function testHeadersAreNotSentIfReloadedSessionDidNotChange()
    {
        $this->assertSame(PHP_SESSION_NONE, session_status());

        $request = $this->createSessionCookieRequest('reloaded-session');
        $session = $this->persistence->initializeSessionFromRequest($request);

        $this->assertSame(PHP_SESSION_ACTIVE, session_status());
        $this->assertInstanceOf(Session::class, $session);
        $this->assertSame($_SESSION, $session->toArray());
        $this->assertSame('reloaded-session', session_id());

        $response = new Response();
        $returnedResponse = $this->persistence->persistSession($session, $response);

        $this->assertSame($returnedResponse, $response, 'returned response should have no cookie and no cache headers');
        $this->assertEmpty($response->getHeaders());
    }
}
