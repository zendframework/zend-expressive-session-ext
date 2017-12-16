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

    public function startSession(string $id = null)
    {
        $id = $id ?: 'testing';
        session_id($id);
        session_start([
            'use_cookies'      => false,
            'use_only_cookies' => true,
        ]);
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

    public function testPersistSessionReturnsResponseWithSetCookieHeaderIfSessionHasContents()
    {
        $this->startSession();
        $session = new Session(['foo' => 'bar']);
        $response = new Response();

        $returnedResponse = $this->persistence->persistSession($session, $response);
        $this->assertNotSame($response, $returnedResponse);

        $setCookie = FigResponseCookies::get($returnedResponse, session_name());
        $this->assertInstanceOf(SetCookie::class, $setCookie);
        $this->assertSame(session_id(), $setCookie->getValue());
        $this->assertSame(ini_get('session.cookie_path'), $setCookie->getPath());

        $this->assertSame($session->toArray(), $_SESSION);
    }

    public function testPersistSessionGeneratesCookieWithNewSessionIdIfSessionWasRegenerated()
    {
        $this->startSession('original-id');

        $session = new Session(['foo' => 'bar']);
        $session = $session->regenerate();

        $response = new Response();

        $returnedResponse = $this->persistence->persistSession($session, $response);
        $this->assertNotSame($response, $returnedResponse);

        $setCookie = FigResponseCookies::get($returnedResponse, session_name());
        $this->assertInstanceOf(SetCookie::class, $setCookie);
        $this->assertNotSame('original-id', $setCookie->getValue());
        $this->assertSame(session_id(), $setCookie->getValue());

        $this->assertSame($session->toArray(), $_SESSION);
    }

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
}
