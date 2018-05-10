<?php
/**
 * @see       https://github.com/zendframework/zend-expressive-session-ext for the canonical source repository
 * @copyright Copyright (c) 2017 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   https://github.com/zendframework/zend-expressive-session-ext/blob/master/LICENSE.md New BSD License
 */

namespace Zend\Expressive\Session\Ext;

use Dflydev\FigCookies\FigCookies\Cookie;
use Dflydev\FigCookies\FigRequestCookies;
use Dflydev\FigCookies\FigResponseCookies;
use Dflydev\FigCookies\SetCookie;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Expressive\Session\Session;
use Zend\Expressive\Session\SessionInterface;
use Zend\Expressive\Session\SessionPersistenceInterface;

use function array_merge;
use function bin2hex;
use function ini_get;
use function random_bytes;
use function session_id;
use function session_name;
use function session_start;
use function session_write_close;

/**
 * Session persistence using ext-session.
 *
 * Adapts ext-session to work with PSR-7 by disabling its auto-cookie creation
 * (`use_cookies => false`), while simultaneously requiring cookies for session
 * handling (`use_only_cookies => true`). The implementation pulls cookies
 * manually from the request, and injects a `Set-Cookie` header into the
 * response.
 *
 * Session identifiers are generated using random_bytes (and casting to hex).
 * During persistence, if the session regeneration flag is true, a new session
 * identifier is created, and the session re-started.
 */
class PhpSessionPersistence implements SessionPersistenceInterface
{
    /** @var string|null */
    private $cookie;

    public function initializeSessionFromRequest(ServerRequestInterface $request) : SessionInterface
    {
        $this->cookie = FigRequestCookies::get($request, session_name())->getValue();
        $id = $this->cookie ?: $this->generateSessionId();
        $this->startSession($id);
        return new Session($_SESSION);
    }

    public function persistSession(SessionInterface $session, ResponseInterface $response) : ResponseInterface
    {
        if ($session->isRegenerated()) {
            $this->regenerateSession();
        }

        $_SESSION = $session->toArray();
        session_write_close();

        if ($this->cookie) {
            $sessionCookie = SetCookie::create(session_name())
                ->withValue($this->cookie)
                ->withPath(ini_get('session.cookie_path'));

            return FigResponseCookies::set($response, $sessionCookie);
        }

        return $response;
    }

    /**
     * @param array $options Additional options to pass to `session_start()`.
     */
    private function startSession(string $id, array $options = []) : void
    {
        session_id($id);
        session_start(array_merge([
            'use_cookies'      => false,
            'use_only_cookies' => true,
        ], $options));
    }

    /**
     * Regenerates the session safely.
     *
     * @link http://php.net/manual/en/function.session-regenerate-id.php (Example #2)
     */
    private function regenerateSession() : void
    {
        session_write_close();
        $this->cookie = $this->generateSessionId();
        $this->startSession($this->cookie, [
            'use_strict_mode' => false,
        ]);
    }

    /**
     * Generate a session identifier.
     */
    private function generateSessionId() : string
    {
        return bin2hex(random_bytes(16));
    }
}
