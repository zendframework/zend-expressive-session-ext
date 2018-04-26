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
use function sprintf;
use function gmdate;
use function time;
use function filemtime;

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
    /** @var Cookie */
    private $cookie;

    /** @var string */
    private $cacheLimiter;

    /** @var int */
    private $cacheExpire;

    public const CACHE_PAST_DATE  = 'Thu, 19 Nov 1981 08:52:00 GMT';
    public const HTTP_DATE_FORMAT = 'D, d M Y H:i:s T';

    public function __construct()
    {
        $this->cacheLimiter = ini_get('session.cache_limiter');
        $this->cacheExpire  = (int) ini_get('session.cache_expire');
    }

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

        if (empty($this->cookie)) {
            $sessionCookie = SetCookie::create(session_name())
                ->withValue(session_id())
                ->withPath(ini_get('session.cookie_path'));

            $response = FigResponseCookies::set($response, $sessionCookie);

            if ($this->cacheLimiter) {
                if ($this->responseAlreadyHasCacheHeaders($response)) {
                    return $response;
                }
                $cacheHeaders = $this->generateCacheHeaders($this->cacheLimiter, $this->cacheExpire);
                foreach ($cacheHeaders as $name => $value) {
                    $response = $response->withHeader($name, $value);
                }
            }

            return $response;
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
            'cache_limiter'    => '',
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
        $this->cookie = null;
        $this->startSession($this->generateSessionId(), [
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

    /**
     * Generate cache headers for a given session cache_limiter value.
     * @param string|null $cacheLimiter
     * @param int $cacheExpire
     */
    private function generateCacheHeaders(string $cacheLimiter = null, int $cacheExpire = 0) : array
    {
        if (! $cacheLimiter) {
            return [];
        }

        if ($cacheLimiter === 'nocache') {
            return [
                'Expires'       => self::CACHE_PAST_DATE,
                'Cache-Control' => 'no-store, no-cache, must-revalidate',
                'Pragma'        => 'no-cache',
            ];
        }

        $headers = [];
        $maxAge  = 60 * $cacheExpire;

        if ($cacheLimiter === 'public') {
            $headers = [
                'Expires'       => gmdate(self::HTTP_DATE_FORMAT, time() + $maxAge),
                'Cache-Control' => sprintf('public, max-age=%d', $maxAge),
            ];
        } elseif ($cacheLimiter === 'private') {
            $headers = [
                'Expires'       => self::CACHE_PAST_DATE,
                'Cache-Control' => sprintf('private, max-age=%d', $maxAge),
            ];
        } elseif ($cacheLimiter === 'private_no_expire') {
            $headers = [
                'Cache-Control' => sprintf('private, max-age=%d', $maxAge),
            ];
        } else {
            return [];
        }

        $script = $_SERVER['SCRIPT_FILENAME'] ?? '';
        $lastModified = $this->getLastModified($script);
        if ($lastModified) {
            $headers['Last-Modified'] = $lastModified;
        }

        return $headers;
    }

    /**
     * Return the Last-Modified header line based on script name mtime
     * @return string|null
     * @return string|null
     */
    private function getLastModified(string $filename) : ?string
    {
        if ($filename
            && is_file($filename)
        ) {
            $mtime = @filemtime($filename);
            if (false === $mtime) {
                return null;
            }
            return gmdate(self::HTTP_DATE_FORMAT, $mtime);
        }

        return null;
    }

    /**
     * Check if the response already carries cache headers
     * @param ResponseInterface $response
     * @return bool
     */
    private function responseAlreadyHasCacheHeaders(ResponseInterface $response) : bool
    {
        return (
               $response->hasHeader('Expires')
            || $response->hasHeader('Last-Modified')
            || $response->hasHeader('Cache-Control')
            || $response->hasHeader('Pragma')
        );
    }
}
