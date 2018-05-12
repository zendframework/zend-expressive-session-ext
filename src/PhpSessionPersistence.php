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
use function filemtime;
use function gmdate;
use function ini_get;
use function is_file;
use function random_bytes;
use function session_id;
use function session_name;
use function session_start;
use function session_write_close;
use function sprintf;
use function time;

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

    /** @var string */
    private $cacheLimiter;

    /** @var int */
    private $cacheExpire;

    /** @var string */
    private $scriptFile;

    /** @var array */
    private static $supported_cache_limiters = [
        'nocache'           => true,
        'public'            => true,
        'private'           => true,
        'private_no_expire' => true,
    ];

    /**
     * This unusual past date value is taken from the php-engine source code and
     * used "as is" for consistency.
     */
    public const CACHE_PAST_DATE  = 'Thu, 19 Nov 1981 08:52:00 GMT';

    public const HTTP_DATE_FORMAT = 'D, d M Y H:i:s T';

    /**
     * Memoize session ini settings before starting the request.
     *
     * The cache_limiter setting is actually "stolen", as we will start the
     * session with a forced empty value in order to instruct the php engine to
     * skip sending the cache headers (this being php's default behaviour).
     * Those headers will be added programmatically to the response along with
     * the session set-cookie header when the session data is persisted.
     */
    public function __construct()
    {
        $this->cacheLimiter = ini_get('session.cache_limiter');
        $this->cacheExpire  = (int) ini_get('session.cache_expire');
    }

    public function initializeSessionFromRequest(ServerRequestInterface $request) : SessionInterface
    {
        $this->scriptFile = $request->getServerParams()['SCRIPT_FILENAME'] ?? __FILE__;
        $id = $this->cookie = FigRequestCookies::get($request, session_name())->getValue();

        if (! $id) {
            $id = $this->cookie = $this->generateSessionId();
        }

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

            $response = FigResponseCookies::set($response, $sessionCookie);

            if (! $this->cacheLimiter || $this->responseAlreadyHasCacheHeaders($response)) {
                return $response;
            }

            $cacheHeaders = $this->generateCacheHeaders();
            foreach ($cacheHeaders as $name => $value) {
                if (false !== $value) {
                    $response = $response->withHeader($name, $value);
                }
            }
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

    /**
     * Generate cache http headers for this instance's session cache_limiter and
     * cache_expire values
     */
    private function generateCacheHeaders() : array
    {
        // Unsupported cache_limiter
        if (! isset(self::$supported_cache_limiters[$this->cacheLimiter])) {
            return [];
        }

        // cache_limiter: 'nocache'
        if ('nocache' === $this->cacheLimiter) {
            return [
                'Expires'       => self::CACHE_PAST_DATE,
                'Cache-Control' => 'no-store, no-cache, must-revalidate',
                'Pragma'        => 'no-cache',
            ];
        }

        $maxAge       = 60 * $this->cacheExpire;
        $lastModified = $this->getLastModified();

        // cache_limiter: 'public'
        if ('public' === $this->cacheLimiter) {
            return [
                'Expires'       => gmdate(self::HTTP_DATE_FORMAT, time() + $maxAge),
                'Cache-Control' => sprintf('public, max-age=%d', $maxAge),
                'Last-Modified' => $lastModified,
            ];
        }

        // cache_limiter: 'private'
        if ('private' === $this->cacheLimiter) {
            return [
                'Expires'       => self::CACHE_PAST_DATE,
                'Cache-Control' => sprintf('private, max-age=%d', $maxAge),
                'Last-Modified' => $lastModified,
            ];
        }

        // last possible case, cache_limiter = 'private_no_expire'
        return [
            'Cache-Control' => sprintf('private, max-age=%d', $maxAge),
            'Last-Modified' => $lastModified,
        ];
    }

    /**
     * Return the Last-Modified header line based on the request's script file
     * modified time. If no script file could be derived from the request we use
     * this class file modification time as fallback.
     * @return string|false
     */
    private function getLastModified()
    {
        if ($this->scriptFile && is_file($this->scriptFile)) {
            return gmdate(self::HTTP_DATE_FORMAT, filemtime($this->scriptFile));
        }

        return false;
    }

    /**
     * Check if the response already carries cache headers
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
