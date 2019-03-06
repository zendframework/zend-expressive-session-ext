<?php
/**
 * @see       https://github.com/zendframework/zend-expressive-session for the canonical source repository
 * @copyright Copyright (c) 2017 Zend Technologies USA Inc. (https://www.zend.com)
 * @license   https://github.com/zendframework/zend-expressive-session/blob/master/LICENSE.md New BSD License
 */

declare(strict_types=1);

namespace Zend\Expressive\Session\Ext;

use Psr\Container\ContainerInterface;

/**
 * Create and return an instance of PhpSessionPersistence.
 *
 * In order to use non-locking sessions please provide a configuration entry
 * like the following:
 *
 * <code>
 * //...
 * 'session' => [
 *     'persistence' => [
 *         'ext' => [
 *             'non_locking' => true, // true|false
 *         ],
 *     ],
 * ],
 * //...
 * <code>
 */
class PhpSessionPersistenceFactory
{
    public function __invoke(ContainerInterface $container) : PhpSessionPersistence
    {
        $config = $container->has('config') ? $container->get('config') : null;
        $config = $config['session']['persistence']['ext'] ?? null;

        return new PhpSessionPersistence(! empty($config['non_locking']));
    }
}
