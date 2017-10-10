<?php
/**
 * @see       https://github.com/zendframework/zend-expressive-session-ext for the canonical source repository
 * @copyright Copyright (c) 2017 Zend Technologies USA Inc. (http://www.zend.com)
 * @license   https://github.com/zendframework/zend-expressive-session-ext/blob/master/LICENSE.md New BSD License
 */

namespace Zend\Expressive\Session\Ext;

use Zend\Expressive\Session\SessionPersistenceInterface;

class ConfigProvider
{
    public function __invoke() : array
    {
        return [
            'dependencies' => $this->getDependencies(),
        ];
    }

    public function getDependencies() : array
    {
        return [
            'aliases' => [
                SessionPersistenceInterface::class => PhpSessionPersistence::class,
            ],
            'invokables' => [
                PhpSessionPersistence::class => PhpSessionPersistence::class,
            ],
        ];
    }
}
