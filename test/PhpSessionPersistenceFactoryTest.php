<?php
/**
 * @see       https://github.com/zendframework/zend-expressive-session for the canonical source repository
 * @copyright Copyright (c) 2017 Zend Technologies USA Inc. (https://www.zend.com)
 * @license   https://github.com/zendframework/zend-expressive-session/blob/master/LICENSE.md New BSD License
 */

declare(strict_types=1);

namespace ZendTest\Expressive\Session\Ext;

use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Zend\Expressive\Session\Ext\PhpSessionPersistence;
use Zend\Expressive\Session\Ext\PhpSessionPersistenceFactory;

class PhpSessionPersistenceFactoryTest extends TestCase
{
    public function testFactoryConfigProducesPhpSessionPersistenceInterfaceService()
    {
        $container = $this->prophesize(ContainerInterface::class);
        $factory = new PhpSessionPersistenceFactory();

        // test php-session-persistence with missing config
        $container->has('config')->willReturn(false);
        $persistence = $factory($container->reveal());
        $this->assertInstanceOf(PhpSessionPersistence::class, $persistence);
        $this->assertAttributeSame(false, 'nonLocking', $persistence);

        // test php-session-persistence with non-locking config set to false and true
        foreach ([false, true] as $nonLocking) {
            $container->has('config')->willReturn(true);
            $container->get('config')->willReturn([
                'session' => [
                    'persistence' => [
                        'ext' => [
                            'non_locking' => $nonLocking,
                        ],
                    ],
                ],
            ]);
            $persistence = $factory($container->reveal());
            $this->assertAttributeSame($nonLocking, 'nonLocking', $persistence);
        }
    }
}
