# zend-expressive-session-ext

This component provides a persistence adapter for use with
[zend-expressive-session](https://docs.zendframework.com/zend-expressive-session/).

## Installation:

Run the following to install this library:

```bash
$ composer require zendframework/zend-expressive-session-ext
```

## Configuration

If your application uses the [zend-component-installer](https://docs.zendframework.com/zend-component-installer)
Composer plugin, your configuration is complete; the shipped
`Zend\Expressive\Session\Ext\ConfigProvider` registers the
`Zend\Expressive\Session\Ext\PhpSessionPersistence` service, as well as an alias
to it under the name `Zend\Expressive\Session\SessionPersistenceInterface`.

Otherwise, you will need to map `Zend\Expressive\Session\SessionPersistenceInterface`
to `Zend\Expressive\Session\Ext\PhpSessionPersistence` in your dependency
injection container.

## Usage

In most cases, usage will be via `Zend\Expressive\Session\SessionMiddleware`,
and will not require direct access to the service on your part. If you do need
to use it, please refer to the zend-expressive-session [session persistence
documentation](https://docs.zendframework.com/zend-expressive-session/persistence/).
