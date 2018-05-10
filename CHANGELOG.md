# Changelog

All notable changes to this project will be documented in this file, in reverse chronological order by release.

## 1.1.1 - TBD

### Added

- Nothing.

### Changed

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- Nothing.

## 1.1.0 - 2018-05-10

### Added

- Nothing.

### Changed

- [#12](https://github.com/zendframework/zend-expressive-session-ext/pull/12) updates the `PhpSessionPersistence` class such that it is now responsible for
  emitting the various cache limiter headers (`Expires`, `Cache-Control`, `Last-Modified`, and `Pragma`) normally
  emitted by ext-session and controlled by the `session.cache_limiter` and `session.cache_expire` INI settings.
  This approach ensures that those headers are not overwritten by ext-session if set elsewhere in your
  application.

- [#9](https://github.com/zendframework/zend-expressive-session-ext/pull/9) swaps a call to `session_commit` to `session_write_close` withing `PhpSessionPersistence`,
  as the former is an alias for the latter.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- [#13](https://github.com/zendframework/zend-expressive-session-ext/pull/13) fixes an issue whereby a new session cookie is not always sent
  following an ID regeneration.

## 1.0.1 - 2018-03-15

### Added

- Nothing.

### Changed

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- [#8](https://github.com/zendframework/zend-expressive-session-ext/pull/8)
  fixes how session resets occur, ensuring cookies are reset correctly.

## 1.0.0 - 2018-03-15

### Added

- Nothing.

### Changed

- Nothing.

### Deprecated

- Nothing.

### Removed

- Removes support for pre-stable 1.0.0 versions of zend-expressive-session.

### Fixed

- Nothing.

## 0.1.4 - 2018-02-28

### Added

- Nothing.

### Changed

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- [#1](https://github.com/zendframework/zend-expressive-session-ext/pull/1)
  fixes a problem that occurs when a requested session does not resolve to an
  existing session and/or an existing session with empty data, leading to
  creation of new sessions on each request.

## 0.1.3 - 2018-02-24

### Added

- [#5](https://github.com/zendframework/zend-expressive-session-ext/pull/5) adds
  support for the ^1.0.0alpha1 release of zend-expressive-session.

## 0.1.2 - 2017-12-12

### Added

- [#3](https://github.com/zendframework/zend-expressive-session-ext/pull/3) adds
  support for the 1.0-dev and 1.0 releases of zend-expressive-session.

### Changed

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- Nothing.

## 0.1.1 - 2017-10-10

### Added

- Nothing.

### Changed

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- Fixes session regeneration under PHP 7.2 so that it will not raise warnings.

## 0.1.0 - 2017-10-10

Initial release.

### Added

- Everything.

### Changed

- Nothing.

### Deprecated

- Nothing.

### Removed

- Nothing.

### Fixed

- Nothing.
