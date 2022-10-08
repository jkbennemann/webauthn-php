
# Simple package to implement the Webauthn API standard inside your PHP projects

[![Latest Version on Packagist](https://img.shields.io/packagist/v/jkbennemann/webauthn-php.svg?style=flat-square)](https://packagist.org/packages/jkbennemann/webauthn-php)
[![Tests](https://github.com/jkbennemann/webauthn-php/actions/workflows/run-tests.yml/badge.svg?branch=main)](https://github.com/jkbennemann/webauthn-php/actions/workflows/run-tests.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/jkbennemann/webauthn-php.svg?style=flat-square)](https://packagist.org/packages/jkbennemann/webauthn-php)

## Installation

You can install the package via composer:

```bash
composer require jkbennemann/webauthn-php
```

## Usage

```php
$skeleton = new Jkbennemann\Webauthn();
echo $skeleton->echoPhrase('Hello, Jkbennemann!');
```

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](https://github.com/spatie/.github/blob/main/CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Jakob Bennemann](https://github.com/jkbennemann)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
