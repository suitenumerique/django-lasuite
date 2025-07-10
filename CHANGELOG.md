# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- ✨(malware_detection) limit simultaneous files analysis for jcop

### Fixed

- 🐛(resource-server) allow `aud` & `iss` JWE headers #24
- 🐛(tests) fix test_project app to be usable with management command #25

## [0.0.10] - 2025-06-18

### Fixed

- 🐛(oidc-rs) fix non base 64 authentication token #21
- 📝(pyproject) fix the package metadata #23

## [0.0.9] - 2025-05-20

### Added

- ✨(configuration) add configuration Value to support file path
  in environment #15

### Changed

- ♻️(malware_detection) retry getting analyse result sooner

## [0.0.8] - 2025-05-06

### Added

- ✨(malware_detection) add a module malware_detection #11

### Fixed

- 🐛(oidc) fix resource server client when using JSON introspection #16
- 🔊(oidc) improve resource server log for inactive user #17
- 🐛(oidc) use the OIDC_USER_SUB_FIELD when needed #18
- 🩹(oidc) remove deprecated cgi use #19

## [0.0.7] - 2025-04-23

### Fixed

- 🐛(oidc) fix user info endpoint format auto #12

## [0.0.6] - 2025-04-11

### Changed

- 💥(oidc) normalize setting names #10

## [0.0.5] - 2025-04-10

### Fixed

- 🐛(oidc) do not allow empty sub claim #9

## [0.0.4] - 2025-04-10

### Added

- ✨(oidc) allow silent login authentication #8

## [0.0.3] - 2025-04-09

### Added

- ✨(oidc) allow JSON format in user info endpoint #5
- ✨(oidc) add essential claims check setting #6

## [0.0.2] - 2025-04-07

### Fixed

- 🐛(oidc-rs) do not check iss in introspection #4

## [0.0.1] - 2025-04-03

### Added

- ✨(tools) extract domain from email address #2
- ✨(oidc) add the authentication backends #2
- ✨(oidc) add refresh token tools #3

[unreleased]: https://github.com/suitenumerique/django-lasuite/compare/v0.0.10...main
[0.0.10]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.10
[0.0.9]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.9
[0.0.8]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.8
[0.0.7]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.7
[0.0.6]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.6
[0.0.5]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.5
[0.0.4]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.4
[0.0.3]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.3
[0.0.2]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.2
[0.0.1]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.1
