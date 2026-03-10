# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.25] - 2026-03-10

### Added

- 💄(admin) allow admin header color customization
- 🍱(core) vendor mime.types file i/o fetching from Apache

## [0.0.24] - 2026-02-04

### Changed

- 🚸(oidc) ignore case when fallback on email #61

### Fixed

- 🐛(oidc) use correct session key for token expiration check #56

## [0.0.23] - 2026-01-14



- ⬆️(oidc) allow use mozilla-django-oidc >5.0.0 with PyJWT
- ♻️(malware) reuse existing file_hash when rescheduling a task

## [0.0.22] - 2025-12-04

### Added

- ✨(marketing) create marketing module

## [0.0.21] - 2025-12-04

### Added

- ✨(malware) save file hash in detection record and callback

## [0.0.20] - 2025-12-02

### Added

- ✨(backend) keep traces of failed malware analysis tasks
- ✨(backend) save backend used in a malware analysis task
- ✨(backend) allow a malware detection backend to reschedule a task
- ✨(malware) add management command to reschedule processing
- ✨(malware) add an admin view to ease tracking tasks

## [0.0.19] - 2025-11-21

### Changed

- ♻️(resource-server) make token introspection earlier #46

## [0.0.18] - 2025-11-06

### Changed

- 🐛(joserfc) refactor JWT handling with joserfc library updates #35
- 👔(oidc) consider urls as refreshable no matter the HTTP method #42

## [0.0.17] - 2025-10-27

### Added

- ✨(backend) extract reach and roles choices #33

### Fixed

- 🐛(oidc) do not allow user sub update when set #34


## [0.0.16] - 2025-10-24

### Fixed

- 🐛(oidc) fix `update_user` when `User.sub` is nullable #31


## [0.0.15] - 2025-10-24

### Added

- ✨(oidc) add backend logout endpoint #28

### Fixed

- 🐛(oidc) validate state param during silent login failure for CSRF protection
- 🐛(oidc) fix session persistence with Redis backend for OIDC flows

## [0.0.14] - 2025-09-05

### Added

- ✨(drf) implement monitored scope throttling class #27

## [0.0.13] - 2025-08-28

### Fixed

- 🗃️(malware_detection) use dict callable for MalwareDetection
  defaut parameters #26

## [0.0.12] - 2025-07-22

### Added

- ✨(malware_detection) limit simultaneous files analysis for jcop #25

### Fixed

- 🐛(tests) fix test_project app to be usable with management command #25

## [0.0.11] - 2025-07-09

### Fixed

- 🐛(resource-server) allow `aud` & `iss` JWE headers #24

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

[unreleased]: https://github.com/suitenumerique/django-lasuite/compare/v0.0.25...main
[0.0.25]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.25
[0.0.24]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.24
[0.0.23]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.23
[0.0.22]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.22
[0.0.21]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.21
[0.0.20]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.20
[0.0.19]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.19
[0.0.18]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.18
[0.0.17]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.17
[0.0.16]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.16
[0.0.15]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.15
[0.0.14]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.13
[0.0.13]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.13
[0.0.12]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.12
[0.0.11]: https://github.com/suitenumerique/django-lasuite/releases/v0.0.11
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
