# Django La Suite

A Django library for the common requirement for the "La Suite numérique" projects.

## Installation

The base package only depends on Django. Each application declares its own
dependencies as an extra, so you only install what you use:

| Application                      | Install command                                    |
|----------------------------------|----------------------------------------------------|
| `lasuite.admin`, `lasuite.tools` | `pip install django-lasuite`                       |
| `lasuite.configuration`          | `pip install django-lasuite[configuration]`        |
| `lasuite.drf`                    | `pip install django-lasuite[drf]`                  |
| `lasuite.malware_detection`      | `pip install django-lasuite[malware-detection]`    |
| `lasuite.marketing`              | `pip install django-lasuite[marketing]`            |
| `lasuite.oidc_login`             | `pip install django-lasuite[oidc-login]`           |
| `lasuite.oidc_resource_server`   | `pip install django-lasuite[oidc-resource-server]` |

Extras can be combined (`pip install "django-lasuite[oidc-login,marketing]"`),
and `django-lasuite[all]` installs every application's dependencies.

## Quick Start

To be documented with the first implementations.

## Development

### Requirements

For this project, we use `uv` Python package manager.
Please follow the installation guidelines on the [uv documentation](https://docs.astral.sh/uv/getting-started/installation/).

### Setup

```bash
# Clone the repository
git clone https://github.com/suitenumerique/django-lasuite.git
cd django-lasuite

# Install development dependencies
make install-dev
```

### Testing

```bash
make test
```

### Code Quality

```bash
make lint
```

## License

MIT License
