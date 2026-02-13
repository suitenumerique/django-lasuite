# Using custom admin colors

This guide will present you how to integrate and configure the `LaSuiteAdminSite` in your Django project.

## Overview

The goal of this small app is to allow a quick customisation of Django admin's colors, to avoid getting mixed up between your different environments and avoid errors.

## Installation
1. Ensure you have the necessary packages installed:

```bash
pip install django-lasuite
```

## Configuration

### Settings

Add the following to your Django settings:

```python
INSTALLED_APPS = [
    ...
    "lasuite.custom_admin",
]

# Django Admin
ADMIN_HEADER_BACKGROUND = "#0f5132"
ADMIN_HEADER_COLOR = "#ffffff"
```

or load desired colors using your env files.

