"""Custom value classes for django-configurations."""

import os

from configurations import values


class SecretFileValue(values.Value):
    """
    Class used to interpret value from environment variables with reading file support.

    The value set is either (in order of priority):
    * The content of the file referenced by the environment variable
      `{name}_{file_suffix}` if set.
    * The value of the environment variable `{name}` if set.
    * The default value
    """

    file_suffix = "FILE"

    def __init__(self, *args, **kwargs):
        """Initialize the value."""
        super().__init__(*args, **kwargs)
        if "file_suffix" in kwargs:
            self.file_suffix = kwargs["file_suffix"]

    def setup(self, name):
        """Get the value from environment variables."""
        value = self.default
        if self.environ:
            full_environ_name = self.full_environ_name(name)
            full_environ_name_file = f"{full_environ_name}_{self.file_suffix}"
            if full_environ_name_file in os.environ:
                filename = os.environ[full_environ_name_file]
                if not os.path.exists(filename):
                    raise ValueError(f"Path {filename!r} does not exist.")
                try:
                    with open(filename) as file:
                        value = self.to_python(file.read().removesuffix("\n"))
                except (OSError, PermissionError) as err:
                    raise ValueError(f"Path {filename!r} cannot be read: {err!r}") from err
            elif full_environ_name in os.environ:
                value = self.to_python(os.environ[full_environ_name])
            elif self.environ_required:
                raise ValueError(
                    f"Value {name!r} is required to be set as the "
                    f"environment variable {full_environ_name_file!r} or {full_environ_name!r}"
                )
        self.value = value
        return value
