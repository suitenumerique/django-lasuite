# Using marketing backend

If you need a marketing service in the application you are developping, this module will provide the implementation you need.

The list of backends available and what they are able to do is subject to evolution.

## Global idea

A backend should inherit from `lasuite.marketing.backends.base.BaseBackend` class and implement the abstract methods declared in it.

### Abstract methods

- `def create_or_update_contact(self, contact_data: ContactData, timeout: int = None) -> dict:`: It is the method to call to create a new contact in your marketin system.
    - `contact_data` is an instance of the `lasuite.marketing.ContactData` data class.
    - `timeout` is an optional parameter used if you want to force a request timeout.

### How to use a backend

We provide a handler responsible to instantiate and configure a backend. You have to declare in your settings the backend to use with their needed parameters.

The settings to use is `settings.LASUITE_MARKETING`. It is a `dict` containing two keys: `BACKEND` and `PARAMETERS`. The `BACKEND` is the full path to the backend class and the `PARAMETERS` is a dict containing all the parameters needed to instantiate the backend class.

Example:

```python
settings.LASUITE_MARKETING = {
    "BACKEND": "lasuite.marketing.backends.dummy.DummyBackend",
    "PARAMETERS": {},
}
```

Then to use the backend in your code, you have to import the `lasuite.marketing.marketing` and call the `create_or_update_contact` method.

## Existing implementations

### Dummy

path: `lasuite.marketing.backend.dummy.DummyBackend`

This implementation does nothing and accept no parameter.

### Brevo

path: ``lasuite.marketing.backend.brevo.BrevoBackend`
parameters:
    - `api_key`: The api_key used by the brevo client. Provided by brevo. Required
    - `api_contact_list_ids`: The list of contact_list defined in brevo. At least one should be provided. Required
    - `api_contact_attributes`: A dict of attributes to add to the contact. Optional
    