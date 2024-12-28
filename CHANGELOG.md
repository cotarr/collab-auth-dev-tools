# Changelog

- Add .gitignore
- Add demo for OAuth 2.0 implicit grant type

## 2024-11-24

- Create new repository "collab-auth-dev-tools"

- Copy /debug/ folder from collab-auth repository to collab-auth-dev-tools repository

After creating a symlink in the collab-auth folder, most tests ran without issue from the symlink.
The following files needed some adjustment to the file path between repositories 
to avoid file not found errors during the tests.

```
modules/import-config.js

login-form-submission.js
admin-access-check.js
protected-routes.js
access-token-client.js
access-token-user.js
cookie-tests.js
```
The tests are working as expected after the file path updates.
