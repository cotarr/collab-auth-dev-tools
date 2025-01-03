# Changelog

## 2024-12-29

This update expands the custom API tests as follows:

- Add .gitignore
- Add demo for OAuth 2.0 implicit grant type
- Add demo for OAuth 2.0 password grant type
- Change load-test-introspect.js to generate access token by code grant instead of client credentials grant.
- Disable client token tests when client credentials grant is disabled
- Add test to confirm disabled grant type are not functional
- Add test to confirm client credentials grant requires valid clientId and clientSecret
- Add test to Add test to confirm authorization code grant requires valid credentials

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
