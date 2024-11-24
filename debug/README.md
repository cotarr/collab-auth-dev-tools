# JavaScript Debug Tests

This "debug/" folder contains a set of JavaScript files that can be used to 
debug and test the collab-auth web server application. 
This debug/README.md file includes instructions for running these tests.

Note: OAuth 2 grant types Implicit Grant and Password Grant are excluded
from these tests because these are generally considered deprecated.

## List of scripts

### debug/clear-database.js

The collab-auth server can optionally select between two different type of databases.
The default is an in-memory RAM database which is used for debugging and software development.
Optionally, collab-auth can be configured to use a PostgreSQL database.
One set of database tables are used to hold access_token meta-data, 
user accounts, and client accounts. A separate tables used to hold session 
data including cookie's meta-data. By default, data is stored in RAM and 
data will be discarded when the program exits. Optionally, the following 
configuration can be used to select PostgreSQL for storage.

```bash
# PostgreSQL
SESSION_ENABLE_POSTGRES=true
DATABASE_ENABLE_POSTGRES=true
# In-memory RAM database (for development)
SESSION_ENABLE_POSTGRES=false
DATABASE_ENABLE_POSTGRES=false
```
When the clear-database.js script is run, it will clear all access tokens and session 
cookies from the currently selected database. The user accounts and client accounts 
will not be effected. This will cause a forced "logout" of all browsers. 
It is included here to provide a clean database for testing, and to clear 
temporary test data at the conclusion of testing.

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
```

### debug/code-grant-demo.js

This API test set is used to demonstrate and test the OAuth2 
authorization code grant workflow. Learning about the code-grant-demo 
module was the main purpose of the project. It is the most complex 
OAuth 2.0 workflow, and difficult to understand. This is a step by 
step execution of the authorization handshakes using authorization 
code grant. This script incorporates use of refresh_tokens that are 
used to replaced expired access_tokens.

(At the bottom of this page is a flowchart showing the code grant workflow)

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
```

### debug/client-grant-demo.js

This API test set is used to demonstrate and test the OAuth2 client credentials 
grant workflow. Client grant is the simplest Oauth 2.0 workflow. A new 
access token can be obtained using a single POST request where client 
credentials are exchanged for an access token.

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
```

### debug/access-token-client.js

It is an overall test of access token validation for token 
created using client credentials grant.

This API test script was written to explore the relationship between
the contents of the access_token payload compared with the associated
token meta-data that is stored in the authorization server database.
The collab-auth server generates OAuth 2.0 access_tokens
that are created as JWT tokens signed using an RSA private key.
This demonstrates validation of tokens, detection of an expired access tokens,
and expiration of token meta-data stored in the authorization server.

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
OAUTH2_CLIENT_TOKEN_EXPIRES_IN_SECONDS=10
```

### debug/access-token-user.js

It is an overall test of access token validation for token 
created using authorization code grant.
The process also includes a user decision step for untrusted client accounts.
This API test script was written to explore the relationship between

This module generate user token by submission of username and password.
the contents of the access_token payload compared with the associated
token meta-data that is stored in the authorization server database.
The collab-auth server generates OAuth 2.0 access_tokens
that are created as JWT tokens signed using an RSA private key.
This demonstrates validation of tokens, detection of an expired access tokens,
and expiration of token meta-data stored in the authorization server.

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
OAUTH2_AUTH_CODE_EXPIRES_IN_SECONDS=8
OAUTH2_TOKEN_EXPIRES_IN_SECONDS=10
OAUTH2_REFRESH_TOKEN_EXPIRES_IN_SECONDS=15
```

### debug/cookie-tests.js

The collab-auth server uses HTTP cookies to manage browser sessions
during authentication of the user's identity by submission
of username and password. The sessions and cookies are created
by the express-session middleware and use passport as authorization middleware.
This script is more a a deep dive into learning how cookies work in general 
using express-session and passport as authorization middleware.
During the code grant workflow, cookies issued by the browser are used
to authenticate the identity of the user when requesting a new authorization code.
The script includes two options for cookies with fixed expiration cookies and rolling cookies,
where rolling cookies will extend the cookie expiration with each request.

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
SESSION_EXPIRE_SEC=8
   # Option 1 of 2
   SESSION_SET_ROLLING_COOKIE=false
   # Option 1 of 2
   SESSION_SET_ROLLING_COOKIE=true
```

### debug/login-form-submission-js

This script will emulate the browser submission of the HTML form for user password entry.
This script will demonstrate detection of various errors conditions that can 
occur when users interact with the login form.

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
```

### debug/public-routes.js

This script will confirm that routes intended to be public are 
accessible when the browser does not provide a valid cookie.
There are several html routes that must be accessible at all 
times for unauthenticated requests.
This include access control forms, such as `/login` and `/logout`.
Additional routes, such as `/status`, `robots.txt`, 
`/.well-known/security.txt`, `/not-found.html` and several css style files.

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
    # Optional configuration (else test skipped)
    SITE_SECURITY_CONTACT=security@example.com
    SITE_SECURITY_EXPIRES="Fri, 1 Apr 2022 08:00:00 -0600"
```

### debug/protected-routes.js

This script will confirm that protected routes are blocked when 
access control credentials are not provided. Access to protected 
routes may be limited by combination of cookies, basic auth 
credentials, and CSRF tokens.

Note that other protected routes that are related to the administration 
page are tested in the alternate script `debug/admin-access-check.js`

```
# Example of protected routes
/secure
/changepassword
/redirecterror
/noscope
/dialog/authorize
/dialog/authorize/decision
/oauth/introspect
/oauth/token
/oauth/token/revoke
```

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
```

### debug/admin-user-edit.js

The collab-auth server may optionally provide the user with 
an account administration web page. This script will exercise 
the functionality of the administration pages used to create 
and modify OAuth 2.0 "user" accounts.

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
```

### debug/admin-client-edit.js

The collab-auth server may optionally provide the user with an 
account administration web page. This script will exercise the 
functionality of the administration pages used to create and 
modify OAuth 2.0 "client" accounts. This test requires the configuration 
setting `OAUTH2_EDITOR_SHOW_CLIENT_SECRET=true` so the text can 
verify the client data values.

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
OAUTH2_EDITOR_SHOW_CLIENT_SECRET=true
```

### debug/admin-access-check.js

The collab-auth server may optionally provide the user with an 
account administration web page. This script will test the 
access control for all administration web pages to verify that 
a valid cookie and in some cases CSRF token are required to 
view that account administration pages.

Note that other protected routes that are not related to the administration 
page are tested in the alternate script `debug/protected-routes.js`

```
/panel/menu
/panel/listusers
/panel/viewuser
/panel/createuser
/panel/edituser
/panel/deleteuser
/panel/listclients
/panel/viewclient
/panel/createclient
/panel/editclient
/panel/deleteclient
/panel/removealltokens
/panel/stats
```

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
```

### debug/admin-scope-check.js

The collab-auth server may optionally provide the user with an account administration web page.
In order to view the administration page, the web server requires a scope value of "user.admin".
The user's OAuth 2.0 account must be assigned the role "user.admin".
In this case where values of "server scope" and "user role" intersect, access is granted.
This script will create a temporary user account that does not include the required role (scope).
The temporary account will then be used to confirm the administration page are not accessible.

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
```

### debug/admin-disabled.js

The collab-auth server may optionally provide the user with an 
account administration web page. As an optional security feature, 
the administration routes may be disabled in the configuration.
It is recommended to disable the administration page routes after 
the user and client accounts have been created. In this case, 
all administration page routes will return 404 Not Found.
In order to run this script, the configuration must 
include `DATABASE_DISABLE_WEB_ADMIN_PANEL=true`.

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
DATABASE_DISABLE_WEB_ADMIN_PANEL=true
```

### debug/rate-limit.js

The collab-auth web server includes rate limiting on several of the routes.
This script will subject the web server to repeated requests to confirm
that future requests are rejected after the limits are exceeded.
To run this script. specific rate limits are required.

rate-limit.js requires:

```bash
# Required settings
LIMITS_PASSWORD_RATE_LIMIT_COUNT=4
LIMITS_TOKEN_RATE_LIMIT_COUNT=6
LIMITS_WEB_RATE_LIMIT_COUNT=16
```

### debug/redirect-timing-debug.js

This script is custom debug tool used to debug redirect 
errors that occur after user's password entry.

The first request (1) modifies the session's record in the 
session store by adding a returnTo property to the session 
with the full URL of the unauthorized request.

The second request (2) modifies the session's record in the 
session store by adding the CSRF token for the login password 
entry form to the session's database record.

The third request (3) is intended to read the saved returnTo 
URL after successful password entry. A 302 redirect will send 
the browser to the remember returnTo URL.

Debug Use:

A timing race condition is possible where request (2) overwrites the
remember returnTo URL from request (1) when writing the CSRF token,
causing request (3) to redirect to a /redirecterror error page.

The series of tests will run continuously until the count is exceeded 
or the process is stopped with ctrl-C.

CAUTION: this adds 1 session record to the session store 
database for each iteration.

```bash
# command line example
TESTENV_RT_COUNT=1 TESTENV_RT_PERIODMS=1000 node ./debug/redirect-timing-debug.js
```

```bash
# Recommended test configuration
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
TESTENV_RT_COUNT=1
TESTENV_RT_PERIODMS=1000
```

### debug/load-test-introspect.js

This module will obtain an access_token, then spawn a collection of 
concurrent asynchronous requests to POST /oauth/introspect, checking 
token signature and looking up token meta-data in the database.
It will calculate the rate in requests/second.

Environment variables

- TESTENV_LT_COUNT - Number of requests to send during testing (default 10)
- TESTENV_LT_PERIODMS - If 0, send requests at maximum rate, if > 0, limit rate, value of milliseconds/request (default 0).

Command configuration may be included in the .env file, or they may precede the command line as shown below.

```bash
TESTENV_LT_COUNT=25 TESTENV_LT_PERIODMS=40 node debug/load-test-introspect.js
```

Example response
```
Test: 4 Spawn multiple asynchronous /oauth/introspect requests
     Requested:  100
     Launched:   100
     Completed:  100
     Errors:     0
     Elapsed:    0.337 seconds
     Rate:       296.7 requests/second
```

```bash
# Recommended settings
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
# Number of requests to send during testing (default 10)
TESTENV_LT_COUNT=10
# If 0, send requests at maximum rate
# if > 0, limit rate, value of milliseconds/request (default 0)
TESTENV_LT_PERIODMS=0
```

## Command Line Test Execution

Some tests use npm modules located in the node_modules folder,
so `npm install` must be run before executing the tests.

Tests must be executed from the base folder of 
the repository by including the "debug" folder
in the filename.

```bash
node ./debug/access-token-client.js
node ./debug/access-token-user.js
node ./debug/admin-access-check.js
node ./debug/admin-client-edit.js
node ./debug/admin-disabled.js
node ./debug/admin-scope-check.js
node ./debug/admin-user-edit.js
node ./debug/client-grant-demo.js
node ./debug/code-grant-demo.js
node ./debug/cookie-tests.js
node ./debug/load-test-introspect.js
node ./debug/login-form-submission.js
node ./debug/protected-routes.js
node ./debug/public-routes.js
node ./debug/rate-limit.js
node ./debug/redirect-timing-debug.js
```

## Test runner.sh bash script

The folder includes a bash script that will run all the test modules in sequence.
The script will pause for 5 seconds between each test to provide an opportunity
to review data and/or to abort the tests using ctrl-C.

For various different test configurations, the script will stop the collab-auth
server, issue new environment variables, then restart the server.
For this to work properly, a folder is needed to store the server process PID.
The default is `~/tmp` in the user's home directory.
The PID folder must exist. An alternate PID folder may be specified
as an environment variables, such as `PID_DIR=/home/user/somewhere`

In the example-clients-db.json file, the first client ("clientId": "abc123")
has proper scope and callback redirect URI to work properly.
The trustedClient is set to false, but this may be changed to true before testing.

In the example-users-db.json, the first user ("username": "bob")
as the necessary user role ("auth.token", "user.admin") needed to run the tests.

The program's default settings should be sufficient to the use the runner script
provided the following bare installation is performed:

- Clone git repository to empty folder
- Install NPM dependencies
- Copy example-clients-db.json to clients-db.json (edit trustedClient if needed)
- Copy example-users-db.json to users-db.json
- Create an empty .env file
- Create a temporary folder `~/tmp` in the user's home directory to hold process PID

Do not start the web server. The script will start the web server automatically.
Start the script from the repository base folder using:

```bash
./debug/runner.sh
```

The runner execution time is approximately 7 to 8 minutes.

#### Using runner.sh bash script with PostgreSQL database

If the authentication web server is running on a different host
from the location of the test scripts, the auth server may be specified
using the TESTENV_AUTHURL environment variable.

```
TESTENV_AUTHURL=http://192.168.100.100:3000
```

When running with the PostgreSQL database, the user and client 
accounts must be configured for use in testing.

Option 1

By default, the first client account in clients-db.json and 
the first user account (index 0) in users-db.json are used for testing.
Both of these accounts must exist in the PostgreSQL database
with equivalent values for both user and client accounts.

Option 2

If the accounts are not the first account in the clients-db.json 
or users-db.sjon file, then the environment variables in the .env file 
may be used to specify the index within the files, starting from index 0.

```
TESTENV_CLIENTINDEX=3
TESTENV_USERINDEX=5
```

Option 3

The account values stored in the PostgreSQL database may be
explicitly specified in environment variables or in the .env file.

TESTENV_CLIENTID=client1234
TESTENV_CLIENTSECRET=xxxxxxxxxx
TESTENV_REDIRECTURI=http://192.168.100.100:3000/login/callback
TESTENV_TRUSTEDCLIENT=false
TESTENV_USERNAME=user4568
TESTENV_PASSWORD=xxxxxxxxx

## Compatibility with server configuration options

The test scripts will incorporate expected values that are
derived from the authorization server configuration files,
client account database and user account database.

The test scripts contain conditional elements where various tests 
may be skipped, or expected values may be configuration dependant.
The following different authorization server configuration options
are supported and should execute the tests without error


| Configuration Option               |   |   |   |   |   |   |   |   |
| ---------------------------------- | - | - | - | - | - | - | - | - |
| .env DATABASE_ENABLE_POSTGRES      | F | F | T | T | F | F | T | T |
| .env SESSION_ENABLE_POSTGRES       | F | F | T | T | F | F | T | T |
| .env SESSION_SET_ROLLING_COOKIE    | F | T | F | T | F | T | F | T |
| clients-db.json trustedClient      | F | F | F | F | T | T | T | T |

Cookie and access_token expiration time may be tested by configuring the 
following expiration times in seconds in the .env file.
This will enable various timers which will make the test pause and run slowly.

| Configuration Option                        |    |
| ------------------------------------------- | -- |
| .env OAUTH2_AUTH_CODE_EXPIRES_IN_SECONDS    | 8  |
| .env OAUTH2_TOKEN_EXPIRES_IN_SECONDS        | 10 |
| .env REFRESH_TOKEN_EXPIRES_IN_SECONDS       | 15 |
| .env OAUTH2_CLIENT_TOKEN_EXPIRES_IN_SECONDS | 10 |
| .env SESSION_EXPIRE_SEC                     | 8  |

The program includes a network request rate limiter that uses
the express-rate-limit middleware. The default is 10 requests 
per hour for GET /login and POST /login routes.
Exceeding the limit will return a 429 status response.
The following may be set in the .env file to disable this feature
by setting 1000 requests per hour.

```
LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
LIMITS_WEB_RATE_LIMIT_COUNT=1000
```

## Environment Variable Overrides

The following environment variables may be used to override the configuration 
defined in the .env file. Changing these values will not impact the actual 
server configuration. Rather, it is intended to allow adhoc substitution
of expected test result values. For example if the configured username 
is set to "bob" in the server configuration, the value "bob" will be imported
from the configuration for automatic use in the tests.
The section above describing the "runner.sh" bash script includes and example.
In order to allow adhoc testing without having to change the configuration
files each time, adhoc values may be prepended on the command line
like the following example:

```bash
TESTENV_USERNAME=bob2 node debug/code-grant-demo.js
```

Default values (For further info, see README in base repository folder, or /docs/)

```bash
TESTENV_AUTHURL=http://127.0.0.1:3500

TESTENV_CLIENTINDEX=0
TESTENV_USERINDEX=0

TESTENV_CLIENTID=abc123
TESTENV_CLIENTSECRET=ssh-secret
TESTENV_TRUSTEDCLIENT=false
TESTENV_REDIRECTURI=http://localhost:3000/login/callback
TESTENV_REDIRECTURIINDEX=0

TESTENV_USERNAME=bob
TESTENV_PASSWORD=bobssecret
```

| imported variable        | Env Var override         | Default value                                                             |
| ------------------------ | ------------------------ | ------------------------------------------------------------------------- |
| testEnv.authURL          | TESTENV_AUTHURL          | config.site.authURL                                                       |
| testEnv.clientIndex      | TESTENV_CLIENTINDEX      | 0                                                                         |
| testEnv.userIndex        | TESTENV_USERINDEX        | 0                                                                         |
| testEnv.clientId         | TESTENV_CLIENTID         | clients[testEnv.clientIndex].clientId                                     |
| testEnv.clientSecret     | TESTENV_CLIENTSECRET     | clients[testEnv.clientIndex].clientSecret                                 |
| testEnv.trustedClient    | TESTENV_TRUSTEDCLIENT    | clients[testEnv.clientIndex].trustedClient                                |
| testEnv.redirectURI      | TESTENV_REDIRECTURI      | clients[testEnv.clientIndex].allowedRedirectURI[testEnv.redirectURIIndex] |
| testEnv.redirectURIIndex | TESTENV_REDIRECTURIINDEX | 0                                                                         |
| testEnv.username         | TESTENV_USERNAME         | users[testEnv.userIndex].username                                         |
| testEnv.password         | TESTENV_PASSWORD         | users[testEnv.userIndex].password                                         |

Example command line override:

```bash
TESTENV_CLIENTSECRET="wrong_secret" node debug/code-grant-demo.js
```

## Command line arguments

Execution of the debug test scripts will basically list
a passing result for each test. Setting these environment
variables from the command line will show additional 
information during test execution.

| Environment  | Description                                |
| ------------ | ------------------------------------------ |
| SHOWRES=1    | Print raw response body for each request   |
| SHOWRES=2    | Print response headers for each request    |
| SHOWRES=3    | Print both body and headers each request   |
| SHOWTOKEN=1  | Print JWT payload                          |
| SHOWTOKEN=2  | Print JWT introspect meta-data             |
| SHOWTOKEN=3  | Print JWT payload and introspect meta-data |
| SHOWCOOKIE=1 | Print request, response cookie             |

### For debugging writing of new tests

| Environment  | Description                                |
| ------------ | ------------------------------------------ |
| SHOWCHAIN=1  | Print chain object at end of tests (debug) |
| SHOWCHAIN=2  | Print chain object after each test (debug) |
| SHOWSTACK=1  | Error handler print stack                  |

Command line example:

```bash
SHOWRES=3 SHOWTOKEN=3 SHOWCOOKIE=1 SHOWSTACK=1 node debug/access-token-client.js
```

## Structure of JavaScript test files

Each test file contains a series of tests that are run sequentially.
The results of each test are available for use in subsequent tests.
Since the network fetch operations are run asynchronously,
the network requests are embedded in a chain of promises, where
various promises resolve after the network request has been 
completed and the response values parsed. The following pseudo code
shows the approach to a chain of tests.

```js
// ...
  .then((chain) => {
    // Set various fetch related variables
    chain.requestMethod = 'GET';
    chain.requestFetchURL = '/some/route/

    // Set any relevant testing variables
    chain.someVariables = someValue;

    // Resolved promise passes chain object to managedFetch function
    return Promise.resolve(chain)

  // The debug/modules/managed-fetch.js module is called.
  .then((chain) => managedFetch(chain))

  .then((chain) => {
    // Evaluate the results of the fetch operation
    if (chain.someValue === 'expected result') {
      doSomething()
    }

    // Assertion testing
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);

    // Parse data for future requests
    chain.parsedCsrfToken =
      chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];

    // Continue to the next test
    return Promise.resolve(chain)
  })
  // ...
  ```

## General Test Logic Concepts

The primary purpose in writing collab-auth was to learn the 
how the OAuth 2.0 authorization code grant works.
In order to understand some of the JavaScript files in the /debug/
folder, it is necessary to consider the overall authorization code workflow.
There are two client account configuration possible, trusted and untrusted clients.

In the case of trusted clients, after the user enters their username and password
to authenticate their identity, the server will return an authorization code 
that may be exchanged for an access token.

In the case of untrusted client account configuration, after password submission,
the user will be presented with a second form to inform the user that a
specific application is requesting permission to access a specific resource.
This requires a "Yes" or "No" response from the user before returning
the authorization code that can exchanged for an access token.

The workflow generally works as follows:

```
    / Browser \
   | Redirect  |
    \         /    
        |
        | -------------------------- < -----------------------------
        |/                                                          \
        |                                                            |
        |                                                           YES
                                                                     |
    /   Is   \                  / Get  \       / Submit \        /        \
   |  cookie  |  -- NO -- > -- |  Login | --> | Password |  --- | Correct? |
    \ valid? /                  \ Form /       \        /        \        /
        |                           |                                |
        |                            \                               NO
       YES                             -------------- < ------------/
        |
   /    Is    \                 /  Get   \       / User  \
  |   Client   | -- NO -- > -- | Decision | --> | Enters  | -- NO ---\
   \ Trusted? /                 \  Form  /       \ "Yes" /            |
        |                                            |            / Redirect \
        |                                           YES          |  Error to  |
        |                                            |            \ Browser  /
        | ----------------- < ----------------------/
        |/ 
        |
        |
   / Redirect \
  | With Auth  |
   \  Code    /

```

The JavaScript test files in the /debug/ folder include conditional tests 
for both trusted and untrusted clients. Specific tests will be performed,
or skipped, depending on authorization server configuration values, and 
OAuth 2 client account settings.

The approach generally follows the following logic:

```
Case 1: Trusted client
Case 2: Untrusted client

    (Read server config for test)
    (Read client account values for test)
    (Read user account values for test)
                |
          (Start test)
                |
      (GET /dialog/authorize)
                |
                |
        [ Client Trusted ? ]
               /\
              /  \
             /    \
    (1) Yes /      \ No (2) Present user with additional resource permission form
           /        \
          /     (Parse CSRF token)
          \   (Parse transaction ID)
           \        /
            \      /
             \    /
              \  /
          [ Trusted ? ]
              /  \
             /    \
    (1) Yes /      \ No (2) Requires user to submit resource permission "Yes" or "No"
           /        \
          /          \
         |        (POST  /dialog/authorize/decision)
          \         /
           \       /
            \     /
             \   /
              \ /
               |
               |        Both Trusted and Untrusted client are handled
               |        the same from here on.
               |
  (parse Oauth 2 authorization code)
  (parse Oauth 2 state nonce)
               |
               |
       (Optional Timer)   Timer used to test authorization code expired
               |
               |
      (POST /oauth/token)
               |
               |
      (parse JWT access token)
      (parse JWT refresh token)
               |
               |
       (Optional Timer)   Timer used to test access token expired
               |
               |
      (POST /oauth/introspect)  Access token submitted to auth server for validation
               |
      (Parse token meta-data)
               |
        [ Token valid? ]         Evaluate test results

```

Optional tests: Certain tests will be optionally performed or skipped 
depending on the server configuration. For example, if an access token
is set to expire in 1 year, this would not be testable.
However, the configuration time for the expiration time could be set
to a temporary value, such as expire in 10 seconds, to make the test practical.
Therefore, certain test require a specific configuration to enable the 
test, else it is disabled. The environment variables that are required
to perform conditional tests are listed in this file.
