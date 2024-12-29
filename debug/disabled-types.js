// disabled-types.js
//
// This script will confirm that disabled grant types are 
// not functional when in a disabled state.  
//
//    # Required test configuration
//    OAUTH2_DISABLE_TOKEN_GRANT=true
//    OAUTH2_DISABLE_CODE_GRANT=true
//    OAUTH2_DISABLE_CLIENT_GRANT=true
//    OAUTH2_DISABLE_PASSWORD_GRANT=true
//    OAUTH2_DISABLE_REFRESH_TOKEN_GRANT=true
//    # Recommended test configuration
//    LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
//    LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
//    LIMITS_WEB_RATE_LIMIT_COUNT=1000
//
// The tests in this module were primarily written for the author
// to better understand the OAuth 2.0 authorization code grant workflow.
//
// The tests are limited in scope and not comprehensive of all possible security risks.
// ---------------------------------------------------------------
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');

if (!fs.existsSync('./package.json')) {
  console.log('Must be run from repository base folder as: node debug/code-grant-demo.js');
  process.exit(1);
}

const {
  testEnv,
  config
  // clients,
  // users
} = require('./modules/import-config.js');
const managedFetch = require('./modules/managed-fetch').managedFetch;
const {
  logRequest,
  showChain,
  showHardError,
  showJwtToken,
  showJwtMetaData,
  check404PossibleVhostError
} = require('./modules/test-utils');

const chainObj = Object.create(null);

/**
 * Initialize shared variables used in chain of promises
 * @param {Object} chain - Data variables passed from promise to promise.
 * @returns {Promise} resolving to chain object
 */
const setup = (chain) => {
  chain.requestAuthorization = 'none';
  chain.requestBasicAuthCredentials =
    Buffer.from(testEnv.clientId + ':' +
    testEnv.clientSecret).toString('base64');
  chain.parsedAccessToken = null;
  chain.parsedRefreshToken = null;
  return Promise.resolve(chain);
};

//
// Main Promise Chain
//
// Calling setup() returns a Promise to initialize variables.
// The resolved promise .then is used to call the next function
// returning the next promise in a chain of asynchronous promises.
// Each promise performs a testing function. Testing related values
// are stored in a shared object "chain".
// The chain object is the argument of each function.
// The modified chain object is returned by the resolved promise.
//
setup(chainObj)
  // -----------------------------------------------------
  // 1 GET /status - Check if server is running
  // -----------------------------------------------------
  .then((chain) => {
    chain.testDescription = '1 GET /status - Check if server is running';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/status');
    chain.requestAuthorization = 'none';
    chain.requestAcceptType = 'application/json';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    return Promise.resolve(chain);
  })

  // ----------------------------------------------------------
  // 50 GET /dialog/authorize - Authorization Check #1 (to get cookie)
  //
  // At this stage, the request is made WITHOUT a valid cookie.
  // The authorization server will store full request URL with query parameters
  // into the user's session. A 302 redirect will tell the browser
  // to load the login password entry form. The 302 redirect response
  // will include a cookie to identify the session.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '50 GET /dialog/authorize - Authorization Check #1 (to get cookie)';
    chain.requestMethod = 'GET';
    let query = '';
    chain.randomStateNonce = 'A' + Math.floor((Math.random() * 1000000)).toString();
    query += '?redirect_uri=' + testEnv.redirectURI;
    query += '&response_type=code';
    query += '&client_id=' + testEnv.clientId;
    query += '&scope=api.read api.write';
    query += '&state=' + chain.randomStateNonce;
    // save for future redirect
    chain.savedAuthorizationPath = encodeURI('/dialog/authorize' + query);
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize' + query);
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    check404PossibleVhostError(chain);
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/login"');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    console.log('\tExpect: response returned set-cookie');
    assert.ok((chain.parsedSetCookieHeader != null) && (chain.parsedSetCookieHeader.length > 0));
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 51 GET /login - Get login form (to get cookie)
  //
  // This request is expected to return a HTML login form for
  // the user to enter username and password. The form will
  // include an embedded CSRF token that must be submitted
  // with the username, password form submission. If the request
  // included a valid cookie, it will be returned in the response,
  // else a new cookie will be generated.
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '51 GET /login - Get login form (to get cookie)';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: body contains "<title>collab-auth</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>collab-auth</title>') >= 0);
    console.log('\tExpect: body contains "name="_csrf""');
    assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
    if (chain.responseStatus === 200) {
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      return Promise.resolve(chain);
    }
  })

  // -----------------------------------------------
  // 52 POST /login - Submit username and password (to get cookie)
  //
  // The submit button in the HTML form is intended
  // to submit the username, password, and CSRF token
  // to the authorization server using x-www-form-urlencoded
  // POST request. If the password is not valid, then a 302
  // redirect will tell the browser to reload a
  // new login form. If credentials are validated,
  // a 302 redirect will send the browser back to the original
  // authorization URL. The cookie will be used to retrieve
  // the original URL with query parameters from the user session.
  // Since the user authentication represents a change in
  // authentication identity, a new cookie and session will be created
  // and the new cookie sent in the 302 redirect response headers.
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '52 POST /login - Submit username and password (to get cookie)';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: testEnv.username,
      password: testEnv.password,
      _csrf: chain.parsedCsrfToken
    };
    // The user login represents a change in user authentication status
    // so a new session cookie will be issued. The old cookie is saved
    // to verify the change in a test.
    chain.tempLastSessionCookie = chain.currentSessionCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: Response includes set-cookie header');
    assert.ok(((chain.parsedSetCookieHeader != null) &&
      (chain.parsedSetCookieHeader.length > 0)));
    console.log('\tExpect: Session cookie replaced after successful login');
    assert.notEqual(
      chain.tempLastSessionCookie,
      chain.parsedSetCookieHeader);
    console.log('\tExpect: Redirect URI to match previously save value');
    assert.strictEqual(
      chain.savedAuthorizationPath,
      chain.parsedLocationHeader);
    // Temporary variable no longer needed
    delete chain.tempLastSessionCookie;
    return Promise.resolve(chain);
  })

  // ----------------------------------------------------------
  // 100 /dialog/authorize - Code Grant disabled check
  //
  // In this case, the authorization request is made with a valid cookie.
  // Depending on the configuration of the client account, two different
  // responses are possible. If the client is configured with
  // trustedClient=true, a 302 redirect to the Oauth 2.0 callback URI
  // with an authorization code included in the 302 Location header.
  // Alternately, if the client is configured with trustedClient=false,
  // the authentication request will return a HTML form for the user
  // to 'Accept' or 'Deny' the application to access the specified resource.
  // The form will also include an embedded CSRF token. An OAuth2.0
  // transaction code (random nonce) is also embedded in the form to
  // validate that the response is from the intended user.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '100 /dialog/authorize - Code Grant disabled check';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 400 });
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    // console.log('\n\n',chain.responseErrorMessage, '\n\n');

    console.log('\tExpect: status === 400');
    assert.strictEqual(chain.responseStatus, 400);
    console.log('\tExpect: error response contains "(code grant) is disabled"');
    assert.ok(chain.responseErrorMessage.indexOf('(code grant) is disabled') >= 0);
    return Promise.resolve(chain);
  })

  // -----------------------------------------
  // 101 /oauth/token - Code Grant disabled check
  //
  // In this request, the authorization code obtained
  // in step #6 will be set to the server.
  // In response to a valid authorization code,
  // the server will return both an OAuth 2.0 access_token
  // and a refresh_token in the body of the response.
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '101 /oauth/token - Code Grant disabled check';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    // No cookie, auth in body of request
    chain.requestAuthorization = 'none';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    chain.requestBody = {
      code: chain.parsedAuthCode,
      redirect_uri: testEnv.redirectURI,
      client_id: testEnv.clientId,
      client_secret: testEnv.clientSecret,
      grant_type: 'authorization_code'
    };
    delete chain.parsedTransactionId;
    delete chain.parsedAuthCode;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 400 });
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    // console.log('\n\n',chain.responseErrorMessage, '\n\n');


    console.log('\tExpect: status === 400');
    assert.strictEqual(chain.responseStatus, 400);
    console.log('\tExpect: error response contains "(code grant) is disabled"');
    assert.ok(chain.responseErrorMessage.indexOf('(code grant) is disabled') >= 0);
    return Promise.resolve(chain);
  })

  // -----------------------------------------
  // 102 POST /oauth/token - Refresh_token disabled check
  // -----------------------------------------
  .then((chain) => {
    chain.parsedAccessToken = null;
    chain.testDescription =
      '102 POST /oauth/token - Refresh_token disabled check';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    // No cookie, auth in body of request
    chain.requestAuthorization = 'none';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    chain.requestBody = {
      client_id: testEnv.clientId,
      client_secret: testEnv.clientSecret,
      grant_type: 'refresh_token',
      refresh_token: chain.parsedRefreshToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 400 });
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    // console.log('\n\n',chain.responseErrorMessage, '\n\n');

    console.log('\tExpect: status === 400');
    assert.strictEqual(chain.responseStatus, 400);
    console.log('\tExpect: error response contains "(Refresh token grant) is disabled"');
    assert.ok(chain.responseErrorMessage.indexOf('(Refresh token grant) is disabled') >= 0);
    return Promise.resolve(chain);
  })

  // ----------------------------------------------------------
  // 200 GET /dialog/authorize - Implicit Grant disabled check
  //
  // At this stage, the request is made WITHOUT a valid cookie.
  // The authorization server will store full request URL with query parameters
  // into the user's session. A 302 redirect will tell the browser
  // to load the login password entry form. The 302 redirect response
  // will include a cookie to identify the session.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '200 GET /dialog/authorize - Implicit Grant disabled check';
    chain.requestMethod = 'GET';
    let query = '';
    chain.randomStateNonce = 'A' + Math.floor((Math.random() * 1000000)).toString();
    query += '?redirect_uri=' + testEnv.redirectURI;
    query += '&response_type=token';
    query += '&client_id=' + testEnv.clientId;
    query += '&scope=api.read api.write';
    query += '&state=' + chain.randomStateNonce;
    // save for future redirect
    chain.savedAuthorizationPath = encodeURI('/dialog/authorize' + query);
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize' + query);
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 400 });
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    // console.log('\n\n',chain.responseErrorMessage, '\n\n');

    console.log('\tExpect: status === 400');
    assert.strictEqual(chain.responseStatus, 400);
    console.log('\tExpect: error response contains "(implicit grant) is disabled"');
    assert.ok(chain.responseErrorMessage.indexOf('(implicit grant) is disabled') >= 0);
    return Promise.resolve(chain);
  })

  // -----------------------------------------
  // 300 POST /oauth/token - Client Credentials Grant disabled check
  //
  // This will submit a set of client credentials
  // to the authentication server.
  // In the case where the credentials are valid
  // and the client account has sufficient scope
  // to issue access_tokens, a new access_token
  // will be generated and returned in the response.
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '300 POST /oauth/token - Client Credentials Grant disabled check';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    chain.requestAuthorization = 'basic';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    chain.requestBody = {
      grant_type: 'client_credentials',
      scope: 'api.read api.write'
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 400 });
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    // console.log('\n\n',chain.responseErrorMessage, '\n\n');

    console.log('\tExpect: status === 400');
    assert.strictEqual(chain.responseStatus, 400);
    console.log('\tExpect: error response contains "(client grant) is disabled"');
    assert.ok(chain.responseErrorMessage.indexOf('(client grant) is disabled') >= 0);
    return Promise.resolve(chain);
  })

  // -----------------------------------------
  // 400 POST /oauth/token - Password Grant disabled check
  //
  // This will submit POST request with a set of client
  // credentials as basic auth along with username and password 
  // in the form-urlencoded body to the authentication server.
  // In the case where the credentials are valid
  // and the client account has sufficient scope
  // to issue access_tokens, a new access_token and new refresh token
  // will be generated and returned in the response.
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '400 POST /oauth/token - Password Grant disabled check';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    chain.requestAuthorization = 'basic';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      grant_type: 'password',
      scope: 'api.read api.write',
      username: testEnv.username,
      password: testEnv.password    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 400 });
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    // console.log('\n\n',chain.responseErrorMessage, '\n\n');

    console.log('\tExpect: status === 400');
    assert.strictEqual(chain.responseStatus, 400);
    console.log('\tExpect: error response contains "(password grant) is disabled');
    assert.ok(chain.responseErrorMessage.indexOf('(password grant) is disabled') >= 0);
    return Promise.resolve(chain);
  })

  //
  // For Debug, show chain object
  //
  .then((chain) => showChain(chain))

  //
  // Assert did not exit, assume all tests passed
  //
  .then((chain) => {
    console.log('---------------------');
    console.log('  All Tests Passed');
    console.log('---------------------');
  })

  //
  // In normal testing, no errors should be rejected in the promise chain.
  // In the case of hardware network errors, catch the error.
  .catch((err) => showHardError(err));
