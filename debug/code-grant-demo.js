// code-grant-demo.js
//
// This API test set is used to demonstrate and test the OAuth2
// authorization code grant workflow. Learning about the code-grant-demo
// module was the main purpose of the project. It is the most complex
// OAuth 2.0 workflow, and difficult to understand. This is a step by
// step execution of the authorization handshakes using authorization
// code grant. This script incorporates use of refresh_tokens that are
// used to replaced expired access_token.
//
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
  // 2 GET /dialog/authorize - Authorization Check #1 (before login)
  //
  // At this stage, the request is made WITHOUT a valid cookie.
  // The authorization server will store full request URL with query parameters
  // into the user's session. A 302 redirect will tell the browser
  // to load the login password entry form. The 302 redirect response
  // will include a cookie to identify the session.
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '2 GET /dialog/authorize - Authorization Check #1 (before login)';
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
    //
    // Parse Data
    //
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 3 GET /login - Get login form
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
      '3 GET /login - Get login form';
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
    //
    // Parse Data
    //
    if (chain.responseStatus === 200) {
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      return Promise.resolve(chain);
    }
  })

  // -----------------------------------------------
  // 4 POST /login - Submit username and password
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
      '4 POST /login - Submit username and password';
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
  // 5 /dialog/authorize - Authorization Check #2 (after login)
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
      '5 /dialog/authorize - Authorization Check #2 (after login)';
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
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: body contains "<title>Resource Decision</title>"');
      assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
      console.log('\tExpect: body contains "name="_csrf""');
      assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
      console.log('\tExpect: body contains "name="transaction_id""');
      assert.ok(chain.responseRawData.indexOf('name="transaction_id"') >= 0);

      //
      // Parse Data
      //
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      chain.parsedTransactionId =
        chain.responseRawData.split('name="transaction_id"')[1].split('value="')[1].split('">')[0];
      return Promise.resolve(chain);
    } // untrusted client
  })

  // --------------------------------------------------------
  // 6 POST /dialog/authorize/decision - Submit accept/deny
  //
  // This request will confirm the user's acceptance
  // by submitting the transaction code and CSRF token.
  // The response will be a 302 redirect to the Oauth 2.0 callback URI
  // with an authorization code included in the 302 Location header.
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '6 POST /dialog/authorize/decision - Submit accept/deny';
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      chain.requestContentType = 'application/x-www-form-urlencoded';
      chain.requestBody = {
        transaction_id: chain.parsedTransactionId,
        _csrf: chain.parsedCsrfToken
        // Uncomment to emulate cancel button
        // cancel: 'deny'
      };
      delete chain.parsedTransactionId;
      return Promise.resolve(chain);
    } // untrusted client
  })
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      return managedFetch(chain);
    }
  })
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    // console.log('parsedLocationHeader: ', chain.parsedLocationHeader);
    console.log('\tExpect: parsedLocationHeader has authorization code');
    assert.ok(chain.parsedLocationHeader.indexOf('code=') >= 0);
    console.log('\tExpect: parsedLocationHeader header has state nonce');
    assert.ok(chain.parsedLocationHeader.indexOf('state=') >= 0);

    //
    // Parse Data
    //
    chain.parsedAuthCode =
      chain.parsedLocationHeader.split('code=')[1].split('&state')[0];
    chain.parsedStateNonce =
      chain.parsedLocationHeader.split('state=')[1];
    console.log('\tExpect: parsed state nonce match previous');
    assert.deepEqual(chain.parsedStateNonce, chain.randomStateNonce);
    if (testEnv.trustedClient) {
      console.log('\nTest: 6 Submit user accept/deny decision');
      console.log('\tTest aborted, client account configuration trustedClient=true');
    }
    return Promise.resolve(chain);
  })

  // -----------------------------------------
  // 7 POST /oauth/token - Get access_token using authorization code
  //
  // In this request, the authorization code obtained
  // in step #6 will be set to the server.
  // In response to a valid authorization code,
  // the server will return both an OAuth 2.0 access_token
  // and a refresh_token in the body of the response.
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '7 POST /oauth/token - Get access_token using authorization code';
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
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: Content-type === "application/json"');
    assert.strictEqual(chain.parsedContentType, 'application/json');
    console.log('\tExpect: response has access_token property');
    assert.ok(Object.hasOwn(chain.responseRawData, 'access_token'));
    if (!config.oauth2.disableRefreshTokenGrant) {
      console.log('\tExpect: response has refresh_token property');
      assert.ok(Object.hasOwn(chain.responseRawData, 'refresh_token'));
    }
    console.log('\tExpect: access_token 3 parts (xxx.xxx.xxx)');
    assert.strictEqual(chain.responseRawData.access_token.split('.').length, 3);
    console.log('\tExpect: response token_type === "Bearer"');
    assert.strictEqual(chain.responseRawData.token_type, 'Bearer');
    console.log('\tExpect: response grantType === "authorization_code"');
    assert.strictEqual(chain.responseRawData.grant_type, 'authorization_code');
    //
    // Parse Data
    //
    chain.parsedAccessToken = chain.responseRawData.access_token;
    chain.parsedRefreshToken = chain.responseRawData.refresh_token;
    //
    // Show Token
    //
    showJwtToken(chain);

    return Promise.resolve(chain);
  })

  // ----------------------------------------------------------
  // 8 POST /oauth/introspect - Request access_token meta-data
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '8 POST /oauth/introspect - Request access_token meta-data';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    chain.requestBody = {
      access_token: chain.parsedAccessToken
    };
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
    console.log('\tExpect: active === true');
    assert.strictEqual(chain.responseRawData.active, true);
    console.log('\tExpect: value of client.clientId is as expected');
    assert.strictEqual(chain.responseRawData.client.clientId,
      testEnv.clientId);
    console.log('\tExpect: grant_type === "authorization_code"');
    assert.strictEqual(chain.responseRawData.grant_type, 'authorization_code');
    console.log('\tExpect: access_token scope is as expected');
    assert.deepStrictEqual(chain.responseRawData.scope, ['api.write']);
    //
    // Show meta-data
    //
    showJwtMetaData(chain);

    return Promise.resolve(chain);
  })

  // -----------------------------------------
  // 9 POST /oauth/token - Get new access_token using refresh_token
  // -----------------------------------------
  .then((chain) => {
    chain.parsedAccessToken = null;
    chain.testDescription =
      '9 POST /oauth/token - Get new access_token using refresh_token';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    if (config.oauth2.disableRefreshTokenGrant) {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    } else {
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
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: Content-type === "application/json"');
      assert.strictEqual(chain.parsedContentType, 'application/json');
      console.log('\tExpect: response has access_token property');
      assert.ok(Object.hasOwn(chain.responseRawData, 'access_token'));
      console.log('\tExpect: access_token 3 parts (xxx.xxx.xxx)');
      assert.strictEqual(chain.responseRawData.access_token.split('.').length, 3);
      console.log('\tExpect: response token_type === "Bearer"');
      assert.strictEqual(chain.responseRawData.token_type, 'Bearer');
      console.log('\tExpect: response grantType === "refresh_token"');
      assert.strictEqual(chain.responseRawData.grant_type, 'refresh_token');
      //
      // Parse Data
      //
      chain.parsedAccessToken = chain.responseRawData.access_token;
      //
      // Show Token
      //
      showJwtToken(chain);

      return Promise.resolve(chain);
    }
  })

  // ----------------------------------------------------------
  // 10 POST /oauth/introspect - Request and check access_token meta-data
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '10 POST /oauth/introspect - Request and check access_token meta-data';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    if (config.oauth2.disableRefreshTokenGrant) {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    } else {
      chain.requestAuthorization = 'basic';
      chain.requestAcceptType = 'application/json';
      chain.requestContentType = 'application/json';
      chain.requestBody = {
        access_token: chain.parsedAccessToken
      };
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: active === true');
      assert.strictEqual(chain.responseRawData.active, true);
      console.log('\tExpect: value of client.clientId is as expected');
      assert.strictEqual(chain.responseRawData.client.clientId,
        testEnv.clientId);
      console.log('\tExpect: grant_type === "refresh_token"');
      assert.strictEqual(chain.responseRawData.grant_type, 'refresh_token');
      console.log('\tExpect: access_token scope is as expected');
      assert.deepStrictEqual(chain.responseRawData.scope, ['api.write']);
      //
      // Show meta-data
      //
      showJwtMetaData(chain);

      return Promise.resolve(chain);
    }
  })

  // --------------------------------------------------
  // 11 POST /oauth/token/revoke - Revoke access_token and refresh_token
  // --------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '11 POST /oauth/token/revoke - Revoke access_token and refresh_token';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token/revoke');
    if (config.oauth2.disableRefreshTokenGrant) {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    } else {
      chain.requestAuthorization = 'basic';
      chain.requestAcceptType = 'application/json';
      chain.requestContentType = 'application/json';
      chain.requestBody = {
        access_token: chain.parsedAccessToken,
        refresh_token: chain.parsedRefreshToken
      };
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      return Promise.resolve(chain);
    }
  })

  // ----------------------------------------------------
  // 12 - POST /oauth/introspect - Confirm token revoked
  // ----------------------------------------------------
  .then((chain) => {
    chain.testDescription = '12 - POST /oauth/introspect - Confirm token revoked';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    if (config.oauth2.disableRefreshTokenGrant) {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    } else {
      chain.requestAuthorization = 'basic';
      chain.requestAcceptType = 'application/json';
      chain.requestContentType = 'application/json';
      chain.requestBody = {
        access_token: chain.parsedAccessToken
      };
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 401 });
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 401');
      assert.strictEqual(chain.responseStatus, 401);
      console.log('\tExpect: Server error message: Unauthorized');
      assert.ok(chain.responseErrorMessage.indexOf(', Unauthorized') >= 0);

      showJwtMetaData();
      return Promise.resolve(chain);
    }
  })

  // -----------------------------------------
  // 13 POST /oauth/token - Confirm refresh token revoked
  // -----------------------------------------
  .then((chain) => {
    chain.parsedAccessToken = null;
    chain.testDescription =
      '13 POST /oauth/token - Confirm refresh token revoked';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    if (config.oauth2.disableRefreshTokenGrant) {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    } else {
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
    }
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 403 });
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 403');
      assert.strictEqual(chain.responseStatus, 403);
      console.log('\tExpect: Server error message: Invalid refresh token');
      assert.ok(chain.responseErrorMessage.indexOf('Invalid refresh token') >= 0);

      showJwtToken();
      return Promise.resolve(chain);
    }
  })

  // ----------------------------------------------------------
  // 14 /dialog/authorize - Authorization check with valid cookie
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '14 /dialog/authorize - Authorization check with valid cookie';
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
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));

      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: body contains "<title>Resource Decision</title>"');
      assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
      console.log('\tExpect: body contains "name="_csrf""');
      assert.ok(chain.responseRawData.indexOf('name="_csrf"') >= 0);
      console.log('\tExpect: body contains "name="transaction_id""');
      assert.ok(chain.responseRawData.indexOf('name="transaction_id"') >= 0);

      //
      // Parse Data
      //
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      chain.parsedTransactionId =
        chain.responseRawData.split('name="transaction_id"')[1].split('value="')[1].split('">')[0];
      return Promise.resolve(chain);
    } // untrusted client
  })

  // --------------------------------------------------------
  // 15 POST /dialog/authorize/decision - Submit accept/deny
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '15 POST /dialog/authorize/decision - Submit accept/deny';
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      chain.requestContentType = 'application/x-www-form-urlencoded';
      chain.requestBody = {
        transaction_id: chain.parsedTransactionId,
        _csrf: chain.parsedCsrfToken
        // Uncomment to emulate cancel button
        // cancel: 'deny'
      };
      delete chain.parsedTransactionId;
      return Promise.resolve(chain);
    } // untrusted client
  })
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      return managedFetch(chain);
    }
  })
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    // console.log('parsedLocationHeader: ', chain.parsedLocationHeader);
    console.log('\tExpect: parsedLocationHeader has authorization code');
    assert.ok(chain.parsedLocationHeader.indexOf('code=') >= 0);
    console.log('\tExpect: parsedLocationHeader has state nonce');
    assert.ok(chain.parsedLocationHeader.indexOf('state=') >= 0);

    //
    // Parse Data
    //
    chain.parsedAuthCode =
      chain.parsedLocationHeader.split('code=')[1].split('&state')[0];
    chain.parsedStateNonce =
      chain.parsedLocationHeader.split('state=')[1];
    console.log('\tExpect: parsed state nonce match previous');
    assert.deepEqual(chain.parsedStateNonce, chain.randomStateNonce);
    if (testEnv.trustedClient) {
      console.log('\nTest: 15 Submit user accept/deny decision');
      console.log('\tTest aborted, client account configuration trustedClient=true');
    }
    return Promise.resolve(chain);
  })

  // -----------------------------------------
  // 16 POST /oauth/token - Get access_token using authorization code
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '16 POST /oauth/token - Get access_token using authorization code';
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
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: Content-type === "application/json"');
    assert.strictEqual(chain.parsedContentType, 'application/json');
    console.log('\tExpect: response has access_token property');
    assert.ok(Object.hasOwn(chain.responseRawData, 'access_token'));
    if (!config.oauth2.disableRefreshTokenGrant) {
      console.log('\tExpect: response has refresh_token property');
      assert.ok(Object.hasOwn(chain.responseRawData, 'refresh_token'));
    }
    console.log('\tExpect: access_token 3 parts (xxx.xxx.xxx)');
    assert.strictEqual(chain.responseRawData.access_token.split('.').length, 3);
    console.log('\tExpect: response token_type === "Bearer"');
    assert.strictEqual(chain.responseRawData.token_type, 'Bearer');
    console.log('\tExpect: response grantType === "authorization_code"');
    assert.strictEqual(chain.responseRawData.grant_type, 'authorization_code');
    //
    // Parse Data
    //
    chain.parsedAccessToken = chain.responseRawData.access_token;
    chain.parsedRefreshToken = chain.responseRawData.refresh_token;
    //
    // Show Token
    //
    showJwtToken(chain);

    return Promise.resolve(chain);
  })

  // ----------------------------------------------------------
  // 17 POST /oauth/introspect - Request and check access_token meta-data
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '17 POST /oauth/introspect - Request and check access_token meta-data';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
    chain.requestAuthorization = 'basic';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    chain.requestBody = {
      access_token: chain.parsedAccessToken
    };
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
    console.log('\tExpect: active === true');
    assert.strictEqual(chain.responseRawData.active, true);
    console.log('\tExpect: value of client.clientId is as expected');
    assert.strictEqual(chain.responseRawData.client.clientId,
      testEnv.clientId);
    console.log('\tExpect: grant_type === "authorization_code"');
    assert.strictEqual(chain.responseRawData.grant_type, 'authorization_code');
    console.log('\tExpect: access_token scope is as expected');
    assert.deepStrictEqual(chain.responseRawData.scope, ['api.write']);
    //
    // Show meta-data
    //
    showJwtMetaData(chain);

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
