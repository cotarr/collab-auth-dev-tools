// password-grant-demo.js
//
// This API test set is used to demonstrate and test the OAuth2 password grant workflow.
//
// Note: The OAuth 2.0 "password grant" is considered deprecated. 
// It is considered insecure because it requires client applications
// to store the users password directly.
//
//    # Recommended test configuration
//    LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
//    LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
//    LIMITS_WEB_RATE_LIMIT_COUNT=1000
//
// The tests in this module were primarily written for the author
// to better understand the OAuth 2.0 client grant workflow.
//
// The tests are limited in scope and not comprehensive of all possible security risks.
// ---------------------------------------------------------------
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');

if (!fs.existsSync('./package.json')) {
  console.log('Must be run from repository base folder as: node debug/password-grant-demo.js');
  process.exit(1);
}

const {
  testEnv,
  config
  // clients,
  // users
} = require('./modules/import-config.js');

const managedFetch = require('./modules/managed-fetch').managedFetch;

//
// Check if OAuth 2.0 grant type password grant is disabled in configuration
//
if (config.oauth2.disablePasswordGrant) {
  // Yes, abort the test without error
  console.log('\nTest skipped, password grant disabled in configuration.');
  console.log('---------------------');
  console.log('  All Tests Passed');
  console.log('---------------------');
  process.exit(0);
}

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
  // ---------------------------------------------------------
  // 1 GET /status - Check authorization server is running
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '1 GET /status - Check authorization server is running';
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

  // -----------------------------------------
  // 2 POST /oauth/token - Get access_token using password grant
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
      '2 POST /oauth/token - Get access_token using password grant';
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
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    check404PossibleVhostError(chain);
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
    if (!config.oauth2.disableRefreshTokenGrant) {
      console.log('\tExpect: response has refresh_token property');
      assert.ok(Object.hasOwn(chain.responseRawData, 'refresh_token'));
    }
    console.log('\tExpect: response grant_type === "password"');
    assert.strictEqual(chain.responseRawData.grant_type, 'password');
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
  // 3 POST /oauth/introspect - Request and check access_token meta data
  //
  // This request will submit the access_token obtained in step #2
  // to the authentication server. A set of valid client credentials are
  // required to submit the request. The authentication server
  // will check the signature of the access token, if valid and
  // not expired, the meta-data associated with the access_token
  // will be looked up in the token database and returned in the response
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '3 POST /oauth/introspect - Request and check access_token meta data';
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
    assert.strictEqual(chain.responseRawData.client.clientId, testEnv.clientId);
    console.log('\tExpect: grant_type === "password"');
    assert.strictEqual(chain.responseRawData.grant_type, 'password');
    console.log('\tExpect: access_token scope is as expected');
    assert.deepStrictEqual(chain.responseRawData.scope, ['api.write']);
    //
    // Show meta-data
    //
    showJwtMetaData(chain);

    return Promise.resolve(chain);
  })

  // --------------------------------------------------
  // 4 POST /oauth/token/revoke - Revoke access token
  //
  // This request will revoke the access_token obtained
  // in step #3
  // --------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '4 POST /oauth/token/revoke - Revoke access token';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token/revoke');
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
    return Promise.resolve(chain);
  })

  // ----------------------------------------------------
  // 5 - POST /oauth/introspect - Confirm token revoked
  //
  // This request will attempt to use the revoked access_token
  // which should return a 401 Unauthorized response.
  // ----------------------------------------------------
  .then((chain) => {
    chain.testDescription = '5 - POST /oauth/introspect - Confirm token revoked';
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
    logRequest(chain, { ignoreErrorStatus: 401 });
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 401');
    assert.strictEqual(chain.responseStatus, 401);

    return Promise.resolve(chain);
  })

  // -----------------------------------------
  // 6 POST /oauth/token - Get new access_token using refresh_token
  // -----------------------------------------
  .then((chain) => {
    chain.parsedAccessToken = null;
    chain.testDescription =
      '6 POST /oauth/token - Get new access_token using refresh_token';
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
  // 7 POST /oauth/introspect - Request and check access_token meta-data
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '7 POST /oauth/introspect - Request and check access_token meta-data';
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
  // 8 POST /oauth/token/revoke - Revoke access_token and refresh_token
  // --------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '8 POST /oauth/token/revoke - Revoke access_token and refresh_token';
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
  // 9 - POST /oauth/introspect - Confirm token revoked
  // ----------------------------------------------------
  .then((chain) => {
    chain.testDescription = '9 - POST /oauth/introspect - Confirm token revoked';
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
  // 10 POST /oauth/token - Confirm refresh token revoked
  // -----------------------------------------
  .then((chain) => {
    chain.parsedAccessToken = null;
    chain.testDescription =
      '10 POST /oauth/token - Confirm refresh token revoked';
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
 
  //
  // For Debug, show chain object
  //
  .then((chain) => showChain(chain))

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
