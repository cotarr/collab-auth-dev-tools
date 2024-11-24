// client-grant-demo.js
//
// This API test set is used to demonstrate and test the OAuth2 client credentials
// grant workflow. Client grant is the simplest Oauth 2.0 workflow. A new
// access token can be obtained using a single POST request where client
// credentials are exchanged for an access token.
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
  console.log('Must be run from repository base folder as: node debug/client-grant-demo.js');
  process.exit(1);
}

const {
  testEnv
  // config,
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
  // 2 POST /oauth/token - Get access_token using client credentials
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
      '2 POST /oauth/token - Get access_token using client credentials';
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
    console.log('\tExpect: response grantType === "client_credentials"');
    assert.strictEqual(chain.responseRawData.grantType, 'client_credentials');
    //
    // Parse Data
    //
    chain.parsedAccessToken = chain.responseRawData.access_token;
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
    console.log('\tExpect: grant_type === "client_credentials"');
    assert.strictEqual(chain.responseRawData.grant_type, 'client_credentials');
    console.log('\tExpect: access_token scope is as expected');
    assert.deepStrictEqual(chain.responseRawData.scope, ['api.read', 'api.write']);
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
