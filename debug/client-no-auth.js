// client-no-auth.js
//
// This script will verify that client credentials grant requests 
// without proper authentication (clientId, clientSecret) are denied.
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
  testEnv,
  config,
  // clients,
  // users
} = require('./modules/import-config.js');

//
// Check if OAuth 2.0 grant type client credentials grant is disabled in configuration
//
if (config.oauth2.disableClientGrant) {
  // Yes, abort the test without error
  console.log('\nTest skipped, client credentials grant disabled in configuration.');
  console.log('---------------------');
  console.log('  All Tests Passed');
  console.log('---------------------');
  process.exit(0);
}

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
  //  100 POST /oauth/token - Request without authorization header
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '100 POST /oauth/token - Request without authorization header';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    chain.requestAuthorization = 'none';
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
    logRequest(chain, { ignoreErrorStatus: 401 });
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    // console.log('\n\n',chain.responseErrorMessage, '\n\n');
    console.log('\tExpect: status === 401');
    assert.strictEqual(chain.responseStatus, 401);
    console.log('\tExpect: error response contains "Unauthorized"');
    assert.ok(chain.responseErrorMessage.indexOf('Unauthorized') >= 0);
    return Promise.resolve(chain);
  })

  // -----------------------------------------
  // 101 POST /oauth/token - Request with invalid client ID
  // -----------------------------------------
  .then((chain) => {
    // Alter clientId by appending 'xyz';
    chain.requestBasicAuthCredentials =
      Buffer.from(testEnv.clientId + 'xyz' + ':' +
      testEnv.clientSecret).toString('base64');
    chain.testDescription =
      '101 POST /oauth/token - Request with invalid client ID';
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
    logRequest(chain, { ignoreErrorStatus: 401 });
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    // console.log('\n\n',chain.responseErrorMessage, '\n\n');
    console.log('\tExpect: status === 401');
    assert.strictEqual(chain.responseStatus, 401);
    console.log('\tExpect: error response contains "Unauthorized"');
    assert.ok(chain.responseErrorMessage.indexOf('Unauthorized') >= 0);
    return Promise.resolve(chain);
  })

  // -----------------------------------------
  // 102 POST /oauth/token - Request with invalid clientSecret
  // -----------------------------------------
  .then((chain) => {
    // Alter client secret by appending 'xyz';
    chain.requestBasicAuthCredentials =
      Buffer.from(testEnv.clientId + ':' +
      testEnv.clientSecret + 'xyz').toString('base64');
    chain.testDescription =
      '102 POST /oauth/token - Request with invalid clientSecret';
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
    logRequest(chain, { ignoreErrorStatus: 401 });
    // console.log(JSON.stringify(chain.responseRawData, null, 2));
    // console.log('\n\n',chain.responseErrorMessage, '\n\n');
    console.log('\tExpect: status === 401');
    assert.strictEqual(chain.responseStatus, 401);
    console.log('\tExpect: error response contains "Unauthorized"');
    assert.ok(chain.responseErrorMessage.indexOf('Unauthorized') >= 0);
    return Promise.resolve(chain);
  })  

  // -----------------------------------------
  // 103 POST /oauth/token - invalid base64 string
  // -----------------------------------------
  .then((chain) => {
    // Alter client secret by appending 'xyz';
    chain.requestBasicAuthCredentials =
      'x' +
      Buffer.from(testEnv.clientId + ':' +
      testEnv.clientSecret).toString('base64') + 'x';
    chain.testDescription =
      '103 POST /oauth/token - invalid base64 string';
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
    console.log('\tExpect: error response contains "Bad Request"');
    assert.ok(chain.responseErrorMessage.indexOf('Bad Request') >= 0);
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
