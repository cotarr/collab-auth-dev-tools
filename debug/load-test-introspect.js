// load-test-introspect.js
//
// This module will obtain an access_token, then spawn a collection of
// concurrent asynchronous requests to POST /oauth/introspect, checking
// token signature and looking up token meta-data in the database.
// It will calculate the rate in requests/second.
//
// Environment variables
//
// TESTENV_LT_COUNT - Number of requests to send during testing (default 10)
// TESTENV_LT_PERIODMS - If 0, send requests at maximum rate,
//    if > 0, limit rate, value of milliseconds/request (default 0).
//
// Command configuration may be included in the .env file,
// or they may precede the command line as shown below.
//
//     TESTENV_LT_COUNT=25 TESTENV_LT_PERIODMS=40 node debug/load-test-introspect.js
//
// Example response:
//
// Test: 4 Spawn multiple asynchronous /oauth/introspect requests
//      Requested:  100
//      Launched:   100
//      Completed:  100
//      Errors:     0
//      Elapsed:    0.337 seconds
//      Rate:       296.7 requests/second
//
// Configuration
//
//    # Recommended settings
//    LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
//    LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
//    LIMITS_WEB_RATE_LIMIT_COUNT=1000
//    # Number of requests to send during testing (default 10)
//    TESTENV_LT_COUNT=10
//    # If 0, send requests at maximum rate
//    # if > 0, limit rate, value of milliseconds/request (default 0)
//    TESTENV_LT_PERIODMS=0
//
// The tests in this module were primarily written for the author
// to better understand how JWT tokens are verified by the Oauth 2.0 server.
//
// The tests are limited in scope and not comprehensive of all possible security risks.
// -----------------------------------------------------------
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');

if (!fs.existsSync('./package.json')) {
  console.log('Must be run from repository base folder as: node debug/load-test-introspect.js');
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
  // showChain,
  showHardError,
  showJwtToken,
  showJwtMetaData,
  check404PossibleVhostError
} = require('./modules/test-utils');

const countLimit = testEnv.loadTest.countLimit;
const periodMs = testEnv.loadTest.periodMs;
let launchedCount = 0;
let completedCount = 0;
let errorCount = 0;
let launchedDoneMs = 0;
const startTimeMs = Date.now(); // Milliseconds

const checkResult = () => {
  if ((launchedCount >= countLimit) &&
    (completedCount + errorCount >= countLimit)) {
    const launchedElapsedMs = launchedDoneMs - startTimeMs;
    const elapsedMSec = Date.now() - startTimeMs;

    let launchedElapsedMsStr = '';
    if (launchedCount > 0) {
      launchedElapsedMsStr = ' in ' + (launchedElapsedMs).toFixed(0) + ' ms (' +
        ((1000.0 * launchedCount) / launchedElapsedMs).toFixed(1) + ' req/sec, ' +
        (launchedElapsedMs / launchedCount).toFixed(3) + ' ms/req';
    }

    let completedStatsStr = '';
    if (completedCount > 0) {
      completedStatsStr = ' in ' +
      elapsedMSec.toFixed(0) + ' ms (' +
      (1000.0 * completedCount / elapsedMSec).toFixed(3) + ' req/sec, ' +
      (elapsedMSec / completedCount).toFixed(3) + ' ms/req)';
    }

    let errorStatsStr = '';
    if ((completedCount === 0) && (errorCount > 0)) {
      errorStatsStr = ' err in ' +
      elapsedMSec.toFixed(0) + ' ms (' +
      (1000.0 * errorCount / elapsedMSec).toFixed(3) + ' err/sec, ' +
      (elapsedMSec / errorCount).toFixed(3) + ' ms/err)';
    }

    console.log('\tLaunched:   ' + launchedCount.toString() + ' req' + launchedElapsedMsStr);
    console.log('\tCompleted:  ' + completedCount.toString() + ' req' + completedStatsStr);
    console.log('\tErrors:     ' + errorCount.toString() + errorStatsStr);
  }
};

const stackedAsyncIntrospect = (accessToken, count) => {
  const fSetup = (chain) => {
    chain.requestAuthorization = 'basic';
    chain.requestBasicAuthCredentials =
      Buffer.from(testEnv.clientId + ':' +
      testEnv.clientSecret).toString('base64');
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    return Promise.resolve(chain);
  };
  const fChainObj = Object.create(null);

  fSetup(fChainObj)
    .then((chain) => {
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/introspect');
      chain.requestBody = {
        access_token: accessToken
      };
      return Promise.resolve(chain);
    })
    .then((chain) => managedFetch(chain))
    //
    // Assertion Tests...
    //
    .then((chain) => {
      if (chain.responseStatus !== 200) throw new Error('Response status not 200');
      if (!chain.responseRawData.active) throw new Error('Token inactive');
      completedCount++;
      checkResult();
    })
    .catch(() => {
      // console.log(err.message || err.toString());
      errorCount++;
      checkResult();
    });
};

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
    console.log('\tExpect: response token_type === "Bearer"');
    assert.strictEqual(chain.responseRawData.token_type, 'Bearer');
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
    //
    // Show meta-data
    //
    showJwtMetaData(chain);

    return Promise.resolve(chain);
  })
  .then((chain) => {
    console.log('\nTest: 4 Spawn multiple asynchronous requests to /oauth/introspect');
    let periodStr = '';
    if (periodMs > 0) {
      periodStr = ' in ' + (countLimit * periodMs).toString() + ' ms (' +
        ((1000.0 * countLimit) / (periodMs * countLimit)).toFixed(1) + ' req/sec, ' +
        ((countLimit * periodMs) / countLimit).toFixed(3) + ' ms/req)';
    } else {
      periodStr = ' at maximum rate';
    }
    console.log('\tRequested:  ' + countLimit.toString() + ' req' + periodStr);
    //
    // Case of spawning requests as fast as possible
    // without an interval timer.
    //
    if (periodMs === 0) {
      for (let i = 0; i < countLimit; i++) {
        launchedCount++;
        launchedDoneMs = Date.now();
        stackedAsyncIntrospect(chain.parsedAccessToken, 1);
      }
      setTimeout(() => {
        console.log('---------------------');
        console.log('  All Tests Passed');
        console.log('---------------------');
      }, 1000);
    } else {
      //
      // Case of spawning requests at equal spaced intervals
      //
      function spawnRequest () {
        if (launchedCount < countLimit) {
          launchedCount++;
          launchedDoneMs = Date.now();
          stackedAsyncIntrospect(chain.parsedAccessToken, 1);
        } else {
          clearInterval(timerId);
          setTimeout(() => {
            console.log('---------------------');
            console.log('  All Tests Passed');
            console.log('---------------------');
          }, 1000);
        }
      }
      const timerId = setInterval(spawnRequest, periodMs);
    }
  })
  //
  // In normal testing, no errors should be rejected in the promise chain.
  // In the case of hardware network errors, catch the error.
  .catch((err) => showHardError(err));
