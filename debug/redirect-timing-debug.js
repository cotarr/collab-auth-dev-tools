// redirect-timing-debug
//
// This script is custom debug tool used to debug redirect
// errors that occur after user's password entry.

// The first request (1) modifies the session's record in the
// session store by adding a returnTo property to the session
// with the full URL of the unauthorized request.

// The second request (2) modifies the session's record in the
// session store by adding the CSRF token for the login password
// entry form to the session's database record.

// The third request (3) is intended to read the saved returnTo
// URL after successful password entry. A 302 redirect will send
// the browser to the remember returnTo URL.

// Debug Use:

// A timing race condition is possible where request (2) overwrites the
// remember returnTo URL from request (1) when writing the CSRF token,
// causing request (3) to redirect to a /redirecterror error page.

// The series of tests will run continuously until the count is exceeded
// or the process is stopped with ctrl-C.

// CAUTION: this adds 1 session record to the session store
// database for each iteration.
//
// ```bash
// # command line example
// TESTENV_RT_COUNT=1 TESTENV_RT_PERIODMS=1000 node ./debug/redirect-timing-debug.js
// ```

// ```bash
// # Recommended test configuration
// LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
// LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
// LIMITS_WEB_RATE_LIMIT_COUNT=1000
// TESTENV_RT_COUNT=1
// TESTENV_RT_PERIODMS=1000
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
  console.log('Must be run from repository base folder as: node debug/redirect-timing.js');
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
  // showJwtToken,
  // showJwtMetaData
  check404PossibleVhostError
} = require('./modules/test-utils');

const chainObj = Object.create(null);

/**
 * Console log elapsed time for each test
 * @param {Object} chain - Chain object holding common variables
 * @return {Promise} resolving to modified chain object
 */
const showTime = (chain) => {
  console.log('\tElapsed = ' + (Date.now() - chain.startTimeMs).toString() + ' ms');
  return Promise.resolve(chain);
};

/**
 * Initialize shared variables used in chain of promises
 * @param {Object} chain - Data variables passed from promise to promise.
 * @returns {Promise} resolving to chain object
 */
const setup = (chain) => {
  chain.startTimeMs = Date.now();
  chain.requestAuthorization = 'cookie';
  chain.requestAcceptType = 'text/html';
  return Promise.resolve(chain);
};

let errorAbortFlag = false;
let testActiveFlag = false;

/**
 * Wrapper for repetitive execution using timer
 */
const repeatTest = () => {
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
    .then((chain) => showTime(chain))
    // -------------------------------
    // 1 GET /panel/menu - Unauthenticated request to protected route.
    // -------------------------------
    .then((chain) => {
      chain.testDescription = '1 GET /panel/menu - Unauthenticated request to protected route.';
      chain.requestMethod = 'GET';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/menu');
      return Promise.resolve(chain);
    })
    .then((chain) => managedFetch(chain))
    //
    // Assertion Tests...
    //
    .then((chain) => {
      logRequest(chain);
      // console.log(chain.responseRawData);
      check404PossibleVhostError(chain);
      console.log('\tExpect: status === 302 (Redirect)');
      assert.strictEqual(chain.responseStatus, 302);
      console.log('\tExpect: Location header redirects to GET /login');
      assert.strictEqual(chain.parsedLocationHeader, '/login');
      console.log('\tExpect: Response returns set-cookie header');
      assert.ok(((chain.parsedSetCookieHeader != null) &&
        (chain.parsedSetCookieHeader.length > 0)));
      return Promise.resolve(chain);
    })
    .then((chain) => showTime(chain))

    // -------------------------------
    // 2 GET /login - Login form with csrf token
    // -------------------------------
    .then((chain) => {
      chain.testDescription =
        '2 GET /login - Login form with csrf token';
      chain.requestMethod = 'GET';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
      return Promise.resolve(chain);
    })
    .then((chain) => managedFetch(chain))
    //
    // Assertion Tests...
    //
    .then((chain) => {
      logRequest(chain);
      // console.log(chain.responseRawData);
      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      //
      // Parse Data
      //
      if (chain.responseStatus === 200) {
        chain.parsedCsrfToken =
          chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      }
      return Promise.resolve(chain);
    })
    .then((chain) => showTime(chain))

    //
    // -----------------------------------------------
    // 3 POST /login - Submit user login password
    // -----------------------------------------------
    .then((chain) => {
      chain.testDescription = '3 POST /login - Submit user login password';
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
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
      // console.log(chain.responseRawData);
      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      //
      // Exit on redirect error
      //
      if (chain.parsedLocationHeader === '/redirecterror') {
        console.log('Error: unexpected 302 redirect to /redirecterror');
        process.exit(0);
      }
      console.log('\tExpect: Response includes set-cookie header');
      assert.ok(((chain.parsedSetCookieHeader != null) &&
        (chain.parsedSetCookieHeader.length > 0)));
      console.log('\tExpect: Redirect URI matches /panel/menu');
      assert.strictEqual(chain.parsedLocationHeader, '/panel/menu');
      console.log('\tExpect: Session cookie replaced after successful login');
      assert.notEqual(
        chain.tempLastSessionCookie,
        chain.parsedSetCookieHeader);
      // Temporary variable no longer needed
      delete chain.tempLastSessionCookie;
      return Promise.resolve(chain);
    })
    .then((chain) => showTime(chain))

    // -------------------------------
    // 4 GET /panel/menu
    // -------------------------------
    .then((chain) => {
      chain.testDescription = '4 GET /panel/menu';
      chain.requestMethod = 'GET';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/menu');
      return Promise.resolve(chain);
    })
    .then((chain) => managedFetch(chain))
    .then((chain) => {
      logRequest(chain);
      // console.log(chain.responseRawData);
      if (chain.responseStatus === 302) {
        console.log('\tWarning: 302 with location header:', chain.parsedLocationHeader);
      }
      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: Response body contains: <title>Web Admin Panel</title>');
      assert.ok(chain.responseRawData.indexOf('<title>Web Admin Panel</title>') >= 0);
      return Promise.resolve(chain);
    })
    .then((chain) => showTime(chain))

    // -------------------------------
    // 5 GET /logout
    // -------------------------------
    .then((chain) => {
      chain.testDescription = '// 5 GET /logout';
      chain.requestMethod = 'GET';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/logout');
      return Promise.resolve(chain);
    })
    .then((chain) => managedFetch(chain))
    .then((chain) => {
      logRequest(chain);
      // console.log(chain.responseRawData);
      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      console.log('\tExpect: Response body contains "<title>Collab-auth Logout</title>"');
      assert.ok(chain.responseRawData.indexOf('<title>Collab-auth Logout</title>') >= 0);
      chain.currentSessionCookie = null;
      return Promise.resolve(chain);
    })
    .then((chain) => showTime(chain))

    //
    // For Debug, show chain object
    //
    .then((chain) => showChain(chain))

    //
    // Assert did not exit, assume all tests passed
    //
    .then((chain) => {
      console.log();
      console.log('Redirect Timing test ' + counter.toString() + ' passed passed');
      console.log();
    })

    //
    // In normal testing, no errors should be rejected in the promise chain.
    // In the case of hardware network errors, catch the error.
    .catch((err) => {
      showHardError(err);
      errorAbortFlag = true;
    });
}; // repeatTest();

const countLimit = testEnv.redirectTiming.countLimit;
const periodMs = testEnv.redirectTiming.periodMs;
let counter = 0;

if (countLimit < 1) {
  console.error('Error, countLimit is zero, test must be run at least one time');
  process.exit(1);
}

/**
 * Function to serve as setInterval() looped function, providing loop exit conditions.
 */
const loopFunction = () => {
  if (counter >= countLimit) {
    console.log('---------------------');
    console.log('  All Tests Passed');
    console.log('---------------------');
    process.exit(0);
  }
  if (errorAbortFlag) {
    console.log('Cycle timer aborted due to errors');
    process.exit(1);
  }
  if (testActiveFlag === true) {
    console.log('Error, overlapping tests');
  }
  testActiveFlag = true;
  repeatTest();
  counter++;
  testActiveFlag = false;
};

//
// Run the tests loop
//
console.log(testEnv);
repeatTest();
counter++;
// Loop timer for running tests
setInterval(loopFunction, periodMs);
