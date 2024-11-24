// public-routes.js
//
// This script will confirm that routes intended to be public are
// accessible when the browser does not provide a valid cookie.
// There are several html routes that must be accessible at all
// times for unauthenticated requests.
// This include access control forms, such as `/login` and `/logout`.
// Additional routes, such as `/status`, `robots.txt`,
// `/.well-known/security.txt`, `/not-found.html` and several css style files.
//
//    # Recommended test configuration
//    LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
//    LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
//    LIMITS_WEB_RATE_LIMIT_COUNT=1000
//        # Optional configuration (else test skipped)
//        SITE_SECURITY_CONTACT=security@example.com
//        SITE_SECURITY_EXPIRES="Fri, 1 Apr 2022 08:00:00 -0600"
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
  console.log('Must be run from repository base folder as: node debug/public-routes.js');
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
  // showChain,
  showHardError,
  // showJwtToken,
  // showJwtMetaData
  check404PossibleVhostError
} = require('./modules/test-utils');

const chainObj = Object.create(null);

const validateResponse = (chain, expectCode, expectLocation) => {
  const code = expectCode || 302;
  logRequest(chain, { ignoreErrorStatus: code });
  // console.log(chain.responseRawData);
  console.log('\tExpect: status === ' + code.toString());
  assert.strictEqual(chain.responseStatus, code);
  if (code === 302) {
    if (expectLocation == null) {
      console.log('\tExpect: Redirect URI matches /login');
      assert.strictEqual(chain.parsedLocationHeader, '/login');
    } else {
      console.log('\tExpect: Redirect URI matches ' + expectLocation);
      assert.strictEqual(chain.parsedLocationHeader, expectLocation);
    }
  }
  return Promise.resolve(chain);
};

/**
 * Initialize shared variables used in chain of promises
 * @param {Object} chain - Data variables passed from promise to promise.
 * @returns {Promise} resolving to chain object
 */
const setup = (chain) => {
  chain.requestAuthorization = 'cookie';
  chain.workingBasicAuthCredentials =
    Buffer.from(testEnv.clientId + ':' +
    testEnv.clientSecret).toString('base64');
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

  // -------------------------------
  // 100 GET /status
  // In app.js
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '100 GET /status';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/status');
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    // console.log(JSON.stringify(chain.responseRawData, null, 2));

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: status: "ok"');
    assert.strictEqual(chain.responseRawData.status, 'ok');
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 101 GET /.well-known/security.txt
  // In app.js
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '101 GET /.well-known/security.txt';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/.well-known/security.txt');
    chain.requestAcceptType = 'text/html';
    if (config.site.securityContact === '') {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
    }
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(chain.responseRawData);
      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);

      console.log('\tExpect: response include security contact email');
      assert.ok(chain.responseRawData.indexOf(config.site.securityContact) >= 0);
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 102 GET /robots.txt
  // In app.js
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '102 GET /robots.txt';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/robots.txt');
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(chain.responseRawData);
      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);

      console.log('\tExpect: response include "Disallow: /"');
      assert.ok(chain.responseRawData.indexOf('Disallow: /') >= 0);
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 103 GET /login
  // In site.js
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '103 GET /login';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(chain.responseRawData);
      check404PossibleVhostError(chain);
      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      // console.log('\tExpect: response include "Disallow: /"');
      // assert.ok(chain.responseRawData.indexOf('Disallow: /') >= 0);
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 104 GET /logout
  // In site.js
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '104 GET /logout';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/logout');
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(chain.responseRawData);
      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      // console.log('\tExpect: response include "Disallow: /"');
      // assert.ok(chain.responseRawData.indexOf('Disallow: /') >= 0);
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 105 GET /panel/unauthorized
  // In site.js
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '105 GET /panel/unauthorized';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/unauthorized');
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateResponse(chain, 200))

  // -------------------------------
  // 200 GET /css/dialog.css
  // Static file server in app.js
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '200 GET /css/dialog.css';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/css/dialog.css');
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateResponse(chain, 200))

  // -------------------------------
  // 201 GET /css/login.css
  // Static file server in app.js
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '201 GET /css/login.css';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/css/login.css');
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateResponse(chain, 200))

  // -------------------------------
  // 202 GET /css/password.css
  // Static file server in app.js
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '202 GET /css/password.css';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/css/password.css');
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateResponse(chain, 200))

  // -------------------------------
  // 203 GET /css/password.css
  // Static file server in app.js
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '203 GET /css/styles.css';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/css/styles.css');
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateResponse(chain, 200))

  // -------------------------------
  // 300 GET /not-found.html
  // Error Handler in app.js
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '300 GET /not-found.html (Error handler)';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/not-found.html');
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 404 });
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 404');
    assert.strictEqual(chain.responseStatus, 404);
    console.log('\tExpect: Error response includes "Not Found"');
    assert.ok(chain.responseErrorMessage.indexOf('Not Found') >= 0);
    return Promise.resolve(chain);
  })

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
