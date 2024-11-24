// rate-limit.js
//
// The collab-auth web server includes rate limiting on several of the routes.
// This script will subject the web server to repeated requests to confirm
// that future requests are rejected after the limits are exceeded.
// To run this script. specific rate limits are required.
//
//    # Required settings
//    LIMITS_PASSWORD_RATE_LIMIT_COUNT=4
//    LIMITS_TOKEN_RATE_LIMIT_COUNT=6
//    LIMITS_WEB_RATE_LIMIT_COUNT=16
//
// The tests in this module were primarily written for the author
// to better understand how JWT tokens are verified by the Oauth 2.0 server.
//
// The tests are limited in scope and not comprehensive of all possible security risks.
// -----------------------------------------------------------
'use strict';

const fs = require('node:fs');

if (!fs.existsSync('./package.json')) {
  console.log('Must be run from repository base folder as: node debug/rate-limit.js');
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
  // showJwtToken,
  // showJwtMetaData
  check404PossibleVhostError
} = require('./modules/test-utils');

if ((config.limits.passwordRateLimitCount !== 4) ||
  (config.limits.tokenRateLimitCount !== 6) ||
  (config.limits.webRateLimitCount !== 16)) {
  console.log('\nTo run this test you must configure:');
  console.log('\nLIMITS_PASSWORD_RATE_LIMIT_COUNT=4');
  console.log('LIMITS_TOKEN_RATE_LIMIT_COUNT=6');
  console.log('LIMITS_WEB_RATE_LIMIT_COUNT=16\n');
  process.exit(1);
}

//
// Initialize sequencer variables
//
let rateRequestLimiterNumber = 0;
let rateRequestCount = 0;
let rateRequestLimit = 0;
let rateRequestDone = true;
let rateRequestErrorCount = 0;

// -------------------------------
// GET /login
// -------------------------------
const getLoginForm = () => {
  const setup = (chain) => {
    return Promise.resolve(chain);
  };

  const chainObj = Object.create(null);
  setup(chainObj)
    .then((chain) => {
      chain.testDescription =
        '1 GET /login Request: ' +
        rateRequestCount.toString() + ' of ' + rateRequestLimit.toString();
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
      logRequest(chain, { ignoreErrorStatus: 429 });
      check404PossibleVhostError(chain);
      if ((rateRequestCount === 1) && (chain.responseStatus === 429)) {
        console.log('\nWarning: Received status 409 (Too many requests) on first iteration.');
        console.log(
          'You must restart the collab-auth server to reset rate counters before this test.\n');
        process.exit(1);
      }
      if (rateRequestCount > rateRequestLimit) {
        if (chain.responseStatus === 429) {
          console.log('\tExpect: status === 429 PASS (Blocked)');
        } else {
          console.log('\tExpect: status === 429 TEST FAILED');
          rateRequestErrorCount++;
        }
      } else {
        if (chain.responseStatus === 200) {
          console.log('\tExpect: status === 200 PASS');
        } else {
          console.log('\tExpect: status === 200 TEST FAILED');
          rateRequestErrorCount++;
        }
      }
    })
    .then((chain) => showChain(chain))
    .catch((err) => showHardError(err));
}; // getLoginForm()

// -------------------------------
// POST /login
// -------------------------------
const postLoginData = () => {
  const setup = (chain) => {
    return Promise.resolve(chain);
  };

  const chainObj = Object.create(null);
  setup(chainObj)
    .then((chain) => {
      chain.testDescription =
        '2 POST /login Request: ' +
        rateRequestCount.toString() + ' of ' + rateRequestLimit.toString();
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      chain.requestContentType = 'application/x-www-form-urlencoded';
      chain.requestBody = {
        username: 'xxxxxxxx',
        password: 'xxxxxxxxxxxx',
        _csrf: 'xxxxxxxxxxxxxxxxxxxx'
      };
      return Promise.resolve(chain);
    })
    .then((chain) => managedFetch(chain))
    //
    // Assertion Tests...
    //
    .then((chain) => {
      logRequest(chain, { ignoreErrorStatus: [403, 429] });
      if (rateRequestCount > rateRequestLimit) {
        if (chain.responseStatus === 429) {
          console.log('\tExpect: status === 429 PASS (Blocked)');
        } else {
          console.log('\tExpect: status === 429 TEST FAILED');
          rateRequestErrorCount++;
        }
      } else {
        if (chain.responseStatus === 403) {
          console.log('\tExpect: status === 403 PASS');
        } else {
          console.log('\tExpect: status === 403 TEST FAILED');
          rateRequestErrorCount++;
        }
      }
    })
    .then((chain) => showChain(chain))
    .catch((err) => showHardError(err));
}; // postLoginData()

// -------------------------------
// POST /dialog/authorize
// -------------------------------
const getDialogAuth = () => {
  const setup = (chain) => {
    return Promise.resolve(chain);
  };

  const chainObj = Object.create(null);
  setup(chainObj)
    .then((chain) => {
      chain.testDescription =
        '3 GET /dialog/authorize: ' +
        rateRequestCount.toString() + ' of ' + rateRequestLimit.toString();
      chain.requestMethod = 'GET';
      let query = '';
      chain.randomStateNonce = 'A' + Math.floor((Math.random() * 1000000)).toString();
      query += '?redirect_uri=' + testEnv.redirectURI;
      query += '&response_type=code';
      query += '&client_id=' + testEnv.clientId;
      query += '&scope=api.read api.write';
      query += '&state=' + chain.randomStateNonce;
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
      logRequest(chain, { ignoreErrorStatus: 429 });
      if (rateRequestCount > rateRequestLimit) {
        if (chain.responseStatus === 429) {
          console.log('\tExpect: status === 429 PASS (Blocked)');
        } else {
          console.log('\tExpect: status === 429 TEST FAILED');
          rateRequestErrorCount++;
        }
      } else {
        if (chain.responseStatus === 302) {
          console.log('\tExpect: status === 302 PASS');
        } else {
          console.log('\tExpect: status === 302 TEST FAILED');
          rateRequestErrorCount++;
        }
      }
    })
    .then((chain) => showChain(chain))
    .catch((err) => showHardError(err));
}; // getDialogAuth()

// -------------------------------
// POST /oauth/token
// -------------------------------
const postOauthToken = () => {
  const setup = (chain) => {
    chain.requestBasicAuthCredentials =
    Buffer.from('xxxxxxx:xxxxxxxxxxxxxxxx').toString('base64');
    return Promise.resolve(chain);
  };

  const chainObj = Object.create(null);
  setup(chainObj)
    .then((chain) => {
      chain.testDescription =
        '4 POST /oauth/token: ' +
        rateRequestCount.toString() + ' of ' + rateRequestLimit.toString();
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
      logRequest(chain, { ignoreErrorStatus: [401, 429] });
      if (rateRequestCount > rateRequestLimit) {
        if (chain.responseStatus === 429) {
          console.log('\tExpect: status === 429 PASS (Blocked)');
        } else {
          console.log('\tExpect: status === 429 TEST FAILED');
          rateRequestErrorCount++;
        }
      } else {
        if (chain.responseStatus === 401) {
          console.log('\tExpect: status === 401 PASS');
        } else {
          console.log('\tExpect: status === 401 TEST FAILED');
          rateRequestErrorCount++;
        }
      }
    })
    .then((chain) => showChain(chain))
    .catch((err) => showHardError(err));
}; // postOauthToken()

setInterval(() => {
  if (rateRequestDone) {
    if (rateRequestLimiterNumber === 0) {
      rateRequestLimiterNumber = 1;
      rateRequestCount = 0;
      rateRequestLimit = 4;
      rateRequestDone = false;
    } else if (rateRequestLimiterNumber === 1) {
      rateRequestLimiterNumber = 2;
      rateRequestCount = 0;
      rateRequestLimit = 4;
      rateRequestDone = false;
    } else if (rateRequestLimiterNumber === 2) {
      rateRequestLimiterNumber = 3;
      rateRequestCount = 12; // Previously GET /login, POST /login
      rateRequestLimit = 16;
      rateRequestDone = false;
    } else if (rateRequestLimiterNumber === 3) {
      rateRequestLimiterNumber = 4;
      rateRequestCount = 0;
      rateRequestLimit = 6;
      rateRequestDone = false;
    } else {
      if (rateRequestErrorCount === 0) {
        console.log('---------------------');
        console.log('  All Tests Passed');
        console.log('---------------------');
        process.exit(0);
      } else {
        console.log('---------------------');
        console.log('  Errors: ' + rateRequestErrorCount.toLocaleString());
        console.log('---------------------');
        process.exit(1);
      }
    }
  }
  rateRequestCount++;
  if (rateRequestCount > rateRequestLimit + 2) {
    rateRequestDone = true;
  } else {
    if (rateRequestLimiterNumber === 1) {
      getLoginForm();
    } else if (rateRequestLimiterNumber === 2) {
      postLoginData();
    } else if (rateRequestLimiterNumber === 3) {
      getDialogAuth();
    } else if (rateRequestLimiterNumber === 4) {
      postOauthToken();
    }
  }
}, 1000);
