// login-form-submission
//
// This script will emulate the browser submission of the HTML form for user password entry.
// This script will demonstrate detection of various errors conditions that can
// occur when users interact with the login form.
//
//    # Recommended test configuration
//    LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
//    LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
//    LIMITS_WEB_RATE_LIMIT_COUNT=1000
//
// The tests in this module were primarily written for the author
// to better understand how JWT tokens are verified by the Oauth 2.0 server.
//
// The tests are limited in scope and not comprehensive of all possible security risks.
// -----------------------------------------------------------
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');

const Tokens = require('../../collab-auth/node_modules/@dr.pogodin/csurf/tokens.js');
const tokens = new Tokens({});

if (!fs.existsSync('./package.json')) {
  console.log('Must be run from repository base folder as: node debug/login-form-submission.js');
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

const chainObj = Object.create(null);

/**
 * Validate login response data assertions.
 * @param {Object} chain - Chain object containing common variables
 * @returns {Promise} resolving to chain object
 */
const validateLoginResponsePass = (chain) => {
  logRequest(chain);
  // console.log(chain.responseRawData);
  console.log('\tExpect: status === 302');
  assert.strictEqual(chain.responseStatus, 302);
  console.log('\tExpect: Redirect URI matches /redirecterror');
  assert.strictEqual(chain.parsedLocationHeader, '/redirecterror');
  return Promise.resolve(chain);
};

const validateLoginResponseFail = (chain, expectCode) => {
  const code = expectCode || 302;
  logRequest(chain, { ignoreErrorStatus: code });
  // console.log(chain.responseRawData);
  console.log('\tExpect: status === ' + code.toString());
  assert.strictEqual(chain.responseStatus, code);
  if (code === 302) {
    console.log('\tExpect: Redirect URI matches /login?retry=yes');
    assert.strictEqual(chain.parsedLocationHeader, '/login?retry=yes');
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
  chain.requestAcceptType = 'text/html';
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
  // 100 GET /login - Login form with csrf token
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '100 GET /login - Login form with csrf token';
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
    check404PossibleVhostError(chain);
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

  // -----------------------------------------------
  // 101 POST /login - Expect successful result
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '101 POST /login - Expect successful result';
    // These values don't change, omit on future requests
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.requestBody = {
      username: testEnv.username,
      password: testEnv.password,
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponsePass(chain))

  // -----------------------------------------------
  // 102 POST /login - Show twice in a row still works
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '102 POST /login - Show twice in a row still works';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: testEnv.username,
      password: testEnv.password,
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponsePass(chain))

  // -----------------------------------------------
  // 103 POST /login - encode as x-www-form-urlencoded manually, (success)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '103 POST /login - manual encode as x-www-form-urlencoded';
    chain.requestContentType = 'text/html';
    chain.forceOverrideContentType = 'application/x-www-form-urlencoded';
    chain.requestBody =
      encodeURIComponent('username') + '=' +
      encodeURIComponent(testEnv.username) + '&' +
      encodeURIComponent('password') + '=' +
      encodeURIComponent(testEnv.password) + '&' +
      encodeURIComponent('_csrf') + '=' +
      encodeURIComponent(chain.parsedCsrfToken);
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponsePass(chain))

  // -----------------------------------------------
  // 104 POST /login - Encode as application/json
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '104 POST /login - Encode as application/json';
    chain.requestContentType = 'application/json';
    chain.requestBody = {
      username: testEnv.username,
      password: testEnv.password,
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponsePass(chain))

  // -----------------------------------------------
  // 200 POST /login - add extraneous property
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '200 POST /login - add extraneous property';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: testEnv.username,
      password: 'x' + testEnv.password,
      dummy: 'dummy-value',
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain, 422))

  // -----------------------------------------------
  // 201 POST /login - form properties not encoded
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '201 POST /login - form properties not encoded';
    chain.requestContentType = 'text/html';
    chain.forceOverrideContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: testEnv.username,
      password: 'x' + testEnv.password,
      dummy: 'dummy-value',
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain, 422))

  // -----------------------------------------------
  // 202 POST /login - x-www-form-urlencoded sent as text/html
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '202 POST /login - x-www-form-urlencoded sent as text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.forceOverrideContentType = 'text/html';
    chain.requestBody = {
      username: testEnv.username,
      password: 'x' + testEnv.password,
      dummy: 'dummy-value',
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain, 422))

  // -----------------------------------------------
  // 203 POST /login - Send POST request without the cookie
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '203 POST /login - Without cookie';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    // Remember current authorization type
    chain.tempRequestAuthorization = chain.requestAuthorization;
    chain.requestAuthorization = 'none';
    chain.requestBody = {
      username: testEnv.username,
      password: testEnv.password,
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain, 403))
  .then((chain) => {
    console.log('\tExpect: Error contains "Cookies may be blocked by browser"');
    assert.ok(chain.responseErrorMessage.indexOf('Cookies may be blocked by browser') >= 0);
    // Restore authorization type after test
    chain.requestAuthorization = chain.tempRequestAuthorization;
    delete chain.tempRequestAuthorization;
    return Promise.resolve(chain);
  })

  // -----------------------------------------------
  // 300 POST /login - Successful request
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '300 POST /login - Successful request';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: testEnv.username,
      password: testEnv.password,
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponsePass(chain))

  // -----------------------------------------------
  // 301 POST /login - Missing password property (input validation)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '301 POST /login - Missing password property (input validation)';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: testEnv.username,
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain, 422))

  // -----------------------------------------------
  // 302 POST /login - zero length password (Input validation)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '302 POST /login - zero length password (Input validation)';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      password: '',
      username: testEnv.username,
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain, 422))

  // -----------------------------------------------
  // 303 POST /login - password exceeds length (input validation)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '303 POST /login - password exceeds length (input validation)';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    let passwordString = '';
    for (let i = 0; i < config.data.userPasswordMaxLength + 1; i++) {
      passwordString += 'x';
    }
    chain.requestBody = {
      password: passwordString,
      username: testEnv.username,
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain, 422))

  // -----------------------------------------------
  // 304 POST /login - password field duplicated 2 key/value pairs
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '304 POST /login - password field duplicated 2 key/value pairs';
    chain.requestContentType = 'text/html';
    chain.forceOverrideContentType = 'application/x-www-form-urlencoded';
    chain.requestBody =
      encodeURIComponent('username') + '=' +
      encodeURIComponent(testEnv.username) + '&' +
      encodeURIComponent('password') + '=' +
      encodeURIComponent(testEnv.password) + '&' +
      encodeURIComponent('password') + '=' +
      encodeURIComponent(testEnv.password) + '&' +
      encodeURIComponent('_csrf') + '=' +
      encodeURIComponent(chain.parsedCsrfToken);
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain))

  // -----------------------------------------------
  // 305 POST /login - password = null
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '305 POST /login - password = null';
    chain.requestContentType = 'text/html';
    chain.forceOverrideContentType = 'application/x-www-form-urlencoded';
    chain.requestBody =
      encodeURIComponent('username') + '=' +
      encodeURIComponent(testEnv.username) + '&' +
      encodeURIComponent('password') + '=' +
      encodeURIComponent(null) + '&' +
      encodeURIComponent('_csrf') + '=' +
      encodeURIComponent(chain.parsedCsrfToken);
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain))

  // -----------------------------------------------
  // 306 POST /login - password = undefined
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '306 POST /login - password = undefined';
    chain.requestContentType = 'text/html';
    chain.forceOverrideContentType = 'application/x-www-form-urlencoded';
    chain.requestBody =
      encodeURIComponent('username') + '=' +
      encodeURIComponent(testEnv.username) + '&' +
      encodeURIComponent('password') + '=' +
      encodeURIComponent(undefined) + '&' +
      encodeURIComponent('_csrf') + '=' +
      encodeURIComponent(chain.parsedCsrfToken);
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain))

  // -----------------------------------------------
  // 307 POST /login - password = 0x00
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '307 POST /login - password = 0x00';
    chain.requestContentType = 'text/html';
    chain.forceOverrideContentType = 'application/x-www-form-urlencoded';
    chain.requestBody =
      encodeURIComponent('username') + '=' +
      encodeURIComponent(testEnv.username) + '&' +
      encodeURIComponent('password') + '=' +
      encodeURIComponent(String.fromCharCode(0)) + '&' +
      encodeURIComponent('_csrf') + '=' +
      encodeURIComponent(chain.parsedCsrfToken);
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain))

  // -----------------------------------------------
  // 308 POST /login - password appended with new line \n char
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '308 POST /login - password appended with new line \\n char';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: testEnv.username,
      password: testEnv.password + '\n',
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain))

  // -----------------------------------------------
  // 309 POST /login - increment first character of password
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '309 POST /login - increment first character of password';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    const password = String.fromCharCode(testEnv.password.charCodeAt(0) + 1) +
      testEnv.password.slice(1, testEnv.password.length);
    chain.requestBody = {
      username: testEnv.username,
      password: password,
      _csrf: chain.parsedCsrfToken
    };
    // console.log('password', password);
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain))

  // -----------------------------------------------
  // 310 POST /login - increment last character of password
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '310 POST /login - increment last character of password';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    const password = testEnv.password.slice(0, testEnv.password.length - 1) +
      String.fromCharCode(testEnv.password.charCodeAt(testEnv.password.length - 1) + 1);
    chain.requestBody = {
      username: testEnv.username,
      password: password,
      _csrf: chain.parsedCsrfToken
    };
    // console.log('password', password);
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain))

  // -----------------------------------------------
  // 400 POST /login - Confirm successful submission
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '400 POST /login - Confirm successful submission';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: testEnv.username,
      password: testEnv.password,
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponsePass(chain))

  // -----------------------------------------------
  // 401 POST /login - increment first character of username
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '401 POST /login - increment first character of username';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    const username = String.fromCharCode(testEnv.username.charCodeAt(0) + 1) +
      testEnv.username.slice(1, testEnv.username.length);
    chain.requestBody = {
      username: username,
      password: testEnv.password,
      _csrf: chain.parsedCsrfToken
    };
    // console.log('username', username);
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain))

  // -----------------------------------------------
  // 402 POST /login - increment last character of username
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '402 POST /login - increment last character of username';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    const username = testEnv.username.slice(0, testEnv.username.length - 1) +
      String.fromCharCode(testEnv.username.charCodeAt(testEnv.username.length - 1) + 1);
    chain.requestBody = {
      username: username,
      password: testEnv.password,
      _csrf: chain.parsedCsrfToken
    };
    // console.log('username', username);
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain))

  // -----------------------------------------------
  // 403 POST /login - zero length username (Input validation)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '403 POST /login - zero length username (Input validation)';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      password: testEnv.password,
      username: '',
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain, 422))

  // -----------------------------------------------
  // 404 POST /login - username exceeds length (input validation)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '404 POST /login - username exceeds length (input validation)';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    let usernameString = '';
    for (let i = 0; i < config.data.userUsernameMaxLength + 1; i++) {
      usernameString += 'x';
    }
    chain.requestBody = {
      password: testEnv.password,
      username: usernameString,
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain, 422))

  // -----------------------------------------------
  // 500 POST /login - Generate invalid CSRF token in correct format
  // ----------------------------------------------
  .then((chain) => {
    chain.testDescription = '500 POST /login - Generate invalid CSRF token in correct format';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: testEnv.username,
      password: testEnv.password,
      _csrf: tokens.create('abcdefghijklmnop')
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponseFail(chain, 403))

  // -----------------------------------------------
  // 999 POST /login - End of test, check for positive end test
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '999 POST /login - End of test, check for positive end test';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: testEnv.username,
      password: testEnv.password,
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => validateLoginResponsePass(chain))

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
