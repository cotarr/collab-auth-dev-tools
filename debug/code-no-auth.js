// code-no-auth.js
//
// This script will confirm that invalid credentials will be denied
// during the Authorization Code Grant workflow
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

/**
 * Promise based sleep timer
 * @param {Object} chain - Chain object passed from promise to promise
 * @param {Boolean} chain.abortSleepTimer - Flag, abort time if true
 * @param {Number} timeSeconds - Timer expiration in seconds
 * @param {String} logMessage - Optional message to print into log
 * @returns {Promise} resolving to chain object
 */
const sleep = (chain, timeSeconds, logMessage) => {
  let messageStr = '';
  if ((logMessage != null) && (logMessage.length > 0)) {
    messageStr = ' (' + logMessage + ')';
  }
  if (chain.abortSleepTimer) {
    delete chain.abortSleepTimer;
    return Promise.resolve(chain);
  } else {
    console.log('\nWaiting for ' + timeSeconds.toString() + ' seconds' + messageStr);
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        resolve(chain);
      }, timeSeconds * 1000);
    });
  }
}; // sleep ()

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
  // 2 GET /dialog/authorize - Authorization Check #1 (to get cookie)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '2 GET /dialog/authorize - Authorization Check #1 (to get cookie)';
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
  // 3 GET /login - Get login form (to get cookie)
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
      '3 GET /login - Get login form (to get cookie)';
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
  // 4 POST /login - Submit username and password (to get cookie)
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
      '4 POST /login - Submit username and password (to get cookie)';
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
  // 100 /dialog/authorize - Untrusted client, user denies permission
  // ----------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '100 /dialog/authorize - Untrusted client, user denies permission';
      chain.requestMethod = 'GET';
      chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      return Promise.resolve(chain);
    }
  })
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      return managedFetch(chain);
    }
  })  //
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
  // 101 POST /dialog/authorize/decision - Untrusted client, user denies permission
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '101 POST /dialog/authorize/decision - Untrusted client, user denies permission';
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      chain.requestContentType = 'application/x-www-form-urlencoded';
      chain.requestBody = {
        transaction_id: chain.parsedTransactionId,
        _csrf: chain.parsedCsrfToken
      };
      if (!testEnv.trustedClient) {
        chain.requestBody.cancel = 'deny';
      }
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
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));
      // console.log(chain.parsedLocationHeader);

      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      console.log('\tExpect: parsedLocationHeader header has state nonce');
      assert.ok(chain.parsedLocationHeader.indexOf('state=') >= 0);
      console.log('\tExpect: parsedLocationHeader does not have authorization code');
      assert.ok(chain.parsedLocationHeader.indexOf('code=') < 0);
      console.log('\tExpect: parsedLocationHeader contains: "error=access_denied"');
      assert.ok(chain.parsedLocationHeader.indexOf('error=access_denied') >= 0);
      console.log('\tExpect: parsedLocationHeader contains: "/login/callback?"');
      assert.ok(chain.parsedLocationHeader.indexOf('/login/callback?') >= 0);
      //
      // Parse Data
      //
      // due to error, no auth code
      chain.parsedAuthCode = null;
      chain.parsedStateNonce = chain.parsedLocationHeader.split('state=')[1];
      console.log('\tExpect: parsed state nonce match previous');
      assert.deepEqual(chain.parsedStateNonce, chain.randomStateNonce);
      return Promise.resolve(chain);
    }
  })

  // ----------------------------------------------------------
  // 102 /dialog/authorize - Untrusted client, no transaction code
  // ----------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '102 /dialog/authorize - Untrusted client, no transaction code';
      chain.requestMethod = 'GET';
      chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      return Promise.resolve(chain);
    }
  })
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      return managedFetch(chain);
    }
  })  //
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
  // 103 POST /dialog/authorize/decision - Untrusted client, No transaction code
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '103 POST /dialog/authorize/decision - Untrusted client, No transaction code';
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      chain.requestContentType = 'application/x-www-form-urlencoded';
      chain.requestBody = {
        // transaction_id: chain.parsedTransactionId,
        _csrf: chain.parsedCsrfToken
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
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 400 });
      // console.log(JSON.stringify(chain.responseRawData, null, 2));
      // console.log('\n\n',chain.responseErrorMessage, '\n\n');
      console.log('\tExpect: status === 400');
      assert.strictEqual(chain.responseStatus, 400);
      console.log('\tExpect: responseErrorMessage contains: \'"msg":"Required value","path":"transaction_id"\'');
      assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"transaction_id"') >= 0);

      return Promise.resolve(chain);
    }
  })


  // ----------------------------------------------------------
  // 104 /dialog/authorize - Untrusted client, invalid transaction code
  // ----------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '104 /dialog/authorize - Untrusted client, invalid transaction code';
      chain.requestMethod = 'GET';
      chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      return Promise.resolve(chain);
    }
  })
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      return managedFetch(chain);
    }
  })  //
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
  // 105 POST /dialog/authorize/decision - Untrusted client, invalid transaction code
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '105 POST /dialog/authorize/decision - Untrusted client, invalid transaction code';
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      chain.requestContentType = 'application/x-www-form-urlencoded';
      chain.requestBody = {
        // This is an invalid transaction id (for testing)
        transaction_id: 'zC5eGbW5dpmldOM6',
        _csrf: chain.parsedCsrfToken
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
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 403 });
      // console.log(JSON.stringify(chain.responseRawData, null, 2));
      // console.log('\n\n',chain.responseErrorMessage, '\n\n');
      console.log('\tExpect: status === 403');
      assert.strictEqual(chain.responseStatus, 403);
      console.log('\tExpect: responseErrorMessage contains: "server_error"\'');
      assert.ok(chain.responseErrorMessage.indexOf('server_error') >= 0);
      console.log('\tExpect: responseErrorMessage contains: "Unable to load OAuth 2.0 transaction"\'');
      assert.ok(chain.responseErrorMessage.indexOf('Unable to load OAuth 2.0 transaction') >= 0);
      return Promise.resolve(chain);
    }
  })

  // ----------------------------------------------------------
  // 106 /dialog/authorize - Untrusted client, no CSRF token
  // ----------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '106 /dialog/authorize - Untrusted client, no CSRF token';
      chain.requestMethod = 'GET';
      chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      return Promise.resolve(chain);
    }
  })
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      return managedFetch(chain);
    }
  })  //
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
  // 107 POST /dialog/authorize/decision - Untrusted client, No CSRF token
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '107 POST /dialog/authorize/decision - Untrusted client, No CSRF token';
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      chain.requestContentType = 'application/x-www-form-urlencoded';
      chain.requestBody = {
        transaction_id: chain.parsedTransactionId,
        // _csrf: chain.parsedCsrfToken
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
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));
      // console.log('\n\n',chain.responseErrorMessage, '\n\n');
      // console.log(chain.parsedLocationHeader);
      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      console.log('\tExpect: parsedLocationHeader contains: "error=EBADCSRFTOKEN"');
      assert.ok(chain.parsedLocationHeader.indexOf('error=EBADCSRFTOKEN') >= 0);

      return Promise.resolve(chain);
    }
  })

  // ----------------------------------------------------------
  // 108 /dialog/authorize - Untrusted client, invalid CSRF token
  // ----------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '108 /dialog/authorize - Untrusted client, invalid CSRF token';
      chain.requestMethod = 'GET';
      chain.requestFetchURL = testEnv.authURL + chain.savedAuthorizationPath;
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      return Promise.resolve(chain);
    }
  })
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      return managedFetch(chain);
    }
  })  //
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
  // 109 POST /dialog/authorize/decision - Untrusted client, Invalid CSRF token
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '109 POST /dialog/authorize/decision - Untrusted client, Invalid CSRF token';
      chain.requestMethod = 'POST';
      chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize/decision');
      chain.requestAuthorization = 'cookie';
      chain.requestAcceptType = 'text/html';
      chain.requestContentType = 'application/x-www-form-urlencoded';
      chain.requestBody = {
        transaction_id: chain.parsedTransactionId,
        // Invalid CSRF token
        _csrf: 'KXbRR1JE-FAP_SSoZ2Nq2C1Ct6WaZKZf_C7JU_ACK1AZ2kqPmDL4'
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
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      // console.log(JSON.stringify(chain.responseRawData, null, 2));
      // console.log('\n\n',chain.responseErrorMessage, '\n\n');
      // console.log(chain.parsedLocationHeader);
      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      console.log('\tExpect: parsedLocationHeader contains: "error=EBADCSRFTOKEN"');
      assert.ok(chain.parsedLocationHeader.indexOf('error=EBADCSRFTOKEN') >= 0);

      return Promise.resolve(chain);
    }
  })

  // ----------------------------------------------------------
  // 200 /dialog/authorize - Invalid authorization code
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '200 /dialog/authorize - Invalid authorization code';
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
  // 201 POST /dialog/authorize/decision - Invalid authorization code
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '201 POST /dialog/authorize/decision - Invalid authorization code';
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
  // 202 POST /oauth/token - Invalid authorization code
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '202 POST /oauth/token - Invalid authorization code';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    // No cookie, auth in body of request
    chain.requestAuthorization = 'none';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    chain.requestBody = {
      code: 'HeOJpM1ylX5YY1VMlYURrmk1',
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
    logRequest(chain, { ignoreErrorStatus: 403 });
    // console.log(JSON.stringify(chain.responseErrorMessage, null, 2));
    console.log('\tExpect: status === 403');
    assert.strictEqual(chain.responseStatus, 403);
    console.log('\tExpect: body contains "invalid_grant"');
    assert.ok(chain.responseErrorMessage.indexOf('invalid_grant') >= 0);
    console.log('\tExpect: body contains "Invalid authorization code"');
    assert.ok(chain.responseErrorMessage.indexOf('Invalid authorization code') >= 0);
    return Promise.resolve(chain);
  })


  // ----------------------------------------------------------
  // 203 /dialog/authorize - Invalid clientId
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '203 /dialog/authorize - Invalid clientId';
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
  // 204 POST /dialog/authorize/decision - Invalid clientId
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '204 POST /dialog/authorize/decision - Invalid clientId';
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
  // 205 POST /oauth/token - Invalid clientId
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '205 POST /oauth/token - Invalid clientId';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/oauth/token');
    // No cookie, auth in body of request
    chain.requestAuthorization = 'none';
    chain.requestAcceptType = 'application/json';
    chain.requestContentType = 'application/json';
    chain.requestBody = {
      code: chain.parsedAuthCode,
      redirect_uri: testEnv.redirectURI,
      client_id: testEnv.clientId + 'x',
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
    logRequest(chain, { ignoreErrorStatus: 401 });
    // console.log(JSON.stringify(chain.responseErrorMessage, null, 2));
    console.log('\tExpect: status === 401');
    assert.strictEqual(chain.responseStatus, 401);
    console.log('\tExpect: body contains "Unauthorized"');
    assert.ok(chain.responseErrorMessage.indexOf('Unauthorized') >= 0);
    return Promise.resolve(chain);
  })

  // ----------------------------------------------------------
  // 206 /dialog/authorize - Invalid clientSecret
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '206 /dialog/authorize - Invalid clientSecret';
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
  // 207 POST /dialog/authorize/decision - Invalid clientSecret
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '207 POST /dialog/authorize/decision - Invalid clientSecret';
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
  // 208 POST /oauth/token - Invalid clientSecret
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '208 POST /oauth/token - Invalid clientSecret';
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
      client_secret: testEnv.clientSecret + 'x',
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
    logRequest(chain, { ignoreErrorStatus: 401 });
    // console.log(JSON.stringify(chain.responseErrorMessage, null, 2));
    console.log('\tExpect: status === 401');
    assert.strictEqual(chain.responseStatus, 401);
    console.log('\tExpect: body contains "Unauthorized"');
    assert.ok(chain.responseErrorMessage.indexOf('Unauthorized') >= 0);
    return Promise.resolve(chain);
  })

  // ----------------------------------------------------------
  // 209 /dialog/authorize - Auth code used two times
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '209 /dialog/authorize - Auth code used two times';
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
  // 210 POST /dialog/authorize/decision - Auth code used two times
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '210 POST /dialog/authorize/decision - Auth code used two times';
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
  // 211 POST /oauth/token - Auth code used two times (first, OK)
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '211 POST /oauth/token - Auth code used two times (first, OK)';
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
    // delete chain.parsedAuthCode;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: response has access_token property');
    assert.ok(Object.hasOwn(chain.responseRawData, 'access_token'));
    console.log('\tExpect: response token_type === "Bearer"');
    assert.strictEqual(chain.responseRawData.token_type, 'Bearer');
    console.log('\tExpect: response grantType === "authorization_code"');
    assert.strictEqual(chain.responseRawData.grant_type, 'authorization_code');
    return Promise.resolve(chain);
  })

  // -----------------------------------------
  // 212 POST /oauth/token - Auth code used two times (second, fail)
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '212 POST /oauth/token - Auth code used two times (second, fail)';
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
    logRequest(chain, { ignoreErrorStatus: 403 });
    // console.log(JSON.stringify(chain.responseErrorMessage, null, 2));
    console.log('\tExpect: status === 403');
    assert.strictEqual(chain.responseStatus, 403);
    console.log('\tExpect: body contains "invalid_grant"');
    assert.ok(chain.responseErrorMessage.indexOf('invalid_grant') >= 0);
    console.log('\tExpect: body contains "Invalid authorization code"');
    assert.ok(chain.responseErrorMessage.indexOf('Invalid authorization code') >= 0);    return Promise.resolve(chain);
  })

  // ----------------------------------------------------------
  // 213 /dialog/authorize - Auth code is expired
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '213 /dialog/authorize - Auth code is expired';
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
  // 214 POST /dialog/authorize/decision - Auth code is expired
  // --------------------------------------------------------
  .then((chain) => {
    if (testEnv.trustedClient) {
      return Promise.resolve(chain);
    } else {
      chain.testDescription =
        '214 POST /dialog/authorize/decision - Auth code is expired';
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
  // 215 POST /oauth/token - Auth code is expired
  // -----------------------------------------
  .then((chain) => {
    chain.testDescription =
      '215 POST /oauth/token - Auth code is expired';
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
    // delete chain.parsedAuthCode;
    return Promise.resolve(chain);
  })
  .then((chain) => sleep(chain, 12, 'Delay - Waiting for auth code to expire'))
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 403 });
    // console.log(JSON.stringify(chain.responseErrorMessage, null, 2));
    console.log('\tExpect: status === 403');
    assert.strictEqual(chain.responseStatus, 403);
    console.log('\tExpect: body contains "invalid_grant"');
    assert.ok(chain.responseErrorMessage.indexOf('invalid_grant') >= 0);
    console.log('\tExpect: body contains "Invalid authorization code"');
    assert.ok(chain.responseErrorMessage.indexOf('Invalid authorization code') >= 0);    return Promise.resolve(chain);
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
