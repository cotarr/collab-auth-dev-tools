// cookie-tests.js
//
// The collab-auth server uses HTTP cookies to manage browser sessions
// during authentication of the user's identity by submission
// of username and password. The sessions and cookies are created
// by the express-session middleware and use passport as authorization middleware.
// This script is more a a deep dive into learning how cookies work in general
// using express-session and passport as authorization middleware.
// During the code grant workflow, cookies issued by the browser are used
// to authenticate the identity of the user when requesting a new authorization code.
// The script includes two options for cookies with fixed expiration cookies and rolling cookies,
// where rolling cookies will extend the cookie expiration with each request.

//    # Recommended test configuration
//    LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
//    LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
//    LIMITS_WEB_RATE_LIMIT_COUNT=1000
//    SESSION_EXPIRE_SEC=8
//        # Option 1 of 2
//        SESSION_SET_ROLLING_COOKIE=false
//        # Option 1 of 2
//        SESSION_SET_ROLLING_COOKIE=true
//
// The tests in this module were primarily written for the author
// to better understand how the cookies are verified in the server.
//
// The tests are limited in scope and not comprehensive of
// all possible security risks.
// ---------------------------------------------------------------
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');

// This is in local node_modules folder as dependency of express-session
const signature = require('../../collab-auth/node_modules/cookie-signature');
const uid = require('../../collab-auth/node_modules/uid-safe').sync;

if (!fs.existsSync('./package.json')) {
  console.log('Must be run from repository base folder as: node debug/cookie-tests.js');
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
  // 1 GET /changepassword - Unauthenticated request to protected route.
  //
  // This is an initial test to a protected route for cookie testing.
  //
  // The following request is not related to testing
  // functionality of the change password request.
  // The /changepassword route will be used in several subsequent tests
  // during evaluation of cookie and session functionality.
  //
  // In the authorization server, protected routes are
  // handled by the passport middleware.
  // This first request represents an initial first connection
  // to the authentication server for there case where the
  // user's browser does not have a session cookie.
  //
  // The request is expected to fail with a 302 FOUND response
  // with the Location header containing a new URL for the login form.
  //
  // This test is to confirm a new cookie is provided
  // in the status 302 redirect request to GET /login.
  //
  // In addition, the passport middleware will create
  // a new session store record and the route "/changepassword"
  // will be stored in the session store so in the future
  // the user's browser can be redirected to back
  // to the intended route after password submission.
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '1 GET /changepassword - No access to protected route.';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/changepassword');
    chain.tempInitialRedirectRoute = '/changepassword';
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
    assert.ok(((chain.parsedSetCookieHeader != null) && (chain.parsedSetCookieHeader.length > 0)));
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 2 GET /login - Get login form (submit cookie, existing session)
  //
  // The request to load the HTTP login form.
  //
  // This is the second request of the series. the user's session
  // cookie from test #1 is submitted with the request.
  //
  // This HTML form is unique because the GET /login route
  // will create a new record in the authentication server
  // session store for unauthenticated requests.
  // This is to have a place to store the CSRF token embedded
  // in the login form.
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '2 GET /login - Get login form (submit cookie, existing session)';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    // In the case where a cookie is returned, it should match the
    // cookie previously obtained in test #1
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

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);

    console.log('\tExpect: set-cookie header present');
    assert.ok(((chain.parsedSetCookieHeader != null) &&
      (chain.parsedSetCookieHeader.length > 0)));
    console.log('\tExpect: cookie matches previous cookie from previous test');
    assert.strictEqual(
      chain.tempLastSessionCookie,
      chain.parsedSetCookieHeader);

    // Temporary variable no longer needed
    delete chain.tempLastSessionCookie;
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
  // 3 POST /login - Submit user login password
  //
  // The purpose of this request is to assign
  // the session as "authenticated" to allow
  // subsequent tests to access a protected route
  // during testing.
  //
  // Since the authenticated status of the session changes,
  // the authentication server generates a replacement cookie.
  // The unauthenticated cookie will no longe be used.
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
    // In this case, the POST request is submitted
    // using a cookie where the associated session store
    // includes a saved redirect URL from a previously failed
    // authentication attempt (invalid cookie).
    console.log('\tExpect: Redirect URI matches initial request');
    assert.strictEqual(chain.parsedLocationHeader, chain.tempInitialRedirectRoute);
    console.log('\tExpect: Response includes set-cookie header');
    assert.ok(((chain.parsedSetCookieHeader != null) &&
      (chain.parsedSetCookieHeader.length > 0)));
    console.log('\tExpect: Session cookie replaced after successful login');
    assert.notEqual(
      chain.tempLastSessionCookie,
      chain.parsedSetCookieHeader);
    // Temporary variable no longer needed
    delete chain.tempLastSessionCookie;
    delete chain.tempInitialRedirectRoute;
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 4 GET /changepassword - Valid cookie retrieves protected route
  //
  // The following tests are not related to testing
  // functionality of the change password request.
  // Rather, the HTML form for submitting a password
  // change is a protected route requiring a cookie.
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '4 GET /changepassword - Valid cookie retrieves protected route';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/changepassword');
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    // console.log(chain.responseRawData);
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    if (config.session.rollingCookie) {
      console.log('\tExpect: set-cookie header (because rollingCookie=true)');
      assert.ok((chain.parsedSetCookieHeader != null) && (chain.parsedSetCookieHeader.length > 0));
    }
    return Promise.resolve(chain);
  })

  // -----------------------------------------------
  // 5 GET /login - Get CSRF token from login form
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '5 GET /login - Get CSRF token from login form';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    if (chain.responseStatus === 200) {
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
    }
    return Promise.resolve(chain);
  })

  // -----------------------------------------------
  // 6 POST /login - Submit user login password
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '6 POST /login - Submit user login password';
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
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: Location header /redirecterror (because no redirectURI in session)');
    assert.strictEqual(chain.parsedLocationHeader, '/redirecterror');
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 7 GET /changepassword - Simple confirm access prior to /logout
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '7 GET /changepassword - Simple confirm access prior to /logout';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/changepassword');
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 8 GET /logout - Call to remove session from session store';
  //
  // In this test, calling /logout will invalidate the user's session.
  // The user's cookie should no longer work, even with valid signature.
  // Next tests will confirm this.
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '8 GET /logout - Call to remove session from session store';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/logout');
    // Remember present cookie to evaluate afterwards
    chain.tempLastSessionCookie = chain.currentSessionCookie;
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
    chain.currentSessionCookie = chain.tempLastSessionCookie;
    delete chain.tempLastSessionCookie;
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 9 GET /changepassword - Expect access denied after logout
  //
  // In this case the cookie is unexpired with signature, but the session deactived
  // -------------------------------
  .then((chain) => {
    chain.testDescription = '9 GET /changepassword - Expect access denied after logout';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/changepassword');
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    // console.log(chain.responseRawData);
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: Location header redirects to GET /login');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    return Promise.resolve(chain);
  })
  // -----------------------------------------------
  // 10 GET /login - Get CSRF token from login form
  //
  // In the next series of tests, new cookies will be minted
  // with various components mutated to see the results.
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '10 GET /login - Get CSRF token from login form';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    // Delete last cookie before test because it has saved /changepassword redirect.
    chain.currentSessionCookie = null;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    if (chain.responseStatus === 200) {
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
    }
    return Promise.resolve(chain);
  })

  // -----------------------------------------------
  // 11 POST /login - Submit user login password
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '11 POST /login - Submit user login password';
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
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: Location header /redirecterror (because no redirectURI in session)');
    assert.strictEqual(chain.parsedLocationHeader, '/redirecterror');
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 12 GET /changepassword - Confirm 200, then decode and save cookie for next tests
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '12 GET /changepassword - Confirm 200, then decode and save cookie for next tests';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/changepassword');
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    return Promise.resolve(chain);
  })
  // ----------------------------1
  // Parse cookie components
  //
  // This are saved temporarily for use in various tests.
  // ----------------------------
  .then((chain) => {
    // Assert that cookie exists before attempting to decode it
    console.log('\tExpect: set-cookie header');
    assert.ok((chain.currentSessionCookie != null) && (chain.currentSessionCookie.length > 0));
    chain.validCookie = {};
    chain.validCookie.cookie = chain.currentSessionCookie;
    console.log('\tExpect: response cookie decodes without error');
    chain.validCookie.name = chain.validCookie.cookie.split('=')[0];
    chain.validCookie.rawValue = chain.validCookie.cookie.split('=')[1];
    chain.validCookie.decoded = decodeURIComponent(chain.validCookie.cookie.split('=')[1]).slice(2);
    assert.ok((typeof chain.validCookie.decoded === 'string') &&
      (chain.validCookie.decoded.length > 0));
    console.log('\tExpect: response cookie has valid signature');
    chain.validCookie.unsigned = signature.unsign(chain.validCookie.decoded, config.session.secret);
    if ((chain.validCookie.unsigned == null) || (chain.validCookie.unsigned === false)) {
      throw new Error('Invalid cookie signature');
    }
    // console.log('validCookie', chain.validCookie);
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 13 GET /changepassword - Send raw cookie SID without signature (authorization.sid=xxxxx)
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '13 GET /changepassword - Send raw cookie SID without signature (authorization.sid=xxxxx)';
    chain.currentSessionCookie = chain.validCookie.name + '=' + chain.validCookie.unsigned;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: Location header redirects to GET /login');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    return Promise.resolve(chain);
  })
  // -------------------------------
  // 14 GET /changepassword - Submit ad-hoc cookie with different cookie name
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '14 GET /changepassword - Submit ad-hoc cookie with different cookie name';
    chain.currentSessionCookie = 'changed.sid' + '=' + chain.validCookie.rawValue;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: Location header redirects to GET /login');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 15 GET /changepassword - Submit ad-hoc cookie signed with wrong secret
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '15 GET /changepassword - Submit ad-hoc cookie signed with wrong secret';
    // This is valid (before using different signature)
    // const signed = signature.sign(chain.validCookie.unsigned, config.session.secret);
    // This is altered
    const signed = signature.sign(chain.validCookie.unsigned, 'a' + config.session.secret);
    // console.log('\nsigned', signed);
    const encoded = encodeURIComponent('s:' + signed);
    // console.log('encoded', encoded);
    const named = chain.validCookie.name + '=' + encoded;
    // console.log('named', named);
    chain.currentSessionCookie = named;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: Location header redirects to GET /login');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    return Promise.resolve(chain);
  })
  // -------------------------------
  // 16 GET /changepassword - Submit ad-hoc cookie, random SID with valid signature
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '16 GET /changepassword - Submit ad-hoc cookie, random SID with valid signature';
    // Used in express-session
    const alternateSid = uid(24);
    // console.log('alternateSid', alternateSid);
    // this is valid (before replacing SID)
    // const signed = signature.sign(chain.validCookie.unsigned, config.session.secret);
    // this is altered
    const signed = signature.sign(alternateSid, config.session.secret);
    // console.log('\nsigned', signed);
    const encoded = encodeURIComponent('s:' + signed);
    // console.log('encoded', encoded);
    const named = chain.validCookie.name + '=' + encoded;
    // console.log('named', named);
    chain.currentSessionCookie = named;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: Location header redirects to GET /login');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    return Promise.resolve(chain);
  })

  // -------------------------------
  // 17 GET /changepassword - Submit original cookie, confirm original cookie still accepted
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '17 GET /changepassword - Submit original cookie, confirm original cookie still accepted';
    chain.currentSessionCookie = chain.validCookie.cookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain);
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    // not needed any more
    delete chain.validCookie;
    return Promise.resolve(chain);
  })

  // -----------------------------------------------
  // 100 GET /login - Get CSRF token from login form
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '100 GET /login - Get CSRF token from login form';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    if ((config.session.ttl === 8)) {
      // Clear previous cookies
      chain.currentSessionCookie = null;
      chain.currentSessionCookieExpires = null;
      return Promise.resolve(chain);
    } else {
      console.log('\nTo test session expires as expected, configure server: SESSION_EXPIRE_SEC=8');
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      if (chain.responseStatus === 200) {
        chain.parsedCsrfToken =
          chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      }
      return Promise.resolve(chain);
    }
  })

  // -----------------------------------------------
  // 101 POST /login - Submit user login password
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '101 POST /login - Submit user login password';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    if ((config.session.ttl === 8)) {
      chain.requestContentType = 'application/x-www-form-urlencoded';
      chain.requestBody = {
        username: testEnv.username,
        password: testEnv.password,
        _csrf: chain.parsedCsrfToken
      };
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      console.log('\tExpect: Location header /redirecterror (because no redirectURI in session)');
      assert.strictEqual(chain.parsedLocationHeader, '/redirecterror');
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 102 GET /secure - Elapsed time 3 seconds, check if expired
  //
  // Assuming the configuration in .env SESSION_EXPIRE_SEC=8, these tests will run
  //
  // Session will be set to expire in 8 seconds
  //
  // At 3 seconds:
  //     Session cookie:   accept (session will expire in 7 seconds)
  //     Fixed expiration: accept (session will expire in 7 seconds)
  //     Rolling cookie:   accept (session will expire in 10 seconds)
  //
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '102 GET /secure - Elapsed time 3 seconds, check if expired';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/secure');

    if ((config.session.ttl === 8)) {
      // Save the expiration time of the previous cookie (UNIX seconds)
      chain.tempLastSessionCookie = chain.currentSessionCookie;
      chain.tempLastSessionCookieExpires = chain.currentSessionCookieExpires;
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => sleep(chain, 3, 'Delay - Waiting for cookie to expire'))
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
      const expiresDelta = chain.currentSessionCookieExpires - chain.tempLastSessionCookieExpires;
      if (config.session.rollingCookie === true) {
        chain.sleepDelayMessage = 'Delay - Waiting for cookie to expire';
        console.log('\tExpect: status === 200');
        assert.strictEqual(chain.responseStatus, 200);
        console.log('\tExpect: set-cookie header (because rollingCookie=true)');
        assert.ok((chain.parsedSetCookieHeader != null) &&
          (chain.parsedSetCookieHeader.length > 0));
        console.log('\tExpect: Cookie not changed');
        assert.strictEqual(chain.tempLastSessionCookie, chain.currentSessionCookie);
        console.log('\tExpect: Cookie expires value incremented by 3 seconds after time delay');
        assert.ok((expiresDelta >= 2) && (expiresDelta <= 4));
      } else {
        chain.sleepDelayMessage = 'Delay - Expecting cookie to be expired';
        console.log('\tExpect: status === 200');
        assert.strictEqual(chain.responseStatus, 200);
      }
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 103 GET /secure - Elapsed time 3 + 3 = 6 seconds, check if expired
  // Session will be set to expire in 8 seconds
  //
  // At 3 + 3 = 6 seconds:
  //     Session cookie:   accept (session will expire in 4 seconds)
  //     Fixed expiration: accept (session will expire in 4 seconds)
  //     Rolling cookie:   accept (session will expire in 10 seconds)
  //
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '103 GET /secure - Elapsed time 3 + 3 = 6 seconds, check if expired';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/secure');
    if (config.session.ttl === 8) {
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => sleep(chain, 3, 'Delay - Waiting for cookie to expire'))
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      const expiresDelta = chain.currentSessionCookieExpires - chain.tempLastSessionCookieExpires;
      if (config.session.rollingCookie === true) {
        console.log('\tExpect: status === 200');
        assert.strictEqual(chain.responseStatus, 200);
        console.log('\tExpect: set-cookie header (because rollingCookie=true)');
        assert.ok((chain.parsedSetCookieHeader != null) &&
          (chain.parsedSetCookieHeader.length > 0));
        console.log('\tExpect: Cookie not changed');
        assert.strictEqual(chain.tempLastSessionCookie, chain.currentSessionCookie);
        console.log('\tExpect: Cookie expires value incremented by 6 seconds after time delay');
        assert.ok((expiresDelta >= 5) && (expiresDelta <= 7));
      } else {
        console.log('\tExpect: status === 200');
        assert.strictEqual(chain.responseStatus, 200);
      }
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 104 GET /secure - Elapsed time 3 + 3 + 4 = 10 seconds, check if expired
  //
  // At this time, there will be a difference in acceptance for different cookies
  //
  // At 3 + 3 + 4 = 10 seconds:
  //     Session cookie:   reject (session expired 2 seconds ago)
  //     Fixed expiration: reject (session expired 2 seconds ago)
  //     Rolling cookie:   accept (session will expire in 10 seconds)
  //
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '104 GET /secure - Elapsed time 3 + 3 + 4 = 10 seconds, check if expired';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/secure');
    if (config.session.ttl === 8) {
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => sleep(chain, 4, chain.sleepDelayMessage))
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 401 });
      const expiresDelta = chain.currentSessionCookieExpires - chain.tempLastSessionCookieExpires;
      if (config.session.rollingCookie === true) {
        console.log('\tExpect: status === 200');
        assert.strictEqual(chain.responseStatus, 200);
        console.log('\tExpect: set-cookie header (because rollingCookie=true)');
        assert.ok((chain.parsedSetCookieHeader != null) &&
          (chain.parsedSetCookieHeader.length > 0));
        console.log('\tExpect: Cookie not changed');
        assert.strictEqual(chain.tempLastSessionCookie, chain.currentSessionCookie);
        console.log('\tExpect: Cookie expires value incremented by 10 seconds after time delay');
        assert.ok((expiresDelta >= 9) && (expiresDelta <= 11));
      } else {
        console.log('\tExpect: status === 401');
        assert.strictEqual(chain.responseStatus, 401);
      }
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 105 GET /secure - Elapsed time 3 + 3 + 4 + 10 = 20 seconds, check if expired
  //
  // In this case, an interval of 10 seconds without any request will expire all cookies
  //
  // At 3 + 3 + 4 + 10 = 20 seconds:
  //     Session cookie:   reject (session expired 12 seconds ago)
  //     Fixed expiration: reject (session expired 12 seconds ago)
  //     Rolling cookie:   reject (session expired 2 seconds ago)
  //
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '105 GET /secure - Elapsed time 3 + 3 + 4 + 10 = 20 seconds, check if expired';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/secure');
    if (config.session.ttl === 8) {
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => sleep(chain, 10, 'Delay - Expecting cookie to be expired'))
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 401 });
      console.log('\tExpect: status === 401');
      assert.strictEqual(chain.responseStatus, 401);
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 106 GET /secure - Elapsed time 3 + 3 + 4 + 10 + 4 = 24 seconds, Done
  //
  // In the previous test #105, all sessions were expired, they should continue to reject
  // At 3 + 3 + 4 +10 + 4 = 24 seconds:
  //     Session cookie:   reject
  //     Fixed expiration: reject
  //     Rolling cookie:   reject
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '106 GET /secure - Elapsed time 3 + 3 + 4 + 10 + 4 = 24 seconds, Done';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/secure');
    if (config.session.ttl === 8) {
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => sleep(chain, 4, 'Delay - Expecting cookie to be expired'))
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    // Temporary variables no longer needed
    delete chain.tempLastSessionCookie;
    delete chain.tempLastSessionCookieExpires;
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain, { ignoreErrorStatus: 401 });
      console.log('\tExpect: status === 401');
      assert.strictEqual(chain.responseStatus, 401);
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 200 GET /dialog/authorize - Initial user authorization (from web server redirect)
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '200 GET /dialog/authorize - Initial user authorization (from web server redirect)';
    chain.requestMethod = 'GET';
    let query = '';
    chain.randomStateNonce = 'A' + Math.floor((Math.random() * 1000000)).toString();
    query += '?redirect_uri=' + testEnv.redirectURI;
    query += '&response_type=code';
    query += '&client_id=' + testEnv.clientId;
    query += '&scope=api.read api.write';
    query += '&state=' + chain.randomStateNonce;
    chain.savedAuthorizationPath = encodeURI('/dialog/authorize' + query);
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/dialog/authorize' + query);

    if ((config.session.ttl === 8)) {
      // Clear previous cookies
      chain.currentSessionCookie = null;
      chain.currentSessionCookieExpires = null;
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
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
      // console.log(chain.responseRawData);
      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      console.log('\tExpect: parsedLocationHeader === "/login"');
      assert.strictEqual(chain.parsedLocationHeader, '/login');
      console.log('\tExpect: response returned set-cookie');
      assert.ok((chain.parsedSetCookieHeader != null) && (chain.parsedSetCookieHeader.length > 0));
      // temporarily save cookies
      chain.tempLastSessionCookie = chain.currentSessionCookie;
      chain.tempLastSessionCookieExpires = chain.currentSessionCookieExpires;
      return Promise.resolve(chain);
    }
  })

  // -----------------------------------------------
  // 201 GET /login - Get CSRF token from login form
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '201 GET /login - Get CSRF token from login form';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    if ((config.session.ttl === 8)) {
      return Promise.resolve(chain);
    } else {
      console.log('\nTo test session expires as expected, configure server: SESSION_EXPIRE_SEC=8');
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      console.log('\tExpect: Cookie not changed');
      assert.strictEqual(chain.tempLastSessionCookie, chain.currentSessionCookie);
      console.log('\tExpect: status === 200');
      assert.strictEqual(chain.responseStatus, 200);
      if (chain.responseStatus === 200) {
        chain.parsedCsrfToken =
          chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
      }
      return Promise.resolve(chain);
    }
  })

  // -----------------------------------------------
  // 202 POST /login - Submit user login password
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '202 POST /login - Submit user login password';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    if ((config.session.ttl === 8)) {
      chain.requestContentType = 'application/x-www-form-urlencoded';
      chain.requestBody = {
        username: testEnv.username,
        password: testEnv.password,
        _csrf: chain.parsedCsrfToken
      };
      return Promise.resolve(chain);
    } else {
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      console.log('\tExpect: New (different) cookie issued after login');
      assert.notEqual(chain.tempLastSessionCookie, chain.currentSessionCookie);
      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      console.log('\tExpect: Redirect URI to match previously save value');
      assert.strictEqual(
        chain.savedAuthorizationPath,
        chain.parsedLocationHeader);
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 203 GET /dialog/authorize - Elapsed time 3 seconds, check if expired
  //
  // Session will be set to expire in 8 seconds
  //
  // At 3 seconds:
  //     Session cookie:   accept (session will expire in 7 seconds)
  //     Fixed expiration: accept (session will expire in 7 seconds)
  //     Rolling cookie:   accept (session will expire in 10 seconds)
  //
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '203 GET /dialog/authorize - Elapsed time 3 seconds, check if expired';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + chain.savedAuthorizationPath);

    if ((config.session.ttl === 8)) {
      // Save the expiration time of the previous cookie (UNIX seconds)
      chain.tempLastSessionCookie = chain.currentSessionCookie;
      chain.tempLastSessionCookieExpires = chain.currentSessionCookieExpires;
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => sleep(chain, 3, 'Delay - Waiting for cookie to expire'))
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
      // console.log(chain.responseRawData);
      if (testEnv.trustedClient) {
        console.log('\tExpect: status === 302');
        assert.strictEqual(chain.responseStatus, 302);
        console.log('\tExpect: redirect location match redirectURI');
        assert.strictEqual(
          testEnv.redirectURI,
          chain.parsedLocationHeader.split('?')[0]);
      } else {
        console.log('\tExpect: status === 200');
        assert.strictEqual(chain.responseStatus, 200);
        console.log('\tExpect: body contains "<title>Resource Decision</title>"');
        assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
      }
      if (config.session.rollingCookie === true) {
        console.log('\tExpect: set-cookie header (because rollingCookie=true)');
        assert.ok((chain.parsedSetCookieHeader != null) &&
        (chain.parsedSetCookieHeader.length > 0));
        console.log('\tExpect: Cookie not changed');
        assert.strictEqual(chain.tempLastSessionCookie, chain.currentSessionCookie);
        const expiresDelta =
          chain.currentSessionCookieExpires - chain.tempLastSessionCookieExpires;
        console.log('\tExpect: Cookie expires value incremented by 3 seconds after time delay');
        assert.ok((expiresDelta >= 2) && (expiresDelta <= 4));
      }
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 204 GET /dialog/authorize - Elapsed time 3 + 3 = 6 seconds, check if expired
  //
  // At 3 + 3 = 6 seconds:
  //     Session cookie:   accept (session will expire in 4 seconds)
  //     Fixed expiration: accept (session will expire in 4 seconds)
  //     Rolling cookie:   accept (session will expire in 10 seconds)
  //
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '204 GET /dialog/authorize - Elapsed time 3 + 3 = 6 seconds, check if expired';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + chain.savedAuthorizationPath);
    if (config.session.ttl === 8) {
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => sleep(chain, 3, 'Delay - Waiting for cookie to expire'))
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      if (testEnv.trustedClient) {
        console.log('\tExpect: status === 302');
        assert.strictEqual(chain.responseStatus, 302);
        console.log('\tExpect: redirect location match redirectURI');
        assert.strictEqual(
          testEnv.redirectURI,
          chain.parsedLocationHeader.split('?')[0]);
      } else {
        console.log('\tExpect: status === 200');
        assert.strictEqual(chain.responseStatus, 200);
        console.log('\tExpect: body contains "<title>Resource Decision</title>"');
        assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
      }
      if (config.session.rollingCookie === true) {
        console.log('\tExpect: set-cookie header (because rollingCookie=true)');
        assert.ok((chain.parsedSetCookieHeader != null) &&
        (chain.parsedSetCookieHeader.length > 0));
        console.log('\tExpect: Cookie not changed');
        assert.strictEqual(chain.tempLastSessionCookie, chain.currentSessionCookie);
        const expiresDelta =
          chain.currentSessionCookieExpires - chain.tempLastSessionCookieExpires;
        console.log('\tExpect: Cookie expires value incremented by 6 seconds after time delay');
        assert.ok((expiresDelta >= 5) && (expiresDelta <= 7));
      }
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 205 GET /dialog/authorize - Elapsed time 3 + 3 + 4 = 10 seconds, check if expired
  //
  // At 3 + 3 + 4 = 10 seconds:
  //     Session cookie:   reject (session xpired 2 seconds ago)
  //     Fixed expiration: reject (session xpired 2 seconds ago)
  //     Rolling cookie:   accept (session will expire in 10 seconds)
  //
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '205 GET /dialog/authorize - Elapsed time 3 + 3 + 4 = 10 seconds, check if expired';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + chain.savedAuthorizationPath);
    if (config.session.ttl === 8) {
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => sleep(chain, 4, chain.sleepDelayMessage))
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      if (config.session.rollingCookie === true) {
        if (testEnv.trustedClient) {
          console.log('\tExpect: status === 302');
          assert.strictEqual(chain.responseStatus, 302);
          console.log('\tExpect: redirect location match redirectURI');
          assert.strictEqual(
            testEnv.redirectURI,
            chain.parsedLocationHeader.split('?')[0]);
        } else {
          console.log('\tExpect: status === 200');
          assert.strictEqual(chain.responseStatus, 200);
          console.log('\tExpect: body contains "<title>Resource Decision</title>"');
          assert.ok(chain.responseRawData.indexOf('<title>Resource Decision</title>') >= 0);
        }
        console.log('\tExpect: set-cookie header (because rollingCookie=true)');
        assert.ok((chain.parsedSetCookieHeader != null) &&
        (chain.parsedSetCookieHeader.length > 0));
        console.log('\tExpect: Cookie not changed');
        assert.strictEqual(chain.tempLastSessionCookie, chain.currentSessionCookie);
        const expiresDelta =
          chain.currentSessionCookieExpires - chain.tempLastSessionCookieExpires;
        console.log('\tExpect: Cookie expires value incremented by 10 seconds after time delay');
        assert.ok((expiresDelta >= 9) && (expiresDelta <= 11));
      } else {
        console.log('\tExpect: status === 302');
        assert.strictEqual(chain.responseStatus, 302);
        console.log('\tExpect: Location header redirects to GET /login');
        assert.strictEqual(chain.parsedLocationHeader, '/login');
      }
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 206 GET /dialog/authorize - Elapsed time 3 + 3 + 4 + 10 = 20 seconds, check if expired
  //
  // All type of cookies rejected
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '206 GET /dialog/authorize - Elapsed time 3 + 3 + 4 + 10 = 20 seconds, check if expired';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + chain.savedAuthorizationPath);
    if (config.session.ttl === 8) {
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => sleep(chain, 10, 'Delay - Expecting cookie to be expired'))
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      console.log('\tExpect: Location header redirects to GET /login');
      assert.strictEqual(chain.parsedLocationHeader, '/login');
      return Promise.resolve(chain);
    }
  })

  // -------------------------------
  // 207 GET /dialog/authorize - Elapsed time 3 + 3 + 4 + 10 + 4 = 24 seconds, Done
  //
  // All type of cookies rejected
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '207 GET /dialog/authorize - Elapsed time 3 + 3 + 4 + 10 + 4 = 24 seconds, Done';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + chain.savedAuthorizationPath);
    if (config.session.ttl === 8) {
      return Promise.resolve(chain);
    } else {
      chain.abortSleepTimer = true;
      chain.abortManagedFetch = true;
      chain.skipInlineTests = true;
      return Promise.resolve(chain);
    }
  })
  .then((chain) => sleep(chain, 4, 'Delay - Expecting cookie to be expired'))
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    // Temporary variables no longer needed
    delete chain.tempLastSessionCookie;
    delete chain.tempLastSessionCookieExpires;
    if (chain.skipInlineTests) {
      delete chain.skipInlineTests;
      return Promise.resolve(chain);
    } else {
      logRequest(chain);
      console.log('\tExpect: status === 302');
      assert.strictEqual(chain.responseStatus, 302);
      console.log('\tExpect: Location header redirects to GET /login');
      assert.strictEqual(chain.parsedLocationHeader, '/login');
      return Promise.resolve(chain);
    }
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
