// admin-scope-check.js
//
// The collab-auth server may optionally provide the user with an account administration web page.
// In order to view the administration page, the web server requires a scope value of "user.admin".
// The user's OAuth 2.0 account must be assigned the role "user.admin".
// In this case where values of "server scope" and "user role" intersect, access is granted.
// This script will create a temporary user account that does not include the required role (scope).
// The temporary account will then be used to confirm the administration page are not accessible.
//
//     # Recommended test configuration
//     LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
//     LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
//     LIMITS_WEB_RATE_LIMIT_COUNT=1000
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
  console.log('Must be run from repository base folder as: node debug/admin-scope.js');
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
  // showJwtMetaData,
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
  }) // 1 GET /status

  // ----------------------------------------------------------
  // 2 GET /panel/menu - Account Administration Menu request #1 (before login)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '2 GET /panel/menu - Account Administration Menu request #1 (before login)';
    chain.requestMethod = 'GET';
    chain.savedAuthorizationPath = encodeURI('/panel/menu');
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/menu');
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
    // console.log(chain.responseRawData);
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
  }) // 2 GET /panel/menu

  // -------------------------------
  // 3 GET /login - Get login form
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '3 GET /login - Get login form';
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
    // console.log(chain.responseRawData);

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
      // After login, this CSRF token will be invalid, a new one will be created, stored in session
      chain.rememberedBadCsrfToken =
        chain.responseRawData.split('name="_csrf"')[1].split('value="')[1].split('">')[0];
    }
    return Promise.resolve(chain);
  }) // 3 GET /login

  // -----------------------------------------------
  // 4 POST /login - Submit username and password
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '4 POST /login - Submit username and password';
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
  // Save cookie for because has valid signature
  //
  .then((chain) => {
    if (chain.responseStatus === 302) {
      chain.rememberedCookie = chain.currentSessionCookie;
      chain.rememberedGoodCsrfToken = chain.parsedCsrfToken;
    } else {
      return Promise.reject(new Error('Error attempting to obtain cookie and CSRF token'));
    }
    return Promise.resolve(chain);
  })
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(chain.responseRawData);

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
    delete chain.requestBody;
    // Delete, no longer valid
    delete chain.parsedCsrfToken;
    return Promise.resolve(chain);
  }) // 4 POST /login

  // ----------------------------------------------------------
  // 5 GET /panel/menu - Account Administration Menu request #2 (after login)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '5 GET /panel/menu - Account Administration Menu request #2 (after login)';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + '/panel/menu';
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
    // console.log(chain.responseRawData);
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    return Promise.resolve(chain);
  }) // 5 GET /panel/menu

  // ----------------------------------------------------------
  // 50 GET /panel/createuser - get CSRF token
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '50 GET /panel/createuser - get CSRF token';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
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
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: body contains "name="_csrf" value=\\""');
    assert.ok(chain.responseRawData.indexOf('name="_csrf" value="') >= 0);
    //
    // Parse Data
    //
    if (chain.responseStatus === 200) {
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf" value="')[1].split('">')[0];
    }
    return Promise.resolve(chain);
  }) // 50 GET /panel/createuser

  // -----------------------------------------------
  // 51 POST /panel/createuser - New user with limited scope (role)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '51 POST /panel/createuser - New user with limited scope (role)';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.savedNewName = 'Not Administrator';
    chain.savedNewNumber = 2000 + Math.floor(Math.random() * 900000);
    chain.savedNewUsername = 'not-admin-' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'password' + Math.floor(Math.random() * 100000).toString();
    // The role (scope) must not contain "user.admin"
    chain.savedNewRole = 'user.password';
    chain.savedNewLoginDisabled = false;
    chain.requestBody = {
      name: chain.savedNewName,
      number: chain.savedNewNumber,
      username: chain.savedNewUsername,
      newpassword1: chain.savedNewpassword,
      newpassword2: chain.savedNewpassword,
      role: chain.savedNewRole,
      _csrf: chain.parsedCsrfToken
    };
    if (chain.savedNewLoginDisabled) {
      chain.requestBody.loginDisabled = 'on';
    }
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
    console.log('\tExpect: body contains "New user record successfully saved."');
    assert.ok(chain.responseRawData.indexOf('New user record successfully saved.') >= 0);
    // Temporary variable no longer needed
    delete chain.parsedCsrfToken;
    delete chain.requestBody;
    return Promise.resolve(chain);
  }) // 51 POST /panel/createuser

  // ----------------------------------------------------------
  // 52 GET /logout - Logout of admin account
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '52 GET /logout - Logout of admin account';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/logout');
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
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: body contains "logged out of the authorization server."');
    assert.ok(chain.responseRawData.indexOf('logged out of the authorization server.') >= 0);
    return Promise.resolve(chain);
  }) // 52 GET /logout

  // -------------------------------
  // 53 GET /login - Get CSRF token from login form
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '53 GET /login - Get CSRF token from login form';
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
    // console.log(chain.responseRawData);

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
    }
    return Promise.resolve(chain);
  }) // 53 GET /login

  // -----------------------------------------------
  // 54 POST /login - Login as not admin user
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '54 POST /login - Submit username and password';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/login');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      username: chain.savedNewUsername,
      password: chain.savedNewpassword,
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
  // Save cookie for because has valid signature
  //
  .then((chain) => {
    if (chain.responseStatus === 302) {
      chain.rememberedCookie = chain.currentSessionCookie;
      chain.rememberedGoodCsrfToken = chain.parsedCsrfToken;
    } else {
      return Promise.reject(new Error('Error attempting to obtain cookie and CSRF token'));
    }
    return Promise.resolve(chain);
  })
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: Redirect URI to match /redirecterror (no saved URL)');
    assert.strictEqual(
      '/redirecterror',
      chain.parsedLocationHeader);

    // Temporary variable no longer needed
    delete chain.requestBody;
    return Promise.resolve(chain);
  }) // 54 POST /login - Login as not admin user

  // -------------------------------
  // 100 GET /secure - Confirm logged in
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '100 GET /secure - Confirm logged in';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/secure');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'application/json';
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
    console.log('\tExpect: response property { authenticated: true }');
    assert.strictEqual(chain.responseRawData.authenticated, true);
    //
    // Parse Data
    //
    return Promise.resolve(chain);
  }) // 100 GET /secure
  //
  //
  // ----------------------------------------------------------
  //                      N O T E
  //
  // All GET requests have similar configuration
  // Therefore, in the next section, only properties that change
  // will be modified in each request.
  // ----------------------------------------------------------
  //
  //
  // ----------------------------------------------------------
  // 101 GET /panel/menu - Cookie with signature, logged out
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '101 GET /panel/menu - (insufficient scope)';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = testEnv.authURL + '/panel/menu';
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 101 GET /panel/menu

  // ----------------------------------------------------------
  // 102 GET /panel/listusers (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '102 GET /panel/listusers (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/listusers';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 102 GET /panel/listusers

  // ----------------------------------------------------------
  // 102 GET /panel/listusers (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '102 GET /panel/listusers (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/listusers';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 102 GET /panel/listusers

  // ----------------------------------------------------------
  // 103 GET /panel/viewuser (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '103 GET /panel/viewuser (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/viewuser';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 103 GET /panel/viewuser

  // ----------------------------------------------------------
  // 104 GET /panel/createuser (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '104 GET /panel/createuser (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/createuser';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 104 GET /panel/createuser

  // ----------------------------------------------------------
  // 105 GET /panel/edituser (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '105 GET /panel/edituser (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/edituser';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 105 GET /panel/edituser

  // ----------------------------------------------------------
  // 106 GET /panel/deleteuser (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '106 GET /panel/deleteuser (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/deleteuser';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 106 GET /panel/deleteuser

  // ----------------------------------------------------------
  // 107 GET /panel/listclients (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '107 GET /panel/listclients (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/listclients';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 107 GET /panel/listclients

  // ----------------------------------------------------------
  // 108 GET /panel/viewlient (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '108 GET /panel/viewlient (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/viewclient';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 108 GET /panel/viewlient

  // ----------------------------------------------------------
  // 109 GET /panel/createlient (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '109 GET /panel/createlient (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/createclient';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 109 GET /panel/createlient

  // ----------------------------------------------------------
  // 110 GET /panel/editlient (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '110 GET /panel/editlient (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/editclient';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 110 GET /panel/editlient

  // ----------------------------------------------------------
  // 111 GET /panel/deletelient (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '111 GET /panel/deletelient (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/deleteclient';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 111 GET /panel/deletelient

  // ----------------------------------------------------------
  // 112 GET /panel/removealltokens (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '112 GET /panel/removealltokens (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/removealltokens';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 112 GET /panel/removealltokens

  // ----------------------------------------------------------
  // 113 GET /panel/stats (insufficient scope)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '113 GET /panel/stats (insufficient scope)';
    chain.requestFetchURL = testEnv.authURL + '/panel/stats';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 113 GET /panel/stats

  // ----------------------------------------------------------
  // 114 GET /panel/unauthorized (logged out, expect 200)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '114 GET /panel/unauthorized (logged out, expect 200)';
    chain.requestFetchURL = testEnv.authURL + '/panel/unauthorized';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    return Promise.resolve(chain);
  }) // 114 GET /panel/unauthorized

  // ----------------------------------------------------------
  // 115 GET /panel/not-found (404 not found)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '115 GET /panel/not-found (404 not found)';
    chain.requestFetchURL = testEnv.authURL + '/panel/not-found';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 404 });
    console.log('\tExpect: status === 404');
    assert.strictEqual(chain.responseStatus, 404);
    return Promise.resolve(chain);
  }) // 115 GET /panel/not-found
  //
  //
  // ----------------------------------------------------------
  //                      N O T E
  //
  // All POST requests have similar configuration
  // Therefore, in the next section, only properties that change
  // will be modified in each request.
  // ----------------------------------------------------------
  //
  // -----------------------------------------------
  // 200 POST /panel/createuser (insufficient scope)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '200 POST /panel/createuser (insufficient scope)';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    const tempUserPassword = 'password' + Math.floor(Math.random() * 100000).toString();
    chain.requestBody = {
      name: 'name' + Math.floor(Math.random() * 1000).toString(),
      number: 2000 + Math.floor(Math.random() * 900000),
      username: 'user' + Math.floor(Math.random() * 1000).toString(),
      newpassword1: tempUserPassword,
      newpassword2: tempUserPassword,
      role: 'api.read, user.password',
      _csrf: chain.rememberedBadCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 200 POST /panel/createuser

  // -----------------------------------------------
  // 201 POST /panel/edituser (insufficient scope)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '201 POST /panel/edituser (insufficient scope)';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/edituser');
    chain.requestBody = {
      dummy: 'value'
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 201 POST /panel/edituser

  // -----------------------------------------------
  // 202 POST /panel/deleteuser (insufficient scope)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '202 POST /panel/deleteuser (insufficient scope)';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/deleteuser');
    chain.requestBody = {
      dummy: 'value'
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 202 POST /panel/deleteuser

  // -----------------------------------------------
  // 203 POST /panel/createclient (insufficient scope)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '203 POST /panel/createclient (insufficient scope)';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createclient');
    chain.requestBody = {
      dummy: 'value'
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 203 POST /panel/createclient

  // -----------------------------------------------
  // 204 POST /panel/editclient (insufficient scope)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '204 POST /panel/editclient (insufficient scope)';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/editclient');
    chain.requestBody = {
      dummy: 'value'
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 204 POST /panel/editclient

  // -----------------------------------------------
  // 205 POST /panel/deleteclient (insufficient scope)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '205 POST /panel/deleteclient (insufficient scope)';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/deleteclient');
    chain.requestBody = {
      dummy: 'value'
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 205 POST /panel/deleteclient

  // -----------------------------------------------
  // 206 POST /panel/removealltokens (insufficient scope)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '206 POST /panel/removealltokens (insufficient scope)';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/removealltokens');
    chain.requestBody = {
      dummy: 'value'
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/noscope"');
    assert.strictEqual(chain.parsedLocationHeader, '/noscope');
    return Promise.resolve(chain);
  }) // 206 POST /panel/removealltokens

  // -----------------------------------------------
  // 207 POST /panel/not-found (404 not found)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '207 POST /panel/not-found (404 not found)';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/not-found');
    chain.requestBody = {
      dummy: 'value'
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 404 });
    console.log('\tExpect: status === 404');
    assert.strictEqual(chain.responseStatus, 404);
    return Promise.resolve(chain);
  }) // 207 POST /panel/not-found

  // ----------------------------------------------------------
  // 900 GET /logout - Logout of non-admin (temporary) account
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '900 GET /logout - Logout of non-admin (temporary) account';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/logout');
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
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: body contains "logged out of the authorization server."');
    assert.ok(chain.responseRawData.indexOf('logged out of the authorization server.') >= 0);
    return Promise.resolve(chain);
  }) // 900 GET /logout

  // -------------------------------
  // 901 GET /login - Get CSRF token from login form
  // -------------------------------
  .then((chain) => {
    chain.testDescription =
      '901 GET /login - Get CSRF token from login form';
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
    // console.log(chain.responseRawData);

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
    }
    return Promise.resolve(chain);
  }) // 901 GET /login

  // -----------------------------------------------
  // 902 POST /login - Login as administrator
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '902 POST /login - Login as administrator';
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
  // Save cookie for because has valid signature
  //
  .then((chain) => {
    if (chain.responseStatus === 302) {
      chain.rememberedCookie = chain.currentSessionCookie;
      chain.rememberedGoodCsrfToken = chain.parsedCsrfToken;
    } else {
      return Promise.reject(new Error('Error attempting to obtain cookie and CSRF token'));
    }
    return Promise.resolve(chain);
  })
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain);
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: Redirect URI to match /redirecterror (no saved URL)');
    assert.strictEqual(
      '/redirecterror',
      chain.parsedLocationHeader);

    // Temporary variable no longer needed
    delete chain.requestBody;
    // Delete, no longer valid
    delete chain.parsedCsrfToken;
    return Promise.resolve(chain);
  }) // 902 POST /login

  // ----------------------------------------------------------
  // 903 GET /panel/listusers - Get temporary users id property
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '903 GET /panel/listusers - Get temporary users id property';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/listusers');
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
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: body contains "<title>Account Info</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Account Info</title>') >= 0);
    console.log('\tExpect: body contains "<h2>List Users</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>List Users</h2>') >= 0);

    // Extract table column label names from HTML on page
    //
    // [
    //   'id',
    //   'number',
    //   'username',
    //   'name',
    //   'role',
    //   'lastLogin'
    // ]
    //
    // Body contains web page HTML code, split into array using HTML row tag.
    let parsedColumnHeadings = Array.from(chain.responseRawData.split('<tr>'));
    parsedColumnHeadings = Array.from(parsedColumnHeadings[1].split('<th>'));
    // Remove unused leading columns from start of array
    parsedColumnHeadings.splice(0, 3);
    // Remove unused tailing columns from end of array
    parsedColumnHeadings.splice(parsedColumnHeadings.length - 1, 1);
    // Clean each element to remove trailing content
    for (let i = 0; i < parsedColumnHeadings.length; i++) {
      parsedColumnHeadings[i] = parsedColumnHeadings[i].split('</th>')[0];
    }
    // console.log(parsedColumnHeadings);

    // Extract user account data from each row, column, into an object
    //
    // [
    //   {
    //     id: '31f3f72b-7c46-4b42-b97d-48e9f9b6a7f1',
    //     number: '276960',
    //     username: 'user943',
    //     name: 'newname543',
    //     role: 'api.read, user.password',
    //     lastLogin: ''
    //   },
    //   {
    //     id: 'c045a3db-eca9-42ce-b42c-f1e41dcc4748',
    //     number: '362198',
    //     username: 'user950',
    //     name: 'newname20',
    //     role: 'api.read, user.password',
    //     lastLogin: ''
    //   },
    // ]
    // Body contains web page HTML code
    let parsedRowData = chain.responseRawData;

    // Disabled accounts will be flagged on server side render
    // by adding class to <tr> element.
    // Remove the class from <tr> elements before parsing content.
    while (parsedRowData.indexOf('<tr class="tr-list-disabled">') >= 0) {
      parsedRowData = parsedRowData.replace('<tr class="tr-list-disabled">', '<tr>');
    }
    // console.log(parsedRowData);

    // Array of objects for each user account, parsed from table
    const userArray = [];

    // Split string into array, using row tag'<tr>' as separator string.
    parsedRowData = Array.from(parsedRowData.split('<tr>'));
    // Remove unused leading columns from start of first data row
    parsedRowData.splice(0, 2);
    // Remove unused content after last row closing tag </tr>
    for (let i = 1; i < parsedRowData.length; i++) {
      parsedRowData[i] = parsedRowData[i].split('</tr>')[0];
    }
    // console.log(parsedRowData);
    // Loop each row
    for (let i = 0; i < parsedRowData.length; i++) {
      // For each row of data in the table,
      // Create an array of string using HTML <td> tag.
      const parsedTableData = Array.from(parsedRowData[i].split('<td>'));
      // Remove unused array elements from start of row
      parsedTableData.splice(0, 3);
      // Remove unused array elements at end of array
      parsedTableData.splice(parsedTableData.length - 1, 1);

      // Loop each column (in a row)
      // Clean each entry to remove tailing content
      for (let j = 0; j < parsedTableData.length; j++) {
        // Clean </td> and content after it for each row.
        parsedTableData[j] = parsedTableData[j].split('</td>')[0];
      }
      const tempUserObj = {};
      for (let j = 0; j < parsedTableData.length; j++) {
        tempUserObj[parsedColumnHeadings[j]] = parsedTableData[j];
      }

      // console.log(tempUserObj);
      userArray.push(tempUserObj);
    }
    // console.log(userArray);
    //
    // Next, find the entry that matches the userId of the new user
    //
    let newUserIndex = -1;
    if (userArray.length > 0) {
      for (let i = 0; i < userArray.length; i++) {
        if (userArray[i].username === chain.savedNewUsername) {
          newUserIndex = i;
        }
      }
      if (newUserIndex < 0) {
        throw new Error('Error extracting user record from HTML page (1)');
      }
    } else {
      throw new Error('Error extracting user record from HTML page (2)');
    }
    // console.log(userArray[newUserIndex]);

    console.log('\tExpect: new user.username extracted from page matches');
    assert.strictEqual(userArray[newUserIndex].username, chain.savedNewUsername);
    console.log('\tExpect: new user.name extracted from page matches');
    assert.strictEqual(userArray[newUserIndex].name, chain.savedNewName);
    console.log('\tExpect: new user.role extracted from page matches');
    assert.strictEqual(userArray[newUserIndex].role, chain.savedNewRole);
    //
    // Parse Data
    //
    // Get the new UUID.v4 generated by server
    chain.savedNewId = userArray[newUserIndex].id;
    return Promise.resolve(chain);
  }) // 903 GET /panel/listusers

  // ----------------------------------------------------------
  // 904 GET /panel/deleteuser - Panel to confirm delete
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '904 GET /panel/deleteuser - Panel to confirm delete';
    chain.requestMethod = 'GET';
    chain.requestFetchURL =
      encodeURI(testEnv.authURL + '/panel/deleteuser?id=' + chain.savedNewId);
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
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: body contains "<title>Confirm Delete User</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Confirm Delete User</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Confirm Delete User</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Confirm Delete User</h2>') >= 0);

    const parsedId = chain.responseRawData.split('user record id=')[1]
      .split(' from the database')[0];
    console.log('\tExpect: previous user.id (to be deleted) extracted from page matches');
    assert.strictEqual(parsedId, chain.savedNewId);
    //
    // Parse Data
    //
    if (chain.responseStatus === 200) {
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf" value="')[1].split('">')[0];
    }
    return Promise.resolve(chain);
  }) // 904 GET /panel/deleteuser

  // -----------------------------------------------
  // 905 POST /panel/deleteuser - Submit request to delete user record
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '905 POST /panel/deleteuser - Submit request to delete user record';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/deleteuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      id: chain.savedNewId,
      _csrf: chain.parsedCsrfToken
    };
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
    console.log('\tExpect: body contains "<title>Delete User</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Delete User</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Delete User</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Delete User</h2>') >= 0);
    console.log('\tExpect: body contains "User successfully deleted."');
    assert.ok(chain.responseRawData.indexOf('User successfully deleted.') >= 0);
    // Temporary variable no longer needed
    delete chain.parsedCsrfToken;
    delete chain.requestBody;
    return Promise.resolve(chain);
  }) // 905 POST /panel/deleteuser

  // ----------------------------------------------------------
  // 906 GET /panel/viewuser - Confirm record deleted
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '902 GET /panel/viewuser - Confirm record deleted';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/viewuser?id=' + chain.savedNewId);
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 400 });
    // console.log(chain.responseRawData);
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 400');
    assert.strictEqual(chain.responseStatus, 400);
    console.log('\tExpect: Error message contains "Invalid Id parameter"');
    assert.ok(chain.responseErrorMessage.indexOf('Invalid Id parameter') >= 0);
    return Promise.resolve(chain);
  }) // 906 GET /panel/viewuser
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
