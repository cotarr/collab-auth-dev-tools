// admin-access-check.js
//
// The collab-auth server may optionally provide the user with an
// account administration web page. This script will test the
// access control for all administration web pages to verify that
// a valid cookie and in some cases CSRF token are required to
// view that account administration pages.

// Note that other protected routes that are not related to the administration
// page are tested in the alternate script `debug/protected-routes.js`

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

const Tokens = require('../../collab-auth/node_modules/@dr.pogodin/csurf/tokens.js');
const tokens = new Tokens({});

if (!fs.existsSync('./package.json')) {
  console.log('Must be run from repository base folder as: node debug/admin-access-check.js');
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
  // 50 GET /panel/createuser - Get CSRF Token
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '50 GET /panel/createuser - Get CSRF Token';
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
      chain.rememberedGoodCsrfToken =
        chain.responseRawData.split('name="_csrf" value="')[1].split('">')[0];
    }
    return Promise.resolve(chain);
  }) // 50 GET /panel/createuser - Get CSRF Token

  // -----------------------------------------------
  // 51 POST /panel/createuser - Invalid CSRF Token
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '51 POST /panel/createuser - Invalid CSRF Token';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.savedNewName = 'name' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewNumber = 2000 + Math.floor(Math.random() * 900000);
    chain.savedNewUsername = 'user' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'password' + Math.floor(Math.random() * 100000).toString();
    chain.savedNewRole = 'api.read, user.password';
    chain.savedNewLoginDisabled = false;
    chain.requestBody = {
      name: chain.savedNewName,
      number: chain.savedNewNumber,
      username: chain.savedNewUsername,
      newpassword1: chain.savedNewpassword,
      newpassword2: chain.savedNewpassword,
      role: chain.savedNewRole,
      // Valid CSRF token
      // _csrf: chain.rememberedBadCsrfToken
      // Invalid CSRF Token
      _csrf: tokens.create('abcdefghijklmnop')
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
    logRequest(chain, { ignoreErrorStatus: 403 });
    // console.log(chain.responseRawData);
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 403');
    assert.strictEqual(chain.responseStatus, 403);
    console.log('\tExpect: Error message contains "invalid csrf token"');
    assert.ok(chain.responseErrorMessage.indexOf('invalid csrf token') >= 0);
    delete chain.requestBody;
    return Promise.resolve(chain);
  }) // 51 POST /panel/createuser

  // -----------------------------------------------
  // 52 POST /panel/createclient - Invalid CSRF Token
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '52 POST /panel/createclient - Invalid CSRF Token';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createclient');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.savedNewName = 'name' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewClientId = 'client' + Math.floor(Math.random() * 1000000).toString();
    chain.savedNewSecret = 'secret' + Math.floor(Math.random() * 1000000000).toString();
    chain.savedNewTrustedClient = false;
    chain.savedNewAllowedScope = 'auth.none, auth.info, auth.token, api.read, api.write';
    chain.savedNewRedirectURI = 'http://localhost:3000/login/callback';
    chain.savedNewClientDisabled = false;
    chain.requestBody = {
      name: chain.savedNewName,
      clientId: chain.savedNewClientId,
      clientSecret: chain.savedNewSecret,
      allowedScope: chain.savedNewAllowedScope,
      allowedRedirectURI: chain.savedNewRedirectURI,
      // valid CSRF token
      // _csrf: chain.parsedCsrfToken
      // Invalid CSRF token
      _csrf: tokens.create('abcdefghijklmnop')
    };
    if (chain.savedNewTrustedClient) {
      chain.requestBody.trustedClient = 'on';
    }
    if (chain.savedNewClientDisabled) {
      chain.requestBody.clientDisabled = 'on';
    }

    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 403 });
    // console.log(chain.responseRawData);
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 403');
    assert.strictEqual(chain.responseStatus, 403);
    console.log('\tExpect: Error message contains "invalid csrf token"');
    assert.ok(chain.responseErrorMessage.indexOf('invalid csrf token') >= 0);
    delete chain.requestBody;
    return Promise.resolve(chain);
  }) // 52 POST /panel/createclient

  // -----------------------------------------------
  // 53 POST /panel/createuser - Missing CSRF Token
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '53 POST /panel/createuser - Missing CSRF Token';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.savedNewName = 'name' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewNumber = 2000 + Math.floor(Math.random() * 900000);
    chain.savedNewUsername = 'user' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'password' + Math.floor(Math.random() * 100000).toString();
    chain.savedNewRole = 'api.read, user.password';
    chain.savedNewLoginDisabled = false;
    chain.requestBody = {
      name: chain.savedNewName,
      number: chain.savedNewNumber,
      username: chain.savedNewUsername,
      newpassword1: chain.savedNewpassword,
      newpassword2: chain.savedNewpassword,
      role: chain.savedNewRole
      // Missing CSRF Token
      // _csrf: chain.rememberedBadCsrfToken
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
    logRequest(chain, { ignoreErrorStatus: 422 });
    // console.log(chain.responseRawData);
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 422');
    assert.strictEqual(chain.responseStatus, 422);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"_csrf""\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"_csrf"') >= 0);

    delete chain.requestBody;
    return Promise.resolve(chain);
  }) // 53 POST /panel/createuser

  // ----------------------------------------------------------
  // 100 GET /logout - Invalidate cookie
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '100 GET /logout - Invalidate cookie';
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
  }) // 100 GET /logout
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
      '101 GET /panel/menu - Cookie with signature, logged out';
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
    console.log('\tExpect: parsedLocationHeader === "/login"');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    return Promise.resolve(chain);
  }) // 101 GET /panel/menu

  // ----------------------------------------------------------
  // 102 GET /panel/listusers (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '102 GET /panel/listusers (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/listusers';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/login"');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    return Promise.resolve(chain);
  }) // 102 GET /panel/listusers

  // ----------------------------------------------------------
  // 103 GET /panel/viewuser (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '103 GET /panel/viewuser (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/viewuser';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/login"');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    return Promise.resolve(chain);
  }) // 103 GET /panel/viewuser

  // ----------------------------------------------------------
  // 104 GET /panel/createuser (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '104 GET /panel/createuser (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/createuser';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 104 GET /panel/createuser

  // ----------------------------------------------------------
  // 105 GET /panel/edituser (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '105 GET /panel/edituser (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/edituser';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 105 GET /panel/edituser

  // ----------------------------------------------------------
  // 106 GET /panel/deleteuser (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '106 GET /panel/deleteuser (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/deleteuser';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 106 GET /panel/deleteuser

  // ----------------------------------------------------------
  // 107 GET /panel/listclients (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '107 GET /panel/listclients (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/listclients';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/login"');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    return Promise.resolve(chain);
  }) // 107 GET /panel/listclients

  // ----------------------------------------------------------
  // 108 GET /panel/viewlient (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '108 GET /panel/viewlient (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/viewclient';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/login"');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
    return Promise.resolve(chain);
  }) // 108 GET /panel/viewlient

  // ----------------------------------------------------------
  // 109 GET /panel/createlient (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '109 GET /panel/createlient (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/createclient';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 109 GET /panel/createlient

  // ----------------------------------------------------------
  // 110 GET /panel/editlient (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '110 GET /panel/editlient (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/editclient';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 110 GET /panel/editlient

  // ----------------------------------------------------------
  // 111 GET /panel/deletelient (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '111 GET /panel/deletelient (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/deleteclient';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 111 GET /panel/deletelient

  // ----------------------------------------------------------
  // 112 GET /panel/removealltokens (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '112 GET /panel/removealltokens (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/removealltokens';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 112 GET /panel/removealltokens

  // ----------------------------------------------------------
  // 113 GET /panel/stats (logged out)
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription = '113 GET /panel/stats (logged out)';
    chain.requestFetchURL = testEnv.authURL + '/panel/stats';
    chain.currentSessionCookie = chain.rememberedCookie;
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/login"');
    assert.strictEqual(chain.parsedLocationHeader, '/login');
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
  // 200 POST /panel/createuser (logged out)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '200 POST /panel/createuser (logged out)';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.savedNewName = 'name' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewNumber = 2000 + Math.floor(Math.random() * 900000);
    chain.savedNewUsername = 'user' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'password' + Math.floor(Math.random() * 100000).toString();
    chain.savedNewRole = 'api.read, user.password';
    chain.savedNewLoginDisabled = false;
    chain.requestBody = {
      name: chain.savedNewName,
      number: chain.savedNewNumber,
      username: chain.savedNewUsername,
      newpassword1: chain.savedNewpassword,
      newpassword2: chain.savedNewpassword,
      role: chain.savedNewRole,
      _csrf: chain.rememberedBadCsrfToken
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
    logRequest(chain, { ignoreErrorStatus: 302 });
    console.log('\tExpect: status === 302');
    assert.strictEqual(chain.responseStatus, 302);
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 200 POST /panel/createuser

  // -----------------------------------------------
  // 201 POST /panel/edituser (logged out)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '201 POST /panel/edituser (logged out)';
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
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 201 POST /panel/edituser

  // -----------------------------------------------
  // 202 POST /panel/deleteuser (logged out)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '202 POST /panel/deleteuser (logged out)';
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
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 202 POST /panel/deleteuser

  // -----------------------------------------------
  // 203 POST /panel/createclient (logged out)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '203 POST /panel/createclient (logged out)';
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
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 203 POST /panel/createclient

  // -----------------------------------------------
  // 204 POST /panel/editclient (logged out)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '204 POST /panel/editclient (logged out)';
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
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 204 POST /panel/editclient

  // -----------------------------------------------
  // 205 POST /panel/deleteclient (logged out)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '205 POST /panel/deleteclient (logged out)';
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
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
    return Promise.resolve(chain);
  }) // 205 POST /panel/deleteclient

  // -----------------------------------------------
  // 206 POST /panel/removealltokens (logged out)
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription = '206 POST /panel/removealltokens (logged out)';
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
    console.log('\tExpect: parsedLocationHeader === "/panel/unauthorized"');
    assert.strictEqual(chain.parsedLocationHeader, '/panel/unauthorized');
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
