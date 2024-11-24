// admin-user-edit.js
//
// The collab-auth server may optionally provide the user with
// an account administration web page. This script will exercise
// the functionality of the administration pages used to create
// and modify OAuth 2.0 "user" accounts.
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
  console.log('Must be run from repository base folder as: node debug/admin-user-edit.js');
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
    delete chain.parsedCsrfToken;
    delete chain.requestBody;
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
    console.log('\tExpect: body contains "<title>Web Admin Panel</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Web Admin Panel</title>') >= 0);
    //
    // Parse Data
    //

    return Promise.resolve(chain);
  }) // 5 GET /panel/menu

  // ----------------------------------------------------------
  // 100 GET /panel/listusers - HTML table listing users
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '100 GET /panel/listusers - HTML table listing users';
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
    //
    // Parse Data
    //

    return Promise.resolve(chain);
  }) // 100 GET /panel/listusers

  // ----------------------------------------------------------
  // 101 GET /panel/createuser - HTML data entry form
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '101 GET /panel/createuser - HTML data entry form';
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
    console.log('\tExpect: body contains "<title>Create New User</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Create New User</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Create New User</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Create New User</h2>') >= 0);
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
  }) // 101 GET /panel/createuser

  // -----------------------------------------------
  // 102 POST /panel/createuser - Submit new user form data
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '102 POST /panel/createuser - Submit new user form data';
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
    console.log('\tExpect: body contains "<title>Create New User</title>>"');
    assert.ok(chain.responseRawData.indexOf('<title>Create New User</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Create New User</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Create New User</h2>') >= 0);
    console.log('\tExpect: body contains "New user record successfully saved."');
    assert.ok(chain.responseRawData.indexOf('New user record successfully saved.') >= 0);
    // Temporary variable no longer needed
    delete chain.parsedCsrfToken;
    delete chain.requestBody;
    return Promise.resolve(chain);
  }) // 102 POST /panel/createuser

  // ----------------------------------------------------------
  // 103 GET /panel/listusers - HTML table listing users
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '103 GET /panel/listusers - HTML table listing users';
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
  }) // 103 GET /panel/listusers

  // ----------------------------------------------------------
  // 104 GET /panel/viewuser - HTML table showing selected user data
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '104 GET /panel/viewuser - HTML table showing selected user data';
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
    logRequest(chain);
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: body contains "<title>View User Info</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>View User Info</title>') >= 0);
    console.log('\tExpect: body contains "<h2>View User Info</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>View User Info</h2>') >= 0);

    const parsedUserProps = {};
    parsedUserProps.id =
      chain.responseRawData.split('<td>id</td><td>')[1].split('<')[0];
    parsedUserProps.number = parseInt(
      chain.responseRawData.split('<td>number</td><td>')[1].split('<')[0]);
    parsedUserProps.username =
      chain.responseRawData.split('<td>username</td><td>')[1].split('<')[0];
    parsedUserProps.name =
      chain.responseRawData.split('<td>name</td><td>')[1].split('<')[0];
    parsedUserProps.loginDisabled =
      chain.responseRawData.split('<td>loginDisabled</td><td>')[1].split('<')[0];
    parsedUserProps.role =
      chain.responseRawData.split('<td>role</td><td>')[1].split('<')[0];
    parsedUserProps.lastLogin =
      chain.responseRawData.split('<td>lastLogin</td><td>')[1].split('<')[0];
    //
    // {
    //   id: '5540f136-238c-4795-9519-e4797c633077',
    //   number: '3241',
    //   username: 'user294',
    //   name: 'name485',
    //   loginDisabled: 'No',
    //   role: 'api.read, user.password',
    //   lastLogin: ''
    // }
    //
    // console.log(parsedUserProps);

    console.log('\tExpect: new user.id extracted from page matches');
    assert.strictEqual(parsedUserProps.id, chain.savedNewId);
    console.log('\tExpect: new user.number extracted from page matches');
    assert.strictEqual(parsedUserProps.number, chain.savedNewNumber);
    console.log('\tExpect: new user.username extracted from page matches');
    assert.strictEqual(parsedUserProps.username, chain.savedNewUsername);
    console.log('\tExpect: new user.name extracted from page matches');
    assert.strictEqual(parsedUserProps.name, chain.savedNewName);
    console.log('\tExpect: new user.loginDisabled extracted from page matches');
    if (chain.savedNewLoginDisabled) {
      assert.strictEqual(parsedUserProps.loginDisabled, 'Yes');
    } else {
      assert.strictEqual(parsedUserProps.loginDisabled, 'No');
    }
    console.log('\tExpect: new user.role extracted from page matches');
    assert.strictEqual(parsedUserProps.role, chain.savedNewRole);
    return Promise.resolve(chain);
  }) // 104 GET /panel/viewuser

  // ----------------------------------------------------------
  // 105 GET /panel/edituser - HTML user edit form
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '105 GET /panel/edituser - HTML user edit form';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/edituser?id=' + chain.savedNewId);
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
    console.log('\tExpect: body contains "<title>Edit User</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Edit User</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Edit User</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Edit User</h2>') >= 0);

    const editPresets = {};

    editPresets.id =
      chain.responseRawData.split('<td>id</td></td><td>')[1].split('<')[0];
    editPresets.number = parseInt(
      chain.responseRawData.split('<td>number</td></td><td>')[1].split('<')[0]);
    editPresets.name =
      chain.responseRawData.split('name="name" value="')[1].split('"')[0];
    editPresets.username =
      chain.responseRawData.split('<td>username</td><td>')[1].split('<')[0];
    editPresets.loginDisabled = 'No';
    if (chain.responseRawData.split('name="loginDisabled"')[1]
      .split('></td>')[0].indexOf('checked') >= 0) {
      editPresets.loginDisabled = 'Yes';
    }
    editPresets.role =
      chain.responseRawData.split('name="role" cols="80" rows="3">')[1].split('<')[0];
    //
    // {
    //   id: 'af761fe4-f8c5-4990-bafe-2e395046fb27',
    //   number: '232977',
    //   name: 'name531',
    //   username: 'user337',
    //   loginDisabled: 'No',
    //   role: 'api.read, user.password'
    // }
    // console.log(editPresets);

    console.log('\tExpect: new user.id extracted from page matches');
    assert.strictEqual(editPresets.id, chain.savedNewId);
    console.log('\tExpect: new user.number extracted from page matches');
    assert.strictEqual(editPresets.number, chain.savedNewNumber);
    console.log('\tExpect: new user.name extracted from page matches');
    assert.strictEqual(editPresets.name, chain.savedNewName);
    console.log('\tExpect: new user.username extracted from page matches');
    assert.strictEqual(editPresets.username, chain.savedNewUsername);
    console.log('\tExpect: new user.loginDisabled extracted from page matches');
    if (chain.savedNewLoginDisabled) {
      assert.strictEqual(editPresets.loginDisabled, 'Yes');
    } else {
      assert.strictEqual(editPresets.loginDisabled, 'No');
    }
    console.log('\tExpect: new user.role extracted from page matches');
    assert.strictEqual(editPresets.role, chain.savedNewRole);

    //
    // Parse Data
    //
    if (chain.responseStatus === 200) {
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf" value="')[1].split('">')[0];
    }
    return Promise.resolve(chain);
  }) // 105 GET /panel/edituser

  // -----------------------------------------------
  // 106 POST /panel/edituser - Submit modified user data form data
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '106 POST /panel/edituser - Submit modified user data form data';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/edituser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    // modified...
    chain.savedNewName = 'newname' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'newpassword' + Math.floor(Math.random() * 100000).toString();
    chain.savedNewRole = 'api.read, user.password, new.scope';
    chain.savedNewLoginDisabled = true;

    chain.requestBody = {
      // Read only
      id: chain.savedNewId,
      // Modified for test
      name: chain.savedNewName,
      newpassword1: chain.savedNewpassword,
      newpassword2: chain.savedNewpassword,
      role: chain.savedNewRole,
      // CSRF
      _csrf: chain.parsedCsrfToken
    };
    if (chain.savedNewTrustedClient) {
      chain.requestBody.trustedClient = 'on';
    }
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
    console.log('\tExpect: body contains "<title>Edit User</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Edit User</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Edit User</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Edit User</h2>') >= 0);
    console.log('\tExpect: body contains "Modified user record successfully saved."');
    assert.ok(chain.responseRawData.indexOf('Modified user record successfully saved.') >= 0);
    // Temporary variable no longer needed
    delete chain.requestBody;
    // keep CSRF token for use in data validation error tests
    // delete chain.parsedCsrfToken;
    return Promise.resolve(chain);
  }) // 106 POST /panel/edituser

  // ----------------------------------------------------------
  // 107 GET /panel/viewuser - HTML table showing selected user data
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '104 GET /panel/viewuser - HTML table showing selected user data';
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
    logRequest(chain);
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: body contains "<title>View User Info</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>View User Info</title>') >= 0);
    console.log('\tExpect: body contains "<h2>View User Info</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>View User Info</h2>') >= 0);

    const parsedUserProps = {};
    parsedUserProps.id =
      chain.responseRawData.split('<td>id</td><td>')[1].split('<')[0];
    parsedUserProps.number = parseInt(
      chain.responseRawData.split('<td>number</td><td>')[1].split('<')[0]);
    parsedUserProps.username =
      chain.responseRawData.split('<td>username</td><td>')[1].split('<')[0];
    parsedUserProps.name =
      chain.responseRawData.split('<td>name</td><td>')[1].split('<')[0];
    parsedUserProps.loginDisabled =
      chain.responseRawData.split('<td>loginDisabled</td><td>')[1].split('<')[0];
    parsedUserProps.role =
      chain.responseRawData.split('<td>role</td><td>')[1].split('<')[0];
    parsedUserProps.lastLogin =
      chain.responseRawData.split('<td>lastLogin</td><td>')[1].split('<')[0];
    //
    // {
    //   id: '5540f136-238c-4795-9519-e4797c633077',
    //   number: '3241',
    //   username: 'user294',
    //   name: 'name485',
    //   loginDisabled: 'No',
    //   role: 'api.read, user.password',
    //   lastLogin: ''
    // }
    //
    // console.log(parsedUserProps);

    console.log('\tExpect: new user.id extracted from page matches');
    assert.strictEqual(parsedUserProps.id, chain.savedNewId);
    console.log('\tExpect: new user.number extracted from page matches');
    assert.strictEqual(parsedUserProps.number, chain.savedNewNumber);
    console.log('\tExpect: new user.username extracted from page matches');
    assert.strictEqual(parsedUserProps.username, chain.savedNewUsername);
    console.log('\tExpect: new user.name extracted from page matches');
    assert.strictEqual(parsedUserProps.name, chain.savedNewName);
    console.log('\tExpect: new user.loginDisabled extracted from page matches');
    if (chain.savedNewLoginDisabled) {
      assert.strictEqual(parsedUserProps.loginDisabled, 'Yes');
    } else {
      assert.strictEqual(parsedUserProps.loginDisabled, 'No');
    }
    console.log('\tExpect: new user.role extracted from page matches');
    assert.strictEqual(parsedUserProps.role, chain.savedNewRole);
    return Promise.resolve(chain);
  }) // 107 GET /panel/viewuser

  // -----------------------------------------------
  // 200 POST /panel/edituser - Data validation, edit user, allowed parameters
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '200 POST /panel/edituser - Data validation, edit user, allowed parameters';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/edituser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      // Forbidden prop
      number: chain.savedNewNumber,
      username: chain.savedNewUsername,
      // Server Generated not allowed
      extraneousKey: 'some-value',
      updatedAt: '2024-09-18T13:37:19.143Z',
      createdAt: '2024-09-18T13:37:19.143Z'
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 422 });
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 422');
    assert.strictEqual(chain.responseStatus, 422);

    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"_csrf"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"_csrf"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"id"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"id"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"name"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"name"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"role"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"role"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Forbidden property (read only)","path":"number"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Forbidden property (read only)","path":"number"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Forbidden property (read only)","path":"username"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Forbidden property (read only)","path":"username"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Server generated values not allowed","path":"updatedAt"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Server generated values not allowed","path":"updatedAt"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Server generated values not allowed","path":"createddAt"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Server generated values not allowed","path":"createdAt"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Invalid param","path":"extraneousKey"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid param","path":"extraneousKey"') >= 0);

    return Promise.resolve(chain);
  }) // 200 POST /panel/edituser

  // -----------------------------------------------
  // 201 POST /panel/edituser - Data validation, edit user, valid data check
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '201 POST /panel/edituser - Data validation, edit user, valid data check';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/edituser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.requestBody = {
      // Required index
      id: chain.savedNewId,
      // Test input validation
      name: 'invalid-chars-$#%',
      loginDisabled: 'xyz',
      role: 'invalid-chars-$#%',
      // CSRF
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 422 });
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 422');
    assert.strictEqual(chain.responseStatus, 422);

    console.log('\tExpect: Error message contains \'"msg":"Invalid characters in string","path":"name"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid characters in string","path":"name"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Checkbox requires on/off","path":"loginDisabled"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Checkbox requires on/off","path":"loginDisabled"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Invalid characters in string","path":"role"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid characters in string","path":"role"') >= 0);

    return Promise.resolve(chain);
  }) // 201 POST /panel/edituser

  // -----------------------------------------------
  // 202 POST /panel/edituser - Password mis-match
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '202 POST /panel/edituser - Password mis-match';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/edituser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    // modified...
    chain.savedNewName = 'newname' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'newpassword' + Math.floor(Math.random() * 100000).toString();
    chain.savedNewRole = 'api.read, user.password, new.scope';
    chain.savedNewLoginDisabled = true;

    chain.requestBody = {
      // Read only
      id: chain.savedNewId,
      // Modified for test
      name: chain.savedNewName,
      newpassword1: chain.savedNewpassword,
      newpassword2: chain.savedNewpassword + 'x',
      role: chain.savedNewRole,
      // CSRF
      _csrf: chain.parsedCsrfToken
    };
    if (chain.savedNewTrustedClient) {
      chain.requestBody.trustedClient = 'on';
    }
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
    console.log('\tExpect: body contains "Passwords do not match, aborted"');
    assert.ok(chain.responseRawData.indexOf('Passwords do not match, aborted') >= 0);
    // Temporary variable no longer needed
    delete chain.requestBody;
    // keep CSRF token for use in data validation error tests
    // delete chain.parsedCsrfToken;
    return Promise.resolve(chain);
  }) // 202 POST /panel/edituser

  // -----------------------------------------------
  // 300 POST /panel/createuser - Duplicated username
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '300 POST /panel/createuser - Duplicated username';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.savedNewName = 'name' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'password' + Math.floor(Math.random() * 100000).toString();
    chain.savedNewRole = 'api.read, user.password';
    chain.savedNewLoginDisabled = false;

    chain.requestBody = {
      name: chain.savedNewName,
      // Deliberate change, preserve previous
      number: 2000 + Math.floor(Math.random() * 900000),
      // Test value, duplilcate username
      username: chain.savedNewUsername,
      newpassword1: chain.savedNewpassword,
      newpassword2: chain.savedNewpassword,
      role: chain.savedNewRole,
      _csrf: chain.parsedCsrfToken
    };
    if (chain.savedNewLoginDisabled) {
      chain.requestBody.loginDisabled = 'off';
    }
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 400 });
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 400');
    assert.strictEqual(chain.responseStatus, 400);

    console.log('\tExpect: Error message contains "username or number already exists"');
    assert.ok(chain.responseErrorMessage.indexOf('username or number already exists') >= 0);

    // Temporary variable no longer needed
    delete chain.requestBody;
    // keep CSRF token for use in data validation error tests
    // delete chain.parsedCsrfToken;
    return Promise.resolve(chain);
  }) // 300 POST /panel/createuser

  // -----------------------------------------------
  // 301 POST /panel/createuser - Duplicated number
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '301 POST /panel/createuser - Duplicated number';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.savedNewName = 'name' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'password' + Math.floor(Math.random() * 100000).toString();
    chain.savedNewRole = 'api.read, user.password';
    chain.savedNewLoginDisabled = false;
    chain.requestBody = {
      name: chain.savedNewName,
      // Test value, duplicated
      number: chain.savedNewNumber,
      // Deliberate change, preserve previous
      username: 'newuser' + Math.floor(Math.random() * 1000).toString(),
      newpassword1: chain.savedNewpassword,
      newpassword2: chain.savedNewpassword,
      role: chain.savedNewRole,
      _csrf: chain.parsedCsrfToken
    };
    if (chain.savedNewLoginDisabled) {
      chain.requestBody.loginDisabled = 'off';
    }
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 400 });
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 400');
    assert.strictEqual(chain.responseStatus, 400);

    console.log('\tExpect: Error message contains "username or number already exists"');
    assert.ok(chain.responseErrorMessage.indexOf('username or number already exists') >= 0);

    // Temporary variable no longer needed
    delete chain.requestBody;
    // keep CSRF token for use in data validation error tests
    // delete chain.parsedCsrfToken;
    return Promise.resolve(chain);
  }) // 301 POST /panel/createuser

  // -----------------------------------------------
  // 302 POST /panel/createuser - Password mismatch
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '302 POST /panel/createuser - Password mismatch';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.savedNewNumber = 2000 + Math.floor(Math.random() * 900000);
    chain.savedNewUsername = 'user' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewName = 'name' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'password' + Math.floor(Math.random() * 100000).toString();
    chain.savedNewRole = 'api.read, user.password';
    chain.savedNewLoginDisabled = false;
    chain.requestBody = {
      name: chain.savedNewName,
      // Test value, duplicated
      number: chain.savedNewNumber,
      // Deliberate change, preserve previous
      username: 'newuser' + Math.floor(Math.random() * 1000).toString(),
      newpassword1: 'x' + chain.savedNewpassword,
      newpassword2: chain.savedNewpassword,
      role: chain.savedNewRole,
      _csrf: chain.parsedCsrfToken
    };
    if (chain.savedNewLoginDisabled) {
      chain.requestBody.loginDisabled = 'off';
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
    console.log('\tExpect: body contains "Passwords do not match, aborted"');
    assert.ok(chain.responseRawData.indexOf('Passwords do not match, aborted') >= 0);
    // Temporary variable no longer needed
    delete chain.requestBody;
    // keep CSRF token for use in data validation error tests
    // delete chain.parsedCsrfToken;
    return Promise.resolve(chain);
  }) // 302 POST /panel/createuser

  // -----------------------------------------------
  // 303 POST /panel/createuser - Invalid number, alpha characters
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '303 POST /panel/createuser - Invalid number, alpha characters';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.savedNewName = 'name' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'password' + Math.floor(Math.random() * 100000).toString();
    chain.savedNewRole = 'api.read, user.password';
    chain.savedNewLoginDisabled = false;

    chain.requestBody = {
      name: chain.savedNewName,
      // Test value, non-numeric
      number: '201334A',
      username: 'newuser' + Math.floor(Math.random() * 1000).toString(),
      newpassword1: chain.savedNewpassword,
      newpassword2: chain.savedNewpassword,
      role: chain.savedNewRole,
      _csrf: chain.parsedCsrfToken
    };
    if (chain.savedNewLoginDisabled) {
      chain.requestBody.loginDisabled = 'off';
    }
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 422 });
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 422');
    assert.strictEqual(chain.responseStatus, 422);

    console.log('\tExpect: Error message contains \'"msg":"Invalid positive integer value","path":"number"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid positive integer value","path":"number') >= 0);

    // Temporary variable no longer needed
    delete chain.requestBody;
    // keep CSRF token for use in data validation error tests
    // delete chain.parsedCsrfToken;
    return Promise.resolve(chain);
  }) // 303 POST /panel/createuser

  // -----------------------------------------------
  // 304 POST /panel/createuser - Create user, allowed parameters
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '304 POST /panel/createuser - Create user, allowed parameters';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.savedNewName = 'name' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'password' + Math.floor(Math.random() * 100000).toString();
    chain.savedNewRole = 'api.read, user.password';
    chain.savedNewLoginDisabled = false;

    chain.requestBody = {
      id: chain.savedNewId,
      // not checked
      newpassword2: chain.savedNewPassword,
      // Server Generated not allowed
      extraneousKey: 'some-value',
      updatedAt: '2024-09-18T13:37:19.143Z',
      createdAt: '2024-09-18T13:37:19.143Z'
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 422 });
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 422');
    assert.strictEqual(chain.responseStatus, 422);

    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"_csrf"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"_csrf"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"number"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"number"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"username"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"username"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"newpassowrd1"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"newpassword1"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"name"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"name"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"role"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"role"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Forbidden property (Server generated)","path":"id"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Forbidden property (Server generated)","path":"id"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Forbidden property (Server generated)","path":"updatedAt"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Forbidden property (Server generated)","path":"updatedAt"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Forbidden property (Server generated)","path":"createdAt"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Forbidden property (Server generated)","path":"createdAt"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Invalid param","path":"extraneousKey"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid param","path":"extraneousKey"') >= 0);

    // Temporary variable no longer needed
    delete chain.requestBody;
    // keep CSRF token for use in data validation error tests
    // delete chain.parsedCsrfToken;
    return Promise.resolve(chain);
  }) // 304 POST /panel/createuser

  // -----------------------------------------------
  // 305 POST /panel/createuser - Input data validation
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '305 POST /panel/createuser - Input data validation';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createuser');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';

    chain.savedNewNumber = 2000 + Math.floor(Math.random() * 900000);
    chain.savedNewUsername = 'user' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewPassword = 'password' + Math.floor(Math.random() * 100000).toString();
    chain.savedNewRole = 'api.read, user.password';
    chain.savedNewLoginDisabled = false;
    chain.requestBody = {
      name: 'invalid-chars-$#%',
      number: 2000 + Math.floor(Math.random() * 900000),
      username: 'invalid-chars-$#%',
      newpassword1: '',
      newpassword2: '',
      role: 'invalid-chars-$#%',
      loginDisabled: 'xyz',
      _csrf: chain.parsedCsrfToken
    };
    return Promise.resolve(chain);
  })
  .then((chain) => managedFetch(chain))
  //
  // Assertion Tests...
  //
  .then((chain) => {
    logRequest(chain, { ignoreErrorStatus: 422 });
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 422');
    assert.strictEqual(chain.responseStatus, 422);

    console.log('\tExpect: Error message contains \'"msg":"Invalid characters in string","path":"name"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid characters in string","path":"name"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Invalid characters in string","path":"username"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid characters in string","path":"username"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Invalid characters in string","path":"role"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid characters in string","path":"role"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Checkbox requires on/off","path":"loginDisabled"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Checkbox requires on/off","path":"loginDisabled"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Invalid string length","path":"newpassword1"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid string length","path":"newpassword1"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Invalid string length","path":"newpassword2"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid string length","path":"newpassword2"') >= 0);

    // Temporary variable no longer needed
    delete chain.requestBody;
    // keep CSRF token for use in data validation error tests
    // delete chain.parsedCsrfToken;
    return Promise.resolve(chain);
  }) // 305 POST /panel/createuser

  // ----------------------------------------------------------
  // 900 GET /panel/deleteuser - Panel to confirm delete
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '900 GET /panel/deleteuser - Panel to confirm delete';
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
  }) // 900 GET /panel/deleteuser

  // -----------------------------------------------
  // 901 POST /panel/deleteuser - Submit request to delete user record
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '901 POST /panel/deleteuser - Submit request to delete user record';
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
  }) // 901 POST /panel/deleteuser

  // ----------------------------------------------------------
  // 902 GET /panel/viewuser - Confirm record deleted
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
  }) // 902 GET /panel/viewuser

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
