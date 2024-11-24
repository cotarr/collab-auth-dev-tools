// admin-client-edit.js
//
// The collab-auth server may optionally provide the user with an
// account administration web page. This script will exercise the
// functionality of the administration pages used to create and
// modify OAuth 2.0 "client" accounts. This test requires the configuration
// setting `OAUTH2_EDITOR_SHOW_CLIENT_SECRET=true` so the text can
// verify the client data values.
//
//    # Recommended test configuration
//    LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
//    LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
//    LIMITS_WEB_RATE_LIMIT_COUNT=1000
//    OAUTH2_EDITOR_SHOW_CLIENT_SECRET=true
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
  console.log('Must be run from repository base folder as: node debug/admin-client-edit.js');
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
  // 100 GET /panel/listclients - HTML table listing clients
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '100 GET /panel/listclients - HTML table listing clients';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/listclients');
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
    console.log('\tExpect: body contains "<h2>List Clients</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>List Clients</h2>') >= 0);
    //
    // Parse Data
    //

    return Promise.resolve(chain);
  }) // 100 GET /panel/listclients

  // ----------------------------------------------------------
  // 101 GET /panel/createclient - HTML data entry form
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '101 GET /panel/createclient - HTML data entry form';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createclient');
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
    console.log('\tExpect: body contains "<title>Create New Client</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Create New Client</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Create New Client</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Create New Client</h2>') >= 0);
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
  }) // 101 GET /panel/createclient

  // -----------------------------------------------
  // 102 POST /panel/createclient - Submit new client form data
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '102 POST /panel/createclient - Submit new client form data';
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
      _csrf: chain.parsedCsrfToken
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
    logRequest(chain);
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: body contains "<title>Create New Client</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Create New Client</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Create New Client</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Create New Client</h2>') >= 0);
    console.log('\tExpect: body contains "New client record successfully saved."');
    assert.ok(chain.responseRawData.indexOf('New client record successfully saved.') >= 0);
    // Temporary variable no longer needed
    delete chain.parsedCsrfToken;
    delete chain.requestBody;
    return Promise.resolve(chain);
  }) // 102 POST /panel/createclient

  // ----------------------------------------------------------
  // 103 GET /panel/listclients - HTML table listing clients
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '103 GET /panel/listclients - HTML table listing clients';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/listclients');
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
    console.log('\tExpect: body contains "<h2>List Clients</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>List Clients</h2>') >= 0);

    // Extract table column label names from HTML on page
    //
    // parsedColumnHeadings = [
    //   'id',
    //   'clientId',
    //   'name',
    //   'allowedScope'
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

    // Extract client account data from each row, column, into an object
    //
    // clientArray = [
    //   {
    //     id: 'e9ad9574-2c9e-4722-8a3e-a0ff797a1bcb',
    //     clientId: 'client451621',
    //     name: 'newname237',
    //     allowedScope: 'auth.none'
    //   },
    //   {
    //     id: 'c5d04092-df38-4421-8426-8bd4c8635af4',
    //     clientId: 'def456',
    //     name: 'collab-backend-api',
    //     allowedScope: 'auth.info'
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

    // Array of objects for each client account, parsed from table
    const clientArray = [];

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
      const tempClientObj = {};
      for (let j = 0; j < parsedTableData.length; j++) {
        tempClientObj[parsedColumnHeadings[j]] = parsedTableData[j];
      }

      // console.log(tempClientObj);
      clientArray.push(tempClientObj);
    }
    // console.log(clientArray);
    //
    // Next, find the entry that matches the clientId of the new client
    //
    let newClientIndex = -1;
    if (clientArray.length > 0) {
      for (let i = 0; i < clientArray.length; i++) {
        if (clientArray[i].clientId === chain.savedNewClientId) {
          newClientIndex = i;
        }
      }
      if (newClientIndex < 0) {
        throw new Error('Error extracting client record from HTML page (1)');
      }
    } else {
      throw new Error('Error extracting client record from HTML page (2)');
    }

    console.log('\tExpect: new client.clientId extracted from page matches');
    assert.strictEqual(clientArray[newClientIndex].clientId, chain.savedNewClientId);
    console.log('\tExpect: new client.name extracted from page matches');
    assert.strictEqual(clientArray[newClientIndex].name, chain.savedNewName);
    console.log('\tExpect: new client.allowedScope extracted from page matches');
    assert.strictEqual(clientArray[newClientIndex].allowedScope, chain.savedNewAllowedScope);

    //
    // Parse Data
    //
    // Get the new UUID.v4 generated by server
    chain.savedNewId = clientArray[newClientIndex].id;
    return Promise.resolve(chain);
  }) // 103 GET /panel/listclients

  // ----------------------------------------------------------
  // 104 GET /panel/viewclient - HTML table showing selected client data
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '104 GET /panel/viewclient - HTML table showing selected client data';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/viewclient?id=' + chain.savedNewId);
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
    console.log('\tExpect: body contains "<title>View Client</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>View Client</title>') >= 0);
    console.log('\tExpect: body contains "<h2>View Client Info</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>View Client Info</h2>') >= 0);

    const parsedClientProps = {};
    parsedClientProps.id =
      chain.responseRawData.split('<td>id</td><td>')[1].split('<')[0];
    parsedClientProps.name =
      chain.responseRawData.split('<td>name</td><td>')[1].split('<')[0];
    parsedClientProps.clientId =
      chain.responseRawData.split('<td>clientId</td><td>')[1].split('<')[0];
    parsedClientProps.clientSecret =
      chain.responseRawData.split('<td>clientSecret</td><td>')[1].split('<')[0];
    parsedClientProps.trustedClient =
      chain.responseRawData.split('<td>trustedClient</td><td>')[1].split('<')[0];
    parsedClientProps.allowedScope =
      chain.responseRawData.split('<td>allowedScope</td><td>')[1].split('<')[0];
    parsedClientProps.allowedRedirectURI =
      chain.responseRawData.split('<td>allowedRedirectURI</td><td>')[1].split('<')[0];
    parsedClientProps.clientDisabled =
      chain.responseRawData.split('<td>clientDisabled</td><td>')[1].split('<')[0];
    //
    // parsedClientProps = {
    //   id: '106f1fa2-087a-4785-9983-97e523c4a0f7',
    //   name: 'name897',
    //   clientId: 'client69649',
    //   clientSecret: 'secret659517331',
    //   trustedClient: 'No',
    //   allowedScope: 'auth.none, auth.info, auth.token, api.read, api.write',
    //   allowedRedirectURI: 'http://localhost:3000/login/callback',
    //   clientDisabled: 'No'
    // }
    // console.log(parsedClientProps);

    console.log('\tExpect: new client.id extracted from page matches');
    assert.strictEqual(parsedClientProps.id, chain.savedNewId);
    console.log('\tExpect: new client.name extracted from page matches');
    assert.strictEqual(parsedClientProps.name, chain.savedNewName);
    console.log('\tExpect: new client.clientId extracted from page matches');
    assert.strictEqual(parsedClientProps.clientId, chain.savedNewClientId);
    console.log('\tExpect: new client.clientSecret extracted from page matches');
    assert.strictEqual(parsedClientProps.clientSecret, chain.savedNewSecret);
    console.log('\tExpect: new client.trustedClient extracted from page matches');
    if (chain.savedNewTrustedClient) {
      assert.strictEqual(parsedClientProps.trustedClient, 'Yes');
    } else {
      assert.strictEqual(parsedClientProps.trustedClient, 'No');
    }
    console.log('\tExpect: new client.allowedScope extracted from page matches');
    assert.strictEqual(parsedClientProps.allowedScope, chain.savedNewAllowedScope);
    console.log('\tExpect: new client.allowedRedirectURI extracted from page matches');
    assert.strictEqual(parsedClientProps.allowedRedirectURI, chain.savedNewRedirectURI);
    console.log('\tExpect: new client.clientDisabled extracted from page matches');
    if (chain.savedNewClientDisabled) {
      assert.strictEqual(parsedClientProps.clientDisabled, 'Yes');
    } else {
      assert.strictEqual(parsedClientProps.clientDisabled, 'No');
    }
    return Promise.resolve(chain);
  }) // 104 GET /panel/viewclient

  // ----------------------------------------------------------
  // 105 GET /panel/editclient - HTML client edit form
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '105 GET /panel/editclient - HTML client edit form';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/editclient?id=' + chain.savedNewId);
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
    console.log('\tExpect: body contains "<title>Edit Client</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Edit Client</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Edit Client</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Edit Client</h2>') >= 0);

    const editPresets = {};

    editPresets.id =
      chain.responseRawData.split('<td>id</td></td><td>')[1].split('<')[0];
    editPresets.clientId =
      chain.responseRawData.split('<td>clientId</td><td>')[1].split('<')[0];
    editPresets.name =
      chain.responseRawData.split('name="name" value="')[1].split('"')[0];
    editPresets.clientSecret =
      chain.responseRawData.split('name="clientSecret" value="')[1].split('"')[0];
    editPresets.trustedClient = 'No';
    if (chain.responseRawData.split('name="trustedClient"')[1]
      .split('></td>')[0].indexOf('checked') >= 0) {
      editPresets.trustedClient = 'Yes';
    }
    editPresets.allowedScope =
      chain.responseRawData.split('name="allowedScope"')[1].split('>')[1].split('<')[0];
    editPresets.allowedRedirectURI =
      chain.responseRawData.split('name="allowedRedirectURI"')[1].split('>')[1].split('<')[0];
    editPresets.clientDisabled = 'No';
    if (chain.responseRawData.split('name="clientDisabled"')[1]
      .split('></td>')[0].indexOf('checked') >= 0) {
      editPresets.clientDisabled = 'Yes';
    }
    // editPresets {
    //   id: 'e9ad9574-2c9e-4722-8a3e-a0ff797a1bcb',
    //   clientId: 'client451621',
    //   name: 'name889',
    //   clientSecret: 'secret362833833',
    //   trustedClient: 'No',
    //   allowedScope: 'auth.none, auth.info, auth.token, api.read, api.write',
    //   allowedRedirectURI: 'http://localhost:3000/login/callback',
    //   clientDisabled: 'No'
    // }
    // console.log(editPresets);

    console.log('\tExpect: new client.id extracted from page matches');
    assert.strictEqual(editPresets.id, chain.savedNewId);
    console.log('\tExpect: new client.name extracted from page matches');
    assert.strictEqual(editPresets.name, chain.savedNewName);
    console.log('\tExpect: new client.clientId extracted from page matches');
    assert.strictEqual(editPresets.clientId, chain.savedNewClientId);
    console.log('\tExpect: new client.clientSecret extracted from page matches');
    assert.strictEqual(editPresets.clientSecret, chain.savedNewSecret);
    console.log('\tExpect: new client.trustedClient extracted from page matches');
    if (chain.savedNewTrustedClient) {
      assert.strictEqual(editPresets.trustedClient, 'Yes');
    } else {
      assert.strictEqual(editPresets.trustedClient, 'No');
    }
    console.log('\tExpect: new client.allowedScope extracted from page matches');
    assert.strictEqual(editPresets.allowedScope, chain.savedNewAllowedScope);
    console.log('\tExpect: new client.allowedRedirectURI extracted from page matches');
    assert.strictEqual(editPresets.allowedRedirectURI, chain.savedNewRedirectURI);
    console.log('\tExpect: new client.clientDisabled extracted from page matches');
    if (chain.savedNewClientDisabled) {
      assert.strictEqual(editPresets.clientDisabled, 'Yes');
    } else {
      assert.strictEqual(editPresets.clientDisabled, 'No');
    }
    //
    // Parse Data
    //
    if (chain.responseStatus === 200) {
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf" value="')[1].split('">')[0];
    }
    return Promise.resolve(chain);
  }) // 105 GET /panel/editclient

  // -----------------------------------------------
  // 106 POST /panel/editclient - Submit new client form data
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '106 POST /panel/editclient - Submit new client form data';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/editclient');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    // Modified...
    chain.savedNewName = 'newname' + Math.floor(Math.random() * 1000).toString();
    chain.savedNewSecret = 'newsecret' + Math.floor(Math.random() * 1000000000).toString();
    chain.savedNewTrustedClient = true;
    chain.savedNewAllowedScope = 'auth.none';
    chain.savedNewRedirectURI = 'http://127.0.0.1:3000/login/callback';
    chain.savedNewClientDisabled = true;

    chain.requestBody = {
      // read only
      id: chain.savedNewId,
      // Modified for test
      name: chain.savedNewName,
      clientSecret: chain.savedNewSecret,
      allowedScope: chain.savedNewAllowedScope,
      allowedRedirectURI: chain.savedNewRedirectURI,
      // CSRF
      _csrf: chain.parsedCsrfToken
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
    logRequest(chain);
    // console.log(chain.responseRawData);

    console.log('\tExpect: status === 200');
    assert.strictEqual(chain.responseStatus, 200);
    console.log('\tExpect: body contains "<title>Edit Client</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Edit Client</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Edit Client</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Edit Client</h2>') >= 0);
    console.log('\tExpect: body contains "Modified client record successfully saved."');
    assert.ok(chain.responseRawData.indexOf('Modified client record successfully saved.') >= 0);
    // Temporary variable no longer needed
    delete chain.requestBody;
    // keep CSRF token for use in data validation error tests
    // delete chain.parsedCsrfToken;
    return Promise.resolve(chain);
  }) // 106 POST /panel/editclient

  // ----------------------------------------------------------
  // 107 GET /panel/viewclient - HTML table showing selected client data
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '107 GET /panel/viewclient - HTML table showing selected client data';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/viewclient?id=' + chain.savedNewId);
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
    console.log('\tExpect: body contains "<title>View Client</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>View Client</title>') >= 0);
    console.log('\tExpect: body contains "<h2>View Client Info</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>View Client Info</h2>') >= 0);

    const parsedClientProps = {};
    parsedClientProps.id =
      chain.responseRawData.split('<td>id</td><td>')[1].split('<')[0];
    parsedClientProps.name =
      chain.responseRawData.split('<td>name</td><td>')[1].split('<')[0];
    parsedClientProps.clientId =
      chain.responseRawData.split('<td>clientId</td><td>')[1].split('<')[0];
    parsedClientProps.clientSecret =
      chain.responseRawData.split('<td>clientSecret</td><td>')[1].split('<')[0];
    parsedClientProps.trustedClient =
      chain.responseRawData.split('<td>trustedClient</td><td>')[1].split('<')[0];
    parsedClientProps.allowedScope =
      chain.responseRawData.split('<td>allowedScope</td><td>')[1].split('<')[0];
    parsedClientProps.allowedRedirectURI =
      chain.responseRawData.split('<td>allowedRedirectURI</td><td>')[1].split('<')[0];
    parsedClientProps.clientDisabled =
      chain.responseRawData.split('<td>clientDisabled</td><td>')[1].split('<')[0];
    //
    // parsedClientProps = {
    //   id: '106f1fa2-087a-4785-9983-97e523c4a0f7',
    //   name: 'name897',
    //   clientId: 'client69649',
    //   clientSecret: 'secret659517331',
    //   trustedClient: 'No',
    //   allowedScope: 'auth.none, auth.info, auth.token, api.read, api.write',
    //   allowedRedirectURI: 'http://localhost:3000/login/callback',
    //   clientDisabled: 'No'
    // }
    // console.log(parsedClientProps);

    console.log('\tExpect: previous client.id extracted from page matches');
    assert.strictEqual(parsedClientProps.id, chain.savedNewId);
    console.log('\tExpect: modified client.name extracted from page matches');
    assert.strictEqual(parsedClientProps.name, chain.savedNewName);
    console.log('\tExpect: previous client.clientId extracted from page matches');
    assert.strictEqual(parsedClientProps.clientId, chain.savedNewClientId);
    console.log('\tExpect: modified client.clientSecret extracted from page matches');
    assert.strictEqual(parsedClientProps.clientSecret, chain.savedNewSecret);
    console.log('\tExpect: modified client.trustedClient extracted from page matches');
    if (chain.savedNewTrustedClient) {
      assert.strictEqual(parsedClientProps.trustedClient, 'Yes');
    } else {
      assert.strictEqual(parsedClientProps.trustedClient, 'No');
    }
    console.log('\tExpect: modified client.allowedScope extracted from page matches');
    assert.strictEqual(parsedClientProps.allowedScope, chain.savedNewAllowedScope);
    console.log('\tExpect: modified client.allowedRedirectURI extracted from page matches');
    assert.strictEqual(parsedClientProps.allowedRedirectURI, chain.savedNewRedirectURI);
    console.log('\tExpect: modified client.clientDisabled extracted from page matches');
    if (chain.savedNewClientDisabled) {
      assert.strictEqual(parsedClientProps.clientDisabled, 'Yes');
    } else {
      assert.strictEqual(parsedClientProps.clientDisabled, 'No');
    }
    return Promise.resolve(chain);
  }) // 107 GET /panel/viewclient

  // -----------------------------------------------
  // 200 POST /panel/editclient - Data validation, edit client, allowed parameters
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '200 POST /panel/editclient - Data validation, edit client, allowed parameters';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/editclient');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      clientId: chain.savedNewClientId,
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
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"clientSecret"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"clientSecret"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"allowedScope"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"allowedScope"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"allowedRedirectURI"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"allowedRedirectURI"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Forbidden property (read only","path":"clientId"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Forbidden property (read only","path":"clientId"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Server generated values not allowed","path":"updatedAt"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Server generated values not allowed","path":"updatedAt"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Server generated values not allowed","path":"createddAt"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Server generated values not allowed","path":"createdAt"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Invalid param","path":"extraneousKey"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid param","path":"extraneousKey"') >= 0);

    return Promise.resolve(chain);
  }) // 200 POST /panel/editclient

  // -----------------------------------------------
  // 201 POST /panel/editclient - Data validation, edit client, valid data check
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '201 POST /panel/editclient - Data validation, edit client, valid data check';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/editclient');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      id: chain.savedNewId,
      name: 'invalid-chars-$#%',
      trustedClient: 'xyz',
      clientDisabled: 'xyz',
      allowedScope: 'invalid-chars-$#%',
      allowedRedirectURI: 'invalid-chars-$$%',
      clientSecret: chain.savedNewSecret,
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
    console.log('\tExpect: Error message contains \'"msg":"Invalid characters in string","path":"allowedScope"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid characters in string","path":"allowedScope"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Invalid characters in string","path":"allowedRedirectURI"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid characters in string","path":"allowedRedirectURI"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Checkbox requires on/off","path":"trustedClient"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Checkbox requires on/off","path":"trustedClient"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Checkbox requires on/off","path":"clientDisabled"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Checkbox requires on/off","path":"clientDisabled"') >= 0);
    return Promise.resolve(chain);
  }) // 201 POST /panel/editclient

  // -----------------------------------------------
  // 300 POST /panel/createclient - Duplicate clientId
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '300 POST /panel/createclient - Duplicate clientId';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createclient');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      name: chain.savedNewName,
      clientId: chain.savedNewClientId,
      clientSecret: chain.savedNewSecret,
      allowedScope: chain.savedNewAllowedScope,
      allowedRedirectURI: chain.savedNewRedirectURI,
      _csrf: chain.parsedCsrfToken
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
    logRequest(chain, { ignoreErrorStatus: 400 });
    // console.log(chain.responseErrorMessage);
    console.log('\tExpect: status === 400');
    assert.strictEqual(chain.responseStatus, 400);

    console.log('\tExpect: Error message contains "client already exists"');
    assert.ok(chain.responseErrorMessage.indexOf('client already exists') >= 0);

    return Promise.resolve(chain);
  }) // 300 POST /panel/createclient

  // -----------------------------------------------
  // 301 POST /panel/createclient - Data validation, create client, allowed parameters
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '301 POST /panel/createclient - Data validation, create client, allowed parameters';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createclient');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      id: chain.savedNewId,
      extraneousKey: 'some-value',
      updatedAt: '2024-09-18T13:37:19.143Z',
      createdAt: '2024-09-18T13:37:19.143Z'
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
    logRequest(chain, { ignoreErrorStatus: 422 });
    // console.log(chain.responseErrorMessage);

    console.log('\tExpect: status === 422');
    assert.strictEqual(chain.responseStatus, 422);

    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"_csrf"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"_csrf"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"name"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"name"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"clientId"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"clientId"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"clientSecret"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"clientSecret"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"allowedScope"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"allowedScope"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Required value","path":"allowedRedirectURI"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Required value","path":"allowedRedirectURI"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Server generated values not allowed","path":"id"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Server generated values not allowed","path":"id"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Server generated values not allowed","path":"updatedAt"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Server generated values not allowed","path":"updatedAt"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Server generated values not allowed","path":"createddAt"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Server generated values not allowed","path":"createdAt"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Invalid param","path":"extraneousKey"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid param","path":"extraneousKey"') >= 0);

    return Promise.resolve(chain);
  }) // 301 POST /panel/createclient

  // -----------------------------------------------
  // 302 POST /panel/createclient - Data validation, create client, valid data check
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '302 POST /panel/createclient - Data validation, create client, valid data check';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/createclient');
    chain.requestAuthorization = 'cookie';
    chain.requestAcceptType = 'text/html';
    chain.requestContentType = 'application/x-www-form-urlencoded';
    chain.requestBody = {
      id: chain.savedNewId,
      name: 'invalid-chars-$#%',
      trustedClient: 'xyz',
      clientDisabled: 'xyz',
      allowedScope: 'invalid-chars-$#%',
      allowedRedirectURI: 'invalid-chars-$$%',
      clientSecret: chain.savedNewSecret,
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
    console.log('\tExpect: Error message contains \'"msg":"Invalid characters in string","path":"allowedScope"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid characters in string","path":"allowedScope"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Invalid characters in string","path":"allowedRedirectURI"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Invalid characters in string","path":"allowedRedirectURI"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Checkbox requires on/off","path":"trustedClient"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Checkbox requires on/off","path":"trustedClient"') >= 0);
    console.log('\tExpect: Error message contains \'"msg":"Checkbox requires on/off","path":"clientDisabled"\'');
    assert.ok(chain.responseErrorMessage.indexOf('"msg":"Checkbox requires on/off","path":"clientDisabled"') >= 0);

    return Promise.resolve(chain);
  }) // 302 POST /panel/createclient

  // ----------------------------------------------------------
  // 900 GET /panel/deleteclient - Panel to confirm delete
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '900 GET /panel/deleteclient - Panel to confirm delete';
    chain.requestMethod = 'GET';
    chain.requestFetchURL =
      encodeURI(testEnv.authURL + '/panel/deleteclient?id=' + chain.savedNewId);
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
    console.log('\tExpect: body contains "<title>Confirm Delete Client</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Confirm Delete Client</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Confirm Delete Client</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Confirm Delete Client</h2>') >= 0);

    const parsedId = chain.responseRawData.split('client record id=')[1]
      .split(' from the database')[0];
    console.log('\tExpect: previous client.id (to be deleted) extracted from page matches');
    assert.strictEqual(parsedId, chain.savedNewId);
    //
    // Parse Data
    //
    if (chain.responseStatus === 200) {
      chain.parsedCsrfToken =
        chain.responseRawData.split('name="_csrf" value="')[1].split('">')[0];
    }
    return Promise.resolve(chain);
  }) // 900 GET /panel/deleteclient

  // -----------------------------------------------
  // 901 POST /panel/deleteclient - Submit request to delete client record
  // -----------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '901 POST /panel/deleteclient - Submit request to delete client record';
    chain.requestMethod = 'POST';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/deleteclient');
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
    console.log('\tExpect: body contains "<title>Delete Client</title>"');
    assert.ok(chain.responseRawData.indexOf('<title>Delete Client</title>') >= 0);
    console.log('\tExpect: body contains "<h2>Delete Client</h2>"');
    assert.ok(chain.responseRawData.indexOf('<h2>Delete Client</h2>') >= 0);
    console.log('\tExpect: body contains "Client successfully deleted."');
    assert.ok(chain.responseRawData.indexOf('Client successfully deleted.') >= 0);
    // Temporary variable no longer needed
    delete chain.parsedCsrfToken;
    delete chain.requestBody;
    return Promise.resolve(chain);
  }) // 901 POST /panel/deleteclient

  // ----------------------------------------------------------
  // 902 GET /panel/viewclient - Expect error due to deleted client record
  // ----------------------------------------------------------
  .then((chain) => {
    chain.testDescription =
      '902 GET /panel/viewclient - Expect error due to deleted client record';
    chain.requestMethod = 'GET';
    chain.requestFetchURL = encodeURI(testEnv.authURL + '/panel/viewclient?id=' + chain.savedNewId);
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
  }) // 902 GET /panel/viewclient

  //
  // In normal testing, no errors should be rejected in the promise chain.
  // In the case of hardware network errors, catch the error.
  .catch((err) => showHardError(err));
