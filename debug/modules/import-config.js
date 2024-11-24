// import-config.js
//
// The testing utility programs in the /debug/ folder will
// extract test values directly from the authorization server configuration.
//
// The local clients-db.json and users-db.json will be
// parsed to obtain values for comparisons during testing.
//
'use strict';

const fs = require('fs');

// Note: loading config will import the .env file into
// the process.env object for use in configuration
const config = require('../../../collab-auth/server/config/index.js');
// console.log('config', JSON.stringify(config, null, 2));

let clients = [];
try {
  clients = JSON.parse(fs.readFileSync('./clients-db.json', 'utf8'));
} catch (e) {
  console.log(e.message);
  process.exit(1);
}
// console.log('clients', JSON.stringify(clients, null, 2));

if (clients.length < 1) {
  console.log('Error, no clients defined in clients-db.json');
  process.exit(1);
}

let users = [];
try {
  users = JSON.parse(fs.readFileSync('./users-db.json', 'utf8'));
} catch (e) {
  console.log(e.message);
  process.exit(1);
}
// console.log('users', JSON.stringify(users, null, 2));

if (users.length < 1) {
  console.log('Error, no users defined in user-db.json');
  process.exit(1);
}

// The following environment variables may be used to
// override the configuration settings for the purpose
// of performing ad-hoc testing without having to
// modify config files for each iteration
//
const testEnv = {};
testEnv.clientIndex = 0;
if ('TESTENV_CLIENTINDEX' in process.env) {
  testEnv.clientIndex = parseInt(process.env.TESTENV_CLIENTINDEX);
}
testEnv.userIndex = 0;
if ('TESTENV_USERINDEX' in process.env) {
  testEnv.userIndex = parseInt(process.env.TESTENV_USERINDEX);
}

testEnv.redirectURIIndex = 0;
if ('TESTENV_REDIRECTURIINDEX' in process.env) {
  testEnv.redirectURIIndex = parseInt(process.env.TESTENV_REDIRECTURIINDEX);
}

testEnv.authURL = config.site.authURL;
if (process.env.TESTENV_AUTHURL) {
  testEnv.authURL = process.env.TESTENV_AUTHURL;
}

testEnv.clientId = clients[testEnv.clientIndex].clientId;
if (process.env.TESTENV_CLIENTID) {
  testEnv.clientId = process.env.TESTENV_CLIENTID;
}

testEnv.clientSecret = clients[testEnv.clientIndex].clientSecret;
if (process.env.TESTENV_CLIENTSECRET) {
  testEnv.clientSecret = process.env.TESTENV_CLIENTSECRET;
}

testEnv.redirectURI = clients[testEnv.clientIndex].allowedRedirectURI[testEnv.redirectURIIndex];
if (process.env.TESTENV_REDIRECTURI) {
  testEnv.redirectURI = process.env.TESTENV_REDIRECTURI;
}

testEnv.trustedClient = clients[testEnv.clientIndex].trustedClient;
if (Object.hasOwn(process.env, 'TESTENV_TRUSTEDCLIENT')) {
  if (process.env.TESTENV_TRUSTEDCLIENT === 'true') {
    testEnv.trustedClient = true;
  } else if (process.env.TESTENV_TRUSTEDCLIENT === 'false') {
    testEnv.trustedClient = false;
  } else {
    console.log('Configuration Error');
    console.log('Environment variable TESTENV_TRUSTEDCLIENT must be string "true" or "false"');
    process.exit(1);
  }
}

testEnv.username = users[testEnv.userIndex].username;
if (process.env.TESTENV_USERNAME) {
  testEnv.username = process.env.TESTENV_USERNAME;
}

testEnv.password = users[testEnv.userIndex].password;
if (process.env.TESTENV_PASSWORD) {
  testEnv.password = process.env.TESTENV_PASSWORD;
}

// For script load-test-introspect.js
testEnv.loadTest = {};
testEnv.loadTest.countLimit = parseInt(process.env.TESTENV_LT_COUNT || '10');
testEnv.loadTest.periodMs = parseInt(process.env.TESTENV_LT_PERIODMS || '0');

// For script redirect-timing.js
testEnv.redirectTiming = {};
testEnv.redirectTiming.countLimit = parseInt(process.env.TESTENV_RT_COUNT || '1');
testEnv.redirectTiming.periodMs = parseInt(process.env.TESTENV_RT_PERIODMS || '1000');

// console.log(JSON.stringify(testEnv, null, 2));

module.exports = { config, clients, users, testEnv };
