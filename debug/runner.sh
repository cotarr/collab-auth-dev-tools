#!/bin/bash

# Used with 'ps' command to check if server is running
PROCMATCH="bin/www"

# This script requires a directory to hold the PID file.
# The directory may be specified in the PID_DIR environment variable
if [ -z "$PID_DIR" ] ; then
  PID_DIR=~/tmp
fi

# PID filename, used to kill the server process
if [ -z "$PID_FILENAME" ] ; then
  PID_FILENAME=$PID_DIR/collab-auth.PID
fi

# Make filename available to nodejs web server as enviornment variable
export SERVER_PID_FILENAME="$PID_FILENAME"

# Used to log script failure when exit code not 0
LOG_DATE=$(date +%s)
LOG_FILENAME="$PID_DIR/runner_log_$LOG_DATE.txt"
echo "Script debug/runner.sh error log" > $LOG_FILENAME
echo "Date: $(date --rfc-3339=seconds)" >> $LOG_FILENAME
echo >> $LOG_FILENAME

# Unless debugging, ignore output
NODE_OUTPUT=/dev/null
#NODE_OUTPUT=/dev/stdout

#
# Function to set environment variable default values
#
function set_default_env
  {
    export NODE_ENV=development
    export SESSION_EXPIRE_SEC=1000
    export SESSION_SET_ROLLING_COOKIE=false
    export OAUTH2_TOKEN_EXPIRES_IN_SECONDS=1000
    export OAUTH2_CLIENT_TOKEN_EXPIRES_IN_SECONDS=1000
    export OAUTH2_EDITOR_SHOW_CLIENT_SECRET=false
    export DATABASE_DISABLE_WEB_ADMIN_PANEL=false
    export LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000
    export LIMITS_TOKEN_RATE_LIMIT_COUNT=1000
    export LIMITS_WEB_RATE_LIMIT_COUNT=1000
  }

function show_default_env
  {
    echo "Config: NODE_ENV=development"
    echo "Config: SESSION_EXPIRE_SEC=1000"
    echo "Config: SESSION_SET_ROLLING_COOKIE=false"
    echo "Config: OAUTH2_TOKEN_EXPIRES_IN_SECONDS=1000"
    echo "Config: OAUTH2_CLIENT_TOKEN_EXPIRES_IN_SECONDS=1000"
    echo "Config: OAUTH2_EDITOR_SHOW_CLIENT_SECRET=false"
    echo "Config: DATABASE_DISABLE_WEB_ADMIN_PANEL=false"
    echo "Config: LIMITS_PASSWORD_RATE_LIMIT_COUNT=1000"
    echo "Config: LIMITS_TOKEN_RATE_LIMIT_COUNT=1000"
    echo "Config: LIMITS_WEB_RATE_LIMIT_COUNT=1000"
  }

#
# Function to stop collab-auth server to change to alternate configuration
#
function stop_server
  {
    if ps ax | grep -v grep | grep "$PROCMATCH" &> /dev/null ; then
      echo "Server: Attempting to shutdown collab-auth server, PID $SERVER_PID"
      if kill $SERVER_PID
      then
        echo "Server: PID $SERVER_PID successfully terminated"
      else
        echo "Server: Unable to terminate PID $SERVER_PID"
        exit 1
      fi
    fi
  }

#
# Function to start collab-auth server to change to alternate configuration
#
function restart_server
  {
    echo "Server: Restarting collab-auth server, launching to background"
    node bin/www &> $NODE_OUTPUT &
    sleep 2
    if ! ps ax | grep -v grep | grep "$PROCMATCH" &> /dev/null ; then
      echo "Server: Unable to start collab-auth server"
      exit 1
    fi
    SERVER_PID=$(cat $PID_FILENAME)
    echo "Server: Collab-auth server detected running, PID=$SERVER_PID"
  }

#
# Check previous function to see if return code shows error
#
function check_for_errors
  {
    RETURN_CODE=$?
    if [ $RETURN_CODE == 0 ] 
    then
      echo "Test: $1" >> $LOG_FILENAME
    else
      echo "Test: $1 (Errors detected)" >> $LOG_FILENAME
      # Show on console
      echo
      echo "=============================="
      echo "Test: $1"
      echo "returned non-zero error code"
      echo "=============================="
    fi
  }

#
#
if [ ! -e debug ] || [ ! -f package.json ]; then
  echo "Script must be run from repository base folder"
  exit 1
fi

if [ ! -e $PID_DIR ] ; then
  echo "This script requires a PID directory ($PID_DIR)"
  echo "The directory may be specified in the PID_DIR env variable"
  echo "   PID_DIR=~/tmp"
  echo
  exit 1
fi

echo
echo "======================================================="
echo "WARNING: The runner.sh script will modify the database"
echo "======================================================="
echo
echo "Table: session       Action: All records deleted"
echo "Table: accesstokens  Action: All records deleted"
echo "Table: refreshtokens Action: All records deleted"
echo "Table: authusers     Action: New records created, then deleted"
echo "Table: authusers     Action: New records created, then deleted"
echo
echo "     Ctrl-C now to abort (You have 15 seconds)"
echo "======================================================="
echo
sleep 5

# ---------------------
# Display Server Config
# ---------------------
echo
echo "Executing: node debug/display-config.js"
sleep 1
node ./debug/display-config.js
sleep 5
echo

#
# Case of previous script aborted, leaving server running in background, stop the server
#
if [ -e $PID_FILENAME ] ; then
  KILL_PID=$(cat $PID_FILENAME)
  echo "Server: PID file found, PID=$KILL_PID, checking if server is running."
  if [ -n "$KILL_PID" ] ; then
    if ps ax | grep -v grep | grep "$PROCMATCH" &> /dev/null ; then
      echo "Server: Found server running, attempting to kill PID $KILL_PID"
      if kill $KILL_PID
      then
        echo "Server: PID $KILL_PID successfully terminated"
      else
        echo "Server: Unable to terminate PID $KILL_PID"
        exit 1
      fi
    fi
  else
    echo "Server: confirmed, server not running at start of script, as expected."
  fi
fi
sleep 2
if [ -f $PID_FILENAME ] ; then
  rm -v $PID_FILENAME
fi

#
# Prerequisite - server must not be running
#
if ps ax | grep -v grep | grep "$PROCMATCH" &> /dev/null ; then
  echo "Server: Collab-auth server must be stopped before running script"
  exit 1
fi

#
# Start collab auth server running
#
show_default_env
echo
set_default_env
echo "Server: starting collab-auth server, launching to background"
node bin/www &> $NODE_OUTPUT &
sleep 2

#
# Check process name 'www' exists as running process
#
if ! ps ax | grep -v grep | grep "$PROCMATCH" &> /dev/null ; then
  echo "Server: unable to start collab-auth server"
  exit 1
fi

#
# Check that PID file created, needed to restart server during tests
#
if [ ! -e $PID_FILENAME ] ; then
  echo "Server: collab-auth PID file not found at $PID_FILENAME"
  exit 1
fi
#
# The PID number is used by functions to restart the server
#
SERVER_PID=$(cat $PID_FILENAME)
echo "Server: collab-auth server detected running, PID=$SERVER_PID"

# ---------------------
# Test: clear-database.js
# ---------------------
echo
echo "Executing: node clear-database.js"
sleep 5
node ./debug/clear-database.js
check_for_errors 1-clear-database
sleep 5

# ---------------------
# Test: client-grant-demo.js
# ---------------------
echo
echo "Executing: node debug/client-grant-demo.js"
sleep 5
node ./debug/client-grant-demo.js
check_for_errors 2-client-grant-demo
sleep 5

# ---------------------
# Test: code-grant-demo.js
# ---------------------
echo
echo "Executing: node debug/code-grant-demo.js"
sleep 5
node ./debug/code-grant-demo.js
check_for_errors 3-code-grant-demo
sleep 5

# ---------------------
# Test: login-form-submission.js
# ---------------------
echo
echo "Executing: node debug/login-form-submission.js"
sleep 5
node ./debug/login-form-submission.js
check_for_errors 4-login-form-submission
sleep 5

# ---------------------
# Test: protected-routes.js
# ---------------------
echo
echo "Executing: node debug/protected-routes.js"
sleep 5
node ./debug/protected-routes.js
check_for_errors 5-protected-routes
sleep 5

# ---------------------
# Test: public-routes.js
# ---------------------
echo
echo "Executing: node debug/public-routes.js"
sleep 5
node ./debug/public-routes.js
check_for_errors 6-public-routes
sleep 5

# ---------------------
# Test: admin-user-edit.js
# ---------------------
echo
echo "Executing: node debug/admin-user-edit.js"
sleep 5
node ./debug/admin-user-edit.js
check_for_errors 7-admin-user-edit
sleep 5

# ---------------------
# Test: admin-access-check.js
# ---------------------
echo
echo "Executing: node debug/admin-access-check.js"
sleep 5
node ./debug/admin-access-check.js
check_for_errors 8-admin-access-check
sleep 5

# ---------------------
# Test: admin-scope-check.js
# ---------------------
echo
echo "Executing: node debug/admin-scope-check.js"
sleep 5
node ./debug/admin-scope-check.js
check_for_errors 9-admin-scope-check
sleep 5

# -------------------------------------------------
# Restart node server with alternate configuration
# -------------------------------------------------
echo
echo "Config: OAUTH2_EDITOR_SHOW_CLIENT_SECRET=true"
echo
stop_server
set_default_env
export OAUTH2_EDITOR_SHOW_CLIENT_SECRET=true
restart_server
sleep 5

# ---------------------
# Test: admin-client-edit.js
# ---------------------
echo
echo "Executing: node debug/admin-client-edit.js"
sleep 5
node ./debug/admin-client-edit.js
check_for_errors 10-admin-client-edit
sleep 5

# -------------------------------------------------
# Restart node server with alternate configuration
# -------------------------------------------------
echo
echo "Config:DATABASE_DISABLE_WEB_ADMIN_PANEL=true"
echo
stop_server
set_default_env
export DATABASE_DISABLE_WEB_ADMIN_PANEL=true
restart_server
sleep 5

# ---------------------
# Test: admin-disabled.js
# ---------------------
echo
echo "Executing: node debug/admin-disabled.js"
sleep 5
node ./debug/admin-disabled.js
check_for_errors 11-admin-disabled
sleep 5

# -------------------------------------------------
# Restart node server with alternate configuration
# -------------------------------------------------
echo
echo "Config: OAUTH2_CLIENT_TOKEN_EXPIRES_IN_SECONDS=10"
echo
stop_server
set_default_env
export OAUTH2_CLIENT_TOKEN_EXPIRES_IN_SECONDS=10
restart_server
sleep 5

# ---------------------
# Test: access-token-client.js
# ---------------------
echo
echo "Executing: node debug/access-token-client.js"
sleep 5
node ./debug/access-token-client.js
check_for_errors 12-access-token-client
sleep 5

# -------------------------------------------------
# Restart node server with alternate configuration
# -------------------------------------------------
echo
echo "Config: OAUTH2_AUTH_CODE_EXPIRES_IN_SECONDS=8"
echo "Config: OAUTH2_TOKEN_EXPIRES_IN_SECONDS=10"
echo "Config: OAUTH2_REFRESH_TOKEN_EXPIRES_IN_SECONDS=15"


echo
stop_server
set_default_env
export OAUTH2_AUTH_CODE_EXPIRES_IN_SECONDS=8
export OAUTH2_TOKEN_EXPIRES_IN_SECONDS=10
export OAUTH2_REFRESH_TOKEN_EXPIRES_IN_SECONDS=15
restart_server
sleep 5

# ---------------------
# Test: access-token-user.js
# ---------------------
echo
echo "Executing: node debug/access-token-user.js"
sleep 5
node ./debug/access-token-user.js
check_for_errors 13-access-token-user
sleep 5

# -------------------------------------------------
# Restart node server with alternate configuration
# -------------------------------------------------
echo
echo "Config: SESSION_EXPIRE_SEC=8" 
echo "Config: SESSION_SET_ROLLING_COOKIE=false"
echo
stop_server
set_default_env
export SESSION_EXPIRE_SEC=8
export SESSION_SET_ROLLING_COOKIE=false
restart_server
sleep 5

# ---------------------
# Test: cookie-tests.js
# ---------------------
echo
echo "Executing: node debug/cookie-tests.js"
sleep 5
node ./debug/cookie-tests.js
check_for_errors 14-cookie-tests
sleep 5

# -------------------------------------------------
# Restart node server with alternate configuration
# -------------------------------------------------
echo
echo "Config: SESSION_EXPIRE_SEC=8" 
echo "Config: SESSION_SET_ROLLING_COOKIE=true"
echo
stop_server
set_default_env
export SESSION_EXPIRE_SEC=8
export SESSION_SET_ROLLING_COOKIE=true
restart_server
sleep 5

# ---------------------
# Test: cookie-tests.js
# ---------------------
echo
echo "Executing: node debug/cookie-tests.js"
sleep 5
node ./debug/cookie-tests.js
check_for_errors 15-cookie-tests
sleep 5


# -------------------------------------------------
# Restart node server with alternate configuration
# -------------------------------------------------
echo
echo "Config: LIMITS_PASSWORD_RATE_LIMIT_COUNT=4"
echo "Config: LIMITS_TOKEN_RATE_LIMIT_COUNT=6"
echo "Config: LIMITS_WEB_RATE_LIMIT_COUNT=16"
echo
stop_server
set_default_env
export LIMITS_PASSWORD_RATE_LIMIT_COUNT=4
export LIMITS_TOKEN_RATE_LIMIT_COUNT=6
export LIMITS_WEB_RATE_LIMIT_COUNT=16
restart_server
sleep 5

# ---------------------
# Test: rate-limit.js
# ---------------------
echo
echo "Executing: node debug/rate-limit.js"
sleep 5
node ./debug/rate-limit.js
check_for_errors 16-rate-limit
sleep 5


# -------------------------------------------------
# Restart node server with alternate configuration
# -------------------------------------------------
echo
echo "Config: TESTENV_LT_COUNT=10" 
echo "Config: TESTENV_LT_PERIODMS=0" 
echo "Config: TESTENV_RT_COUNT=1" 
echo "Config: TESTENV_RT_PERIODMS=1000"
echo
stop_server
set_default_env
export TESTENV_LT_COUNT=10
export TESTENV_LT_PERIODMS=0
restart_server
sleep 5

# ---------------------
# Test: load-test-introspect.js
# ---------------------
echo
echo "Executing: node load-test-introspect.js"
sleep 5
node ./debug/load-test-introspect.js
check_for_errors 17-load-test-introspect
sleep 5

# -------------------------------------------------
# Restart node server with alternate configuration
# -------------------------------------------------
echo
echo "Config: TESTENV_RT_COUNT=1" 
echo "Config: TESTENV_RT_PERIODMS=1000"
echo
stop_server
set_default_env

export TESTENV_RT_COUNT=1
export TESTENV_RT_PERIODMS=1000
restart_server
sleep 5

# ---------------------
# Test: redirect-timing-debug.js
# ---------------------
echo
echo "Executing: node redirect-timing-debug.js"
sleep 5
node ./debug/redirect-timing-debug.js
check_for_errors 18-redirect-timing-debug
sleep 5

# ---------------------
# Test: clear-database.js
# ---------------------
echo
echo "Executing: node clear-database.js"
sleep 5
node ./debug/clear-database.js
check_for_errors 19-clear-database
sleep 5

# --------
#   DONE
# --------
echo
echo "All tests completed, stopping server"
stop_server
echo
echo >> $LOG_FILENAME
echo "runner.sh - End of log" >> $LOG_FILENAME
echo
cat $LOG_FILENAME
echo
echo "Script runner.sh completed"
echo
exit 0
