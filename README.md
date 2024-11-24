# collab-auth-dev-tools

Optional debug utilities for collab-auth

## Description

This is an external repository containing debug test scripts used by the "collab-auth" repository.
There are two reasons for using an external repository:

First, the test scripts are not compatible with the GitHub CodeQL venerability
scanner in the collab-auth repository. Although test script CodeQL issues have
been been designated as (Ignore, used in tests), the number of issues causes CodeQL
to fail for exceeding limits for repeating too many issues in the public (free) GitHub CodeQL scanner.

The second reason to locate the debug scripts to an external repository is to allow the
the debug tests to be further evolved and cleaned up without having to make commits
the the main collab-auth repository, when there are no actual application code changes were made.

## Installation

- Prerequisite: The "collab-auth" git repository must be installed.
- Prerequisite: The collab-auth npm dependencies must have been previously installed using `npm install` from the base folder of the collab-auth repository.

- Locate the parent folder containing the "collab-auth" repository, for example: ~/projects/collab-auth
- Change directory to the parent folder, in this case the command would be `cd ~/projects`
- Install the "collab-auth-dev-tools" repository, then list the files as follows:

```bash
git clone git@github.com:cotarr/collab-auth-dev-tools.git

# list files
ls -l
``

- Confirm the directory listing shows both collab-auth and collab-auth-dev-tools in the same folder

```
drwxr-xr-x 13 user1 user1 4096 Nov 23 15:56 collab-auth
drwxr-xr-x  4 user1 user1 4096 Nov 23 15:37 collab-auth-dev-tools
````

- Change directory to the collab-auth repository `cd collab-auth`
- Inspect the .gitignore file in the collab-auth folder and confirm .gitignore contains "debug" as an excluded folder.
- In the base folder of the collab-auth repository create a symlink to the "debug" folder in the collab-auth-dev-tools repository

```bash
ln -s ../collab-auth-dev-tools/debug debug
````

The installation of the debug tests is now complete.
The debug tests must be executed from the base folder of the collab-auth repository.
Complete instructions are in the "debug/README.md" file

## Editing of debug tests

The debug test files should be edited within the collab-auth-dev-tools folder, then committed and uploaded from that folder.
The .gitignore file in the collab-auth repository will prevent the debug tests from being committed to the collab-auth repository.

## Linting of test files

From the base folder of the collab-auth repository, type the following commands to run eslint on the debug test files in the symlink folder.

```bash
npx eslint debug
```
