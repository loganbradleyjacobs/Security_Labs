#!/bin/bash
# Build Sphinx docs and push to gh-pages branch for deployment.
# Allows unsaved changes to be stashed and restored.

set -e #exit if any command fails
set -u #exit if any undefined var is used

# get current branch and stash changes before switching branches
current_branch=$(git rev-parse --abbrev-ref HEAD)
git stash -u
git checkout master

# uses html builder to build what's in docs/source to docs/build/html
sphinx-build -b html docs/source docs/build/html

# pushes buld html to gh-pages branch (branch defaults to gh-pages)
ghp-import -n -p -f docs/build/html -b gh-pages

# restore state
git checkout "$current_branch"
git stash pop || true

printf "\n --- Documentation deployed to gh-pages branch. ---\n"
