#!/bin/bash -eux

cwd=$(pwd)

pushd $cwd/dp-authorisation
  make test
popd

pushd $cwd/dp-authorisation/v2
  make test
popd
