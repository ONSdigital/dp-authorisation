#!/bin/bash -eux

cwd=$(pwd)

pushd $cwd/dp-authorisation/v2
  make build
popd

pushd $cwd/dp-authorisation
  make build
popd
