#!/bin/bash -eux

cwd=$(pwd)

pushd $cwd/dp-authorisation
  make lint
popd

pushd $cwd/dp-authorisation/v2
  make lint
popd
