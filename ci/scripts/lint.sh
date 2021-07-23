#!/bin/bash -eux

cwd=$(pwd)

pushd $cwd/dp-authorisation
  make lint
popd
