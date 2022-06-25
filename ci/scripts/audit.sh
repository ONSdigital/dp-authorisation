#!/bin/bash -eux

cwd=$(pwd)

pushd $cwd/dp-authorisation/v2
  make audit
popd

pushd $cwd/dp-authorisation
  make audit
popd
