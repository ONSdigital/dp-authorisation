#!/bin/bash -eux

cwd=$(pwd)

pushd $cwd/dp-authorisation
  make audit
popd