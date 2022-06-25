#!/bin/bash -eux

cwd=$(pwd)

lint_ver=1.46.2
curl --location --no-progress-meter https://github.com/golangci/golangci-lint/releases/download/v$lint_ver/golangci-lint-$lint_ver-linux-amd64.tar.gz | tar zxvf -
PATH=$PATH:$cwd/golangci-lint-$lint_ver-linux-amd64

pushd $cwd/dp-authorisation/v2
  make lint
popd

pushd $cwd/dp-authorisation
  make lint
popd
