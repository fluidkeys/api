#!/bin/sh

# Go installation directory
export GOROOT=/opt/go
export PATH=$PATH:$GOROOT/bin

# Go workspace, where my source lives
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
