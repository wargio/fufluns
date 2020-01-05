#!/bin/sh

SCRIPTPATH="$(cd "$(dirname "$0")"; pwd -P)"

python "$SCRIPTPATH/main.py" $@