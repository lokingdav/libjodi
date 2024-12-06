#!/bin/bash

SSS_dir="./src/libs/sss"

if [ -d "$DIR" ] && [ "$(ls -A "$DIR")" ]; then
    echo "Library $DIR exists... Skipping"
else
    git clone --recursive https://github.com/dsprenkels/sss.git $SSS_dir
fi

exit 0
