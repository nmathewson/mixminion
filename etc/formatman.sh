#!/bin/bash

if [ "X$TARGET" = "X" ]; then
    TARGET=/tmp/minion-pages
fi

mkdir $TARGET || true;

for PAGE in mixminion.1 mixminionrc.5 mixminiond.conf.5 mixminiond.8; do
    echo $PAGE
    man2html $PAGE > $TARGET/$PAGE.html
    man ./$PAGE | perl -pe 's/.\x08//g;' > $TARGET/$PAGE.txt
    man -t ./$PAGE > $TARGET/$PAGE.ps
    ps2pdf $TARGET/$PAGE.ps $TARGET/$PAGE.pdf
    rm -f $TARGET/$PAGE.ps.gz
    gzip -9 $TARGET/$PAGE.ps
done