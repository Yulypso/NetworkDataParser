#!/usr/local/bin/zsh

find . -name "*.java" > source.txt
javac --enable-preview --release 17 @source.txt -d out
rm source.txt
java --enable-preview -cp out RiShark "$@"