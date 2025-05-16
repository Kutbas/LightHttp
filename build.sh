#!/bin/bash

make clean
make
make output
cd output
./httpserver 8080