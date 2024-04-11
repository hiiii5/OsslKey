#!/bin/bash

# Build the project
mkdir build && cd $_
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build . --target install
rm -r ./* && cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --target install
