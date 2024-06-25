#! /bin/sh

if ! grep 'project(sysjail)' CMakeLists.txt >/dev/null ; then
	printf 'build.sh should be called in the project root directory'
	exit 2
fi

cmake --build build/ --config Debug
