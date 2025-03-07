#! /bin/sh

if ! grep 'project(sysjail)' CMakeLists.txt >/dev/null ; then
	printf 'setup.sh should be called in the project root directory'
	exit 2
fi

LINKER_FLAGS="-fuse-ld=lld"

cmake -S . -B build \
	-DCMAKE_BUILD_TYPE=Debug \
	-DCMAKE_SHARED_LINKER_FLAGS=${LINKER_FLAGS} \
	-DCMAKE_EXE_LINKER_FLAGS=${LINKER_FLAGS}
