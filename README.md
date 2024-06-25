# sysjail
Block chosen Linux syscalls using seccomp-bpf.

> [!CAUTION]
> Not production safe.

## Building
```sh
# CMake setup
./setup.sh

./build.sh

# Artifacts in build/
build/sysjail
```

## Usage
```sh
build/sysjail --help
```
