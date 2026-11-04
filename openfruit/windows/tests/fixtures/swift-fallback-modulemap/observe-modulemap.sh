#!/bin/sh

found=0
windows_paths=0
wsl_paths=0
for argument in "$@"; do
    case "$argument" in
        -fmodule-map-file=*)
            modulemap=${argument#-fmodule-map-file=}
            if [ ! -f "$modulemap" ]; then
                continue
            fi
            if ! grep -q 'module OPENFRUITFallbackProbe' "$modulemap"; then
                continue
            fi
            found=$((found + 1))
            if grep -Eq '[[:alpha:]]:\\\\' "$modulemap"; then
                windows_paths=$((windows_paths + 1))
            fi
            if grep -Fq '/mnt/' "$modulemap"; then
                wsl_paths=$((wsl_paths + 1))
            fi
            ;;
    esac
done

echo "MODULEMAP_ARGUMENT_COUNT=$found"
echo "MODULEMAP_CONTENT_WINDOWS_PATH_COUNT=$windows_paths"
echo "MODULEMAP_CONTENT_WSL_PATH_COUNT=$wsl_paths"

if [ "$found" -ne 2 ]; then
    echo "MODULEMAP_ARGUMENT=missing"
    exit 25
fi
if [ "$windows_paths" -ne 0 ]; then
    exit 23
fi
if [ "$wsl_paths" -ne 2 ]; then
    echo "MODULEMAP_CONTENT_PATH=unrecognized"
    exit 24
fi
exit 0
