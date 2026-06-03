#!/usr/bin/env sh
set -eu

api="${API:-35}"
sdk="${ANDROID_HOME:-${HOME}/Library/Android/sdk}"

if [ -n "${ANDROID_NDK_HOME:-}" ]; then
	ndk="${ANDROID_NDK_HOME}"
else
	ndk="$(find "${sdk}/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1)"
fi

if [ -z "${ndk}" ] || [ ! -d "${ndk}" ]; then
	echo "Android NDK not found. Set ANDROID_NDK_HOME or ANDROID_HOME." >&2
	exit 1
fi

prebuilt="$(find "${ndk}/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d | sort | head -n 1)"
cxx="${prebuilt}/bin/aarch64-linux-android${api}-clang++"

if [ ! -x "${cxx}" ]; then
	echo "Compiler not found: ${cxx}" >&2
	exit 1
fi

mkdir -p out/android-arm64
"${cxx}" \
	-std=c++17 \
	-Wall -Wextra -Werror \
	-fno-exceptions -fno-rtti -nostdlib++ \
	-O2 -fPIE -pie \
	-I include \
	tools/embianctl.cpp \
	-o out/android-arm64/embianctl

echo "built out/android-arm64/embianctl"
