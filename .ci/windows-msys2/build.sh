#!/usr/bin/env bash

# Build Veyon and its NSIS installer natively inside an MSYS2 MINGW64 shell.
#
# Required packages (prefix mingw-w64-x86_64-): gcc cmake ninja qt6-base qt6-tools
# qt6-5compat qt6-websockets qt6-httpserver qt6-translations qca-qt6 openssl
# libjpeg-turbo libpng zlib lzo2 libvncserver openldap cyrus-sasl nsis ntldd
# plus the MSYS packages git and dos2unix.
# The Interception library (interception.h, libinterception.dll.a, interception.dll)
# has to be installed into /mingw64 manually.
#
# usage: .ci/windows-msys2/build.sh [build directory]

set -e

SRCDIR=$(cd "$(dirname "$0")/../.." && pwd)
BUILDDIR=${1:-$SRCDIR/../build-win64}
PREFIX=/mingw64
QT_PLUGINS=$PREFIX/share/qt6/plugins

cd "$SRCDIR"
.ci/common/strip-ultravnc-sources.sh
cd "$SRCDIR"

cmake -G Ninja -S "$SRCDIR" -B "$BUILDDIR" -DCMAKE_BUILD_TYPE=Release -DWITH_WERROR=OFF
cmake --build "$BUILDDIR"

cd "$BUILDDIR"

rm -rf veyon-win64-* veyon-*-setup.exe
DIST=$(sed -n 's/^!define VERSION "\(.*\)"/veyon-win64-\1/p' nsis/veyon.nsi)
mkdir -p $DIST/{interception,plugins,translations,crypto,imageformats,platforms,styles,tls}

cp "$SRCDIR"/3rdparty/interception/* $DIST/interception
cp "$SRCDIR"/3rdparty/ddengine/ddengine64.dll $DIST
cp core/veyon-core.dll $DIST
find . -mindepth 2 -name 'veyon-*.exe' -not -path "./$DIST/*" -exec cp '{}' $DIST/ ';'
find plugins/ -name '*.dll' -exec cp '{}' $DIST/plugins/ ';'
mv $DIST/plugins/lib*.dll $DIST
mv $DIST/plugins/vnchooks.dll $DIST

cp translations/*.qm $DIST/translations/
cp $PREFIX/share/qt6/translations/qtbase_*.qm $DIST/translations/

cp $QT_PLUGINS/crypto/libqca-ossl.dll $DIST/crypto
cp $QT_PLUGINS/imageformats/qjpeg.dll $DIST/imageformats
cp $QT_PLUGINS/platforms/qwindows.dll $DIST/platforms
cp $QT_PLUGINS/styles/*.dll $DIST/styles
cp $QT_PLUGINS/tls/qopensslbackend.dll $DIST/tls
cp $PREFIX/bin/interception.dll $DIST

# collect all runtime dependencies provided by MSYS2
find $DIST -name '*.exe' -o -name '*.dll' | xargs ntldd -R 2>/dev/null |
	grep -i 'mingw64' | sed -e 's/.*=> \(.*\) (0x.*/\1/' -e 's,\\,/,g' | sort -u |
	while read -r dll ; do
		cp -n "$(cygpath -u "$dll")" $DIST/
	done

strip $DIST/*.dll $DIST/*.exe $DIST/plugins/*.dll $DIST/platforms/*.dll $DIST/styles/*.dll $DIST/crypto/*.dll

cp "$SRCDIR"/COPYING $DIST
cp "$SRCDIR"/COPYING $DIST/LICENSE.TXT
cp "$SRCDIR"/README.md $DIST/README.TXT
unix2dos -q $DIST/*.TXT
cp -r "$SRCDIR"/nsis $DIST
cp nsis/veyon.nsi $DIST

# makensis for Windows does not accept forward slashes in file paths
sed -i -e '/^File "\|"nsis\//s,/,\\,g' $DIST/veyon.nsi
(cd $DIST && makensis veyon.nsi)
mv $DIST/veyon-*setup.exe .
ls -l "$BUILDDIR"/veyon-*setup.exe
