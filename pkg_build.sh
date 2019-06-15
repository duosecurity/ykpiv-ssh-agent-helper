#!/bin/bash

RUN_DIRECTORY="$(dirname "$(readlink $0)")"
PROJECT_DOMAIN="com.duosecurity.ykpiv-ssh-agent-helper"
PROJECT_NAME="ykpiv-ssh-agent-helper"
PACKAGE_NAME="ykpiv-ssh-agent-helper"
TARGET_NAME="$PROJECT_NAME"
INSTALL_PREFIX="/usr/local/bin"
LAUNCHAGENT_PREFIX="/Library/LaunchAgents"
COMMIT="$(cd "$RUN_DIRECTORY" || exit; git log | awk '/commit/{print substr($2,1,10);exit}')"
TMP_PATH="/private/tmp/$PROJECT_NAME-$COMMIT-$$$RANDOM"
PACKAGE_IDENT="$PROJECT_DOMAIN.$PACKAGE_NAME.$COMMIT"
OUTPUT_DIR="$RUN_DIRECTORY/pkg_build"
PRODUCT_DIR="$RUN_DIRECTORY/build/"

which xcodebuild > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
    echo "xcodebuild is not installed. Exiting now."
    exit 1
fi

PIVTOOL_ZIPPATH="$(find -s "$RUN_DIRECTORY" -depth 1 -name "yubico-piv-tool-*-mac.zip"  | head -n 1)"
if [[ -z "$PIVTOOL_ZIPPATH" ]]; then
    echo "cannot find yubico-piv-tool!"
    exit 1
fi
echo $PIVTOOL_ZIPPATH
PIVTOOL_DIRNAME=$(basename $PIVTOOL_ZIPPATH .zip)

if [[ ! -d "$PRODUCT_DIR" ]]; then
    mkdir -p "$PRODUCT_DIR"
fi

XCODE_PROJECT="$RUN_DIRECTORY/$PROJECT_NAME.xcodeproj"

if [[ -e "$XCODE_PROJECT" ]]; then
    mkdir -p "${TMP_PATH}/$INSTALL_PREFIX"

    # build ykpiv-ssh-agent-helper
    xcodebuild -project "$RUN_DIRECTORY/$PROJECT_NAME.xcodeproj" \
        CONFIGURATION_BUILD_DIR="$PRODUCT_DIR" clean build
    [ $? -eq 0 ] || { printf "\nxcodebuild failed! Exiting now."; exit 1; }
    mv "$RUN_DIRECTORY/build/$TARGET_NAME" "${TMP_PATH}/$INSTALL_PREFIX/"

    mkdir "${TMP_PATH}/tmp/"
    cp OpenSC\ 0.18.0.pkg "${TMP_PATH}/tmp/"

    # unzip yubico-piv-tool-(version)-mac.zip
    mkdir -p "${TMP_PATH}/opt/$PIVTOOL_DIRNAME"
    unzip "$PIVTOOL_ZIPPATH" -d "${TMP_PATH}/opt/$PIVTOOL_DIRNAME"
    pushd "${TMP_PATH}/opt/"
    ln -s "$PIVTOOL_DIRNAME" "yubico-piv-tool"
    popd

    # put the correct path into the LaunchAgent plist and copy it into place
    mkdir -p "${TMP_PATH}/$LAUNCHAGENT_PREFIX"
    sed "s/__PIVTOOL_DIRNAME__/$PIVTOOL_DIRNAME/g" \
        "$RUN_DIRECTORY/com.duosecurity.ykpiv-ssh-agent-helper.plist" > \
        "${TMP_PATH}/$LAUNCHAGENT_PREFIX/com.duosecurity.ykpiv-ssh-agent-helper.plist"

    pkgbuild --identifier "$PACKAGE_IDENT" \
        --root "$TMP_PATH/" \
        --scripts "$OUTPUT_DIR/${PACKAGE_NAME}_scripts" \
        "$OUTPUT_DIR/${PACKAGE_NAME}_$COMMIT.pkg"
fi

exit $?
