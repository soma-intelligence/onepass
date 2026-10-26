# OnePass Apple build. Run with `make -C apple <target>`.
SHELL := /bin/bash
.DEFAULT_GOAL := core

APPLE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
TEST_XCFRAMEWORK := ../build/test/OnePassFFI.xcframework

# The shell script keeps its own content stamp (apple/build/.core-stamp and
# apple/build/test/.core-stamp) and is a no-op when the Rust sources are
# unchanged; make always delegates to it.
.PHONY: core core-test test project build-ios build-mac uitest screenshots clean

## Shipped XCFramework (release, ios + ios-simulator + macOS) and bindings.
core:
	@"$(APPLE_DIR)/scripts/build-core.sh" shipped

## Test XCFramework (macOS arm64, debug, dev-fast-kdf). Never shipped.
core-test:
	@"$(APPLE_DIR)/scripts/build-core.sh" test

## Swift tests against the fast-KDF test XCFramework.
test: core-test
	ONEPASS_FFI_XCFRAMEWORK="$(TEST_XCFRAMEWORK)" swift test --package-path "$(APPLE_DIR)/VaultKit"
	@if [ -d "$(APPLE_DIR)/DesignKit" ]; then \
		ONEPASS_FFI_XCFRAMEWORK="$(TEST_XCFRAMEWORK)" swift test --package-path "$(APPLE_DIR)/DesignKit"; \
	fi

## Xcode project from project.yml.
project: core
	cd "$(APPLE_DIR)" && xcodegen generate

IOS_DESTINATION := platform=iOS Simulator,name=OnePass M2 iPhone

## Simulator build, unsigned (the dedicated simulator must exist, see README).
build-ios: project
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePass \
		-destination '$(IOS_DESTINATION)' -derivedDataPath DerivedData \
		CODE_SIGNING_ALLOWED=NO build

## Native Mac build (arm64), signed ad hoc so it runs locally.
build-mac: project
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePass \
		-destination 'platform=macOS,arch=arm64' -derivedDataPath DerivedData \
		CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= build

uitest: project
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePass \
		-destination '$(IOS_DESTINATION)' -derivedDataPath DerivedData \
		CODE_SIGNING_ALLOWED=NO test

screenshots: project
	"$(APPLE_DIR)/scripts/screenshots.sh"

clean:
	rm -rf "$(APPLE_DIR)/build" "$(APPLE_DIR)/DerivedData" "$(APPLE_DIR)/VaultKit/.build" \
		"$(APPLE_DIR)/VaultKit/Sources/OnePassCore/onepass_ffi.swift"
