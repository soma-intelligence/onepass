# OnePass Apple build. Run with `make -C apple <target>`.
SHELL := /bin/bash
.DEFAULT_GOAL := core

APPLE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
TEST_XCFRAMEWORK := ../build/test/OnePassFFI.xcframework

# The shell script keeps its own content stamp (apple/build/.core-stamp and
# apple/build/test/.core-stamp) and is a no-op when the Rust sources are
# unchanged; make always delegates to it.
.PHONY: core core-test test project simulators build-ios build-mac uitest screenshots clean

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
	ONEPASS_FFI_XCFRAMEWORK="$(TEST_XCFRAMEWORK)" swift test --package-path "$(APPLE_DIR)/CompanionKit"

## Xcode project from project.yml.
project: core
	cd "$(APPLE_DIR)" && xcodegen generate

IOS_DESTINATION := platform=iOS Simulator,name=OnePass M2 iPhone
IOS_RUNTIME := com.apple.CoreSimulator.SimRuntime.iOS-27-0

## The two dedicated simulators, created when missing. Never boots, stops or erases any simulator.
simulators:
	@xcrun simctl list devices | grep -q "OnePass M2 iPhone (" || \
		xcrun simctl create "OnePass M2 iPhone" com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro $(IOS_RUNTIME)
	@xcrun simctl list devices | grep -q "OnePass M2 iPad (" || \
		xcrun simctl create "OnePass M2 iPad" com.apple.CoreSimulator.SimDeviceType.iPad-mini-A17-Pro $(IOS_RUNTIME)

## Simulator build, unsigned. Uses the committed OnePass.xcodeproj (`make project` regenerates it).
build-ios: core simulators
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePass \
		-destination '$(IOS_DESTINATION)' -derivedDataPath DerivedData \
		CODE_SIGNING_ALLOWED=NO build

## Native Mac build (arm64), signed ad hoc so it runs locally.
build-mac: core
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePass \
		-destination 'platform=macOS,arch=arm64' -derivedDataPath DerivedData \
		CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= build

## XCUITest on the dedicated iPhone simulator (real Argon2id: account creation takes seconds).
## Signed ad hoc: an iOS app built with CODE_SIGNING_ALLOWED=NO has no keychain at all (-34018), so
## its Secret Key could not be stored and the test could not unlock after locking.
uitest: core simulators
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePass \
		-destination '$(IOS_DESTINATION)' -derivedDataPath DerivedData \
		CODE_SIGN_IDENTITY=- test

## Screenshots (iPhone, iPad landscape, Mac) with the demo data: `make screenshots OUT=<folder>`,
## a folder outside the repository.
screenshots: core simulators
	@if [ -z "$(OUT)" ]; then echo "usage: make -C apple screenshots OUT=<folder>" >&2; exit 64; fi
	"$(APPLE_DIR)/scripts/screenshots.sh" "$(OUT)"

clean:
	rm -rf "$(APPLE_DIR)/build" "$(APPLE_DIR)/DerivedData" "$(APPLE_DIR)/VaultKit/.build" "$(APPLE_DIR)/CompanionKit/.build" \
		"$(APPLE_DIR)/VaultKit/Sources/OnePassCore/onepass_ffi.swift"
