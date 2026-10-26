# OnePass Apple build. Run with `make -C apple <target>`.
SHELL := /bin/bash
.DEFAULT_GOAL := core

APPLE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
TEST_XCFRAMEWORK := ../build/test/OnePassFFI.xcframework

# The shell script keeps its own content stamp (apple/build/.core-stamp and
# apple/build/test/.core-stamp) and is a no-op when the Rust sources are
# unchanged; make always delegates to it.
.PHONY: core core-test test project simulators build-ios build-mac uitest screenshots clean
.PHONY: simulators-m6 build-watch build-vision screenshots-m6
.PHONY: simulator-m3 uitest-autofill

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
M3_SIMULATOR := OnePass M3 iPhone
M3_DESTINATION := platform=iOS Simulator,name=$(M3_SIMULATOR)

## The two dedicated simulators, created when missing. Never boots, stops or erases any simulator.
simulators:
	@xcrun simctl list devices | grep -q "OnePass M2 iPhone (" || \
		xcrun simctl create "OnePass M2 iPhone" com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro $(IOS_RUNTIME)
	@xcrun simctl list devices | grep -q "OnePass M2 iPad (" || \
		xcrun simctl create "OnePass M2 iPad" com.apple.CoreSimulator.SimDeviceType.iPad-mini-A17-Pro $(IOS_RUNTIME)

## The milestone 3 simulator (AutoFill UI test), created when missing. Never touches any other one.
simulator-m3:
	@xcrun simctl list devices | grep -q "$(M3_SIMULATOR) (" || \
		xcrun simctl create "$(M3_SIMULATOR)" com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro $(IOS_RUNTIME)

## Simulator build, unsigned. Uses the committed OnePass.xcodeproj (`make project` regenerates it).
build-ios: core simulators
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePass \
		-destination '$(IOS_DESTINATION)' -derivedDataPath DerivedData \
		CODE_SIGNING_ALLOWED=NO build
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePassAutoFill \
		-destination '$(IOS_DESTINATION)' -derivedDataPath DerivedData \
		CODE_SIGNING_ALLOWED=NO build

WATCH_DESTINATION := platform=watchOS Simulator,name=OnePass M6 Watch
WATCH_RUNTIME := com.apple.CoreSimulator.SimRuntime.watchOS-27-0
VISION_RUNTIME := com.apple.CoreSimulator.SimRuntime.xrOS-27-0

## Milestone 6 simulators (Apple Watch, Vision Pro when a visionOS 27 runtime exists), created
## when missing. Never boots, stops or erases any simulator.
simulators-m6:
	@xcrun simctl list devices | grep -q "OnePass M6 Watch (" || \
		xcrun simctl create "OnePass M6 Watch" com.apple.CoreSimulator.SimDeviceType.Apple-Watch-Series-12-46mm $(WATCH_RUNTIME)
	@if xcrun simctl list runtimes | grep -q "$(VISION_RUNTIME)"; then \
		xcrun simctl list devices | grep -q "OnePass M6 Vision Pro (" || \
			xcrun simctl create "OnePass M6 Vision Pro" com.apple.CoreSimulator.SimDeviceType.Apple-Vision-Pro-4K $(VISION_RUNTIME); \
	else echo "no visionOS 27 runtime: OnePass M6 Vision Pro not created"; fi

## watchOS Simulator build of the watch app and its complication, signed ad hoc.
build-watch: core simulators-m6
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePassWatch \
		-destination '$(WATCH_DESTINATION)' -derivedDataPath DerivedData \
		CODE_SIGN_IDENTITY=- build

VISION_DESTINATION := platform=visionOS Simulator,name=OnePass M6 Vision Pro

## visionOS Simulator build of the app, signed ad hoc. Falls back to the generic visionOS
## Simulator destination when the dedicated simulator does not exist (no visionOS 27 runtime).
build-vision: core simulators-m6
	@if xcrun simctl list devices | grep -q "OnePass M6 Vision Pro ("; then \
		dest='$(VISION_DESTINATION)'; else dest='generic/platform=visionOS Simulator'; fi; \
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePass \
		-destination "$$dest" -derivedDataPath DerivedData \
		CODE_SIGN_IDENTITY=- build

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

## AutoFill XCUITest on `OnePass M3 iPhone`, signed ad hoc (the simulator embeds the App Group,
## keychain group and provider entitlements). The test drives AutoFillHost; OnePass and its
## extension are installed beside it first, since `xcodebuild test` installs only the host app.
## Boots only the M3 simulator, and only when it is shut down.
uitest-autofill: core simulator-m3
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePassAutoFill \
		-destination '$(M3_DESTINATION)' -derivedDataPath DerivedData \
		CODE_SIGN_IDENTITY=- build-for-testing
	xcrun simctl bootstatus "$(M3_SIMULATOR)" -b
	xcrun simctl install "$(M3_SIMULATOR)" "$(APPLE_DIR)/DerivedData/Build/Products/Debug-iphonesimulator/OnePass.app"
	cd "$(APPLE_DIR)" && xcodebuild -project OnePass.xcodeproj -scheme OnePassAutoFill \
		-destination '$(M3_DESTINATION)' -derivedDataPath DerivedData \
		CODE_SIGN_IDENTITY=- test-without-building

## Screenshots (iPhone, iPad landscape, Mac) with the demo data: `make screenshots OUT=<folder>`,
## a folder outside the repository.
screenshots: core simulators
	@if [ -z "$(OUT)" ]; then echo "usage: make -C apple screenshots OUT=<folder>" >&2; exit 64; fi
	"$(APPLE_DIR)/scripts/screenshots.sh" "$(OUT)"

## Milestone 6 screenshots (Apple Watch list, Vision Pro list and detail, light and dark) with
## fictional data: `make screenshots-m6 OUT=<folder>`, a folder outside the repository.
screenshots-m6: core simulators-m6
	@if [ -z "$(OUT)" ]; then echo "usage: make -C apple screenshots-m6 OUT=<folder>" >&2; exit 64; fi
	"$(APPLE_DIR)/scripts/screenshots-m6.sh" "$(OUT)"

clean:
	rm -rf "$(APPLE_DIR)/build" "$(APPLE_DIR)/DerivedData" "$(APPLE_DIR)/VaultKit/.build" "$(APPLE_DIR)/CompanionKit/.build" \
		"$(APPLE_DIR)/VaultKit/Sources/OnePassCore/onepass_ffi.swift"
