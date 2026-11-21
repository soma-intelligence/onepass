# How to add a new iPhone, iPad or Mac to OnePass

On the new device, choose to add it from another device: it shows a QR code that renews every 30 seconds. On an unlocked iPhone or iPad, go to Settings > Devices > Add a Device and scan it. Both screens then show the same 6-digit code; check that they match and confirm with Face ID or your master password. Nothing leaves the approving device before both confirmations.

## Step by step

1. Install OnePass on the new device ([App Store](https://apps.apple.com/app/id6831411523)) and pick the option to add it from another device.
2. On your unlocked iPhone or iPad: Settings > Devices > Add a Device, then scan the QR shown by the new device.
3. Compare the 6-digit code on both screens. If they differ, cancel: someone may be on the channel.
4. Confirm with Face ID or your master password.
5. The new device appears in the signed device list.

Without another device at hand, restore with your [Emergency Kit](master-password-secret-key-emergency-kit.md) and master password instead.

## Manage your devices

Settings > Devices shows the signed device list. You can rename a device or remove it. A removed device erases its data, its Secret Key and its biometric enrollment the next time it unlocks or syncs. The core also supports a full key rotation without a device, and the formal model `formal/proverif/rotation.pv` checks that what is written after a rotation stays secret from the removed device.

## Lend a few items to a borrowed device (public computer mode)

You can lend a few items to a device that is not yours for 15 to 60 minutes. The guest session lives in memory only, is read-only, and ends on expiry, from your phone, after 5 idle minutes, or when the app leaves the screen.

## Related

- [Master password, Secret Key and Emergency Kit](master-password-secret-key-emergency-kit.md)
- [How sync through iCloud works](icloud-sync.md)
- [OnePass threat model](threat-model.md)
- [README](../../README.md)
