# Slide copy and the screenshot each slide frames. Shots live in ../shots (real simulator captures).
PHONE = [
    dict(name="home", shot="p69-home.png", head="Every password, one calm place",
         sub="Logins, cards and passkeys on every Apple device."),
    dict(name="detail", shot="p69-detail.png", head="Sign in without the hunt",
         sub="Passwords and one-time codes fill in Safari and apps."),
    dict(name="watchtower", shot="p69-watchtower.png", head="See what needs a fix",
         sub="Watchtower flags weak and reused passwords."),
    dict(name="duplicates", shot="p69-duplicates.png", head="Tidy up duplicates",
         sub="See what differs, then merge in one go."),
    dict(name="locked", shot="p69-locked-dark.png", head="Yours alone, end to end",
         sub="Encrypted on your device and in your private iCloud.", bg="ink", dark=True),
    dict(name="items", shot="p69-items.png", head="Open source, top to bottom",
         sub="Read every line of the code that guards your vault."),
]


def with_prefix(items, prefix):
    return [dict(it, shot=it["shot"].replace("p69-", prefix + "-")) for it in items]


PAD = [
    dict(name="browse", shot="pad-detail.png", head="Every password, one calm place",
         sub="Logins, cards and passkeys on every Apple device."),
    dict(name="watchtower", shot="pad-watchtower.png", head="See what needs a fix",
         sub="Watchtower flags weak and reused passwords."),
    dict(name="duplicates", shot="pad-duplicates.png", head="Tidy up duplicates",
         sub="See what differs, then merge in one go."),
    dict(name="locked", shot="pad-locked-dark.png", head="Yours alone, end to end",
         sub="Encrypted on your device and in your private iCloud.", bg="ink", dark=True),
]

MAC = [
    dict(name="browse", shot="mac-detail.png", head="Every password, one calm place",
         sub="Logins, cards and passkeys on every Apple device."),
    dict(name="watchtower", shot="mac-watchtower.png", head="See what needs a fix",
         sub="Watchtower flags weak and reused passwords."),
    dict(name="duplicates", shot="mac-duplicates.png", head="Tidy up duplicates",
         sub="See what differs, then merge in one go."),
    dict(name="locked", shot="mac-locked-dark.png", head="Yours alone, end to end",
         sub="Encrypted on your Mac and in your private iCloud.", bg="dusk", dark=True),
]

SETS = {
    "iphone-6.9": (1320, 2868, "iphone", PHONE),
    "iphone-6.3": (1206, 2622, "iphone", with_prefix(PHONE, "p63")),
    "ipad-13": (2064, 2752, "ipad", PAD),
    "mac": (2880, 1800, "mac", MAC),
}
