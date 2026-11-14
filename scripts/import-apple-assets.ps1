# Copies the iPhone app's rendered assets (apple/App/Resources/Assets.xcassets)
# into the Android and Windows apps, so the three show the same icons: the app
# icon, the 26 category tiles, the settings tiles, card networks and sign-in
# providers. These are the project's own assets (AGPL), not SF Symbols.
#
#   powershell -File scripts/import-apple-assets.ps1
#
# Run again whenever the Apple assets change. Windows only (System.Drawing).
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $PSScriptRoot
$xc = Join-Path $root "apple/App/Resources/Assets.xcassets"
$res = Join-Path $root "android/app/src/main/res"
$web = Join-Path $root "desktop/src/assets"

function Resize([string]$src, [string]$dst, [int]$size) {
    $img = [System.Drawing.Image]::FromFile($src)
    try {
        $bmp = New-Object System.Drawing.Bitmap $size, $size
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $g.DrawImage($img, 0, 0, $size, $size)
        $g.Dispose()
        New-Item -ItemType Directory -Force (Split-Path $dst) | Out-Null
        $bmp.Save($dst, [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
    } finally {
        $img.Dispose()
    }
}

# camelCase -> snake_case for Android resource names.
function Snake([string]$s) { ($s -creplace '([A-Z])', '_$1').ToLower() }

# ---- App icon -------------------------------------------------------------------
$appIcon = Join-Path $xc "AppIcon.appiconset/AppIcon-ios.png"
$densities = @{ "mdpi" = 1; "hdpi" = 1.5; "xhdpi" = 2; "xxhdpi" = 3; "xxxhdpi" = 4 }
foreach ($d in $densities.Keys) {
    $f = $densities[$d]
    # Legacy launcher icon (48 dp) and the adaptive foreground (108 dp, full bleed:
    # the iOS icon is a full-bleed gradient with its mark well inside the safe zone).
    Resize $appIcon (Join-Path $res "mipmap-$d/ic_launcher.png") ([int](48 * $f))
    Resize $appIcon (Join-Path $res "mipmap-$d/ic_launcher_round.png") ([int](48 * $f))
    Resize $appIcon (Join-Path $res "mipmap-$d/ic_launcher_foreground.png") ([int](108 * $f))
}
Resize $appIcon (Join-Path $web "app-icon.png") 128

# ---- Category tiles ----------------------------------------------------------------
Get-ChildItem (Join-Path $xc "Categories") -Directory | ForEach-Object {
    $name = $_.Name -replace '^category-', '' -replace '\.imageset$', ''
    $png = Get-ChildItem $_.FullName -Filter *.png | Select-Object -First 1
    # 38 dp rows, 64 dp headers: 192 px covers xxxhdpi at 48 dp.
    Resize $png.FullName (Join-Path $res ("drawable-nodpi/cat_" + (Snake $name) + ".png")) 192
    Resize $png.FullName (Join-Path $web "categories/$name.png") 128
}

# ---- Settings tiles ------------------------------------------------------------------
Get-ChildItem (Join-Path $xc "Settings") -Directory | ForEach-Object {
    $name = $_.Name -replace '^settings-', '' -replace '\.imageset$', ''
    $png = Get-ChildItem $_.FullName -Filter *.png | Select-Object -First 1
    if ($png) {
        Resize $png.FullName (Join-Path $res ("drawable-nodpi/settings_" + (Snake $name) + ".png")) 120
        Resize $png.FullName (Join-Path $web "settings/$name.png") 96
    }
}

# ---- Card networks and sign-in providers (SVG): the web view draws them as is --------
foreach ($group in @("Cards", "Providers")) {
    Get-ChildItem (Join-Path $xc $group) -Directory | ForEach-Object {
        $svg = Get-ChildItem $_.FullName -Filter *.svg | Select-Object -First 1
        if ($svg) {
            $dst = Join-Path $web ($group.ToLower())
            New-Item -ItemType Directory -Force $dst | Out-Null
            Copy-Item $svg.FullName (Join-Path $dst $svg.Name) -Force
        }
    }
}

Write-Host "Apple assets imported."
