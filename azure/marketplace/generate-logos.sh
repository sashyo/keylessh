#!/bin/bash

# =============================================================================
# Generate PNG logos from SVG for Azure Marketplace
# Requires: inkscape, imagemagick, or rsvg-convert
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

SVG_FILE="logo.svg"

if [ ! -f "$SVG_FILE" ]; then
    echo "Error: $SVG_FILE not found"
    exit 1
fi

echo "Generating PNG logos from $SVG_FILE..."

# Try different conversion tools in order of preference

# Option 1: Inkscape (best quality)
if command -v inkscape &> /dev/null; then
    echo "Using Inkscape..."
    inkscape "$SVG_FILE" -w 48 -h 48 -o logo-48x48.png
    inkscape "$SVG_FILE" -w 216 -h 216 -o logo-216x216.png
    echo "Done! Generated:"
    ls -la logo-*.png
    exit 0
fi

# Option 2: rsvg-convert (librsvg)
if command -v rsvg-convert &> /dev/null; then
    echo "Using rsvg-convert..."
    rsvg-convert -w 48 -h 48 "$SVG_FILE" -o logo-48x48.png
    rsvg-convert -w 216 -h 216 "$SVG_FILE" -o logo-216x216.png
    echo "Done! Generated:"
    ls -la logo-*.png
    exit 0
fi

# Option 3: ImageMagick convert
if command -v convert &> /dev/null; then
    echo "Using ImageMagick..."
    convert -background none -resize 48x48 "$SVG_FILE" logo-48x48.png
    convert -background none -resize 216x216 "$SVG_FILE" logo-216x216.png
    echo "Done! Generated:"
    ls -la logo-*.png
    exit 0
fi

# Option 4: Use an online tool
echo ""
echo "No conversion tool found. Install one of:"
echo "  - inkscape: sudo apt install inkscape"
echo "  - librsvg: sudo apt install librsvg2-bin"
echo "  - imagemagick: sudo apt install imagemagick"
echo ""
echo "Or convert manually using an online tool:"
echo "  1. Open logo.svg in a browser"
echo "  2. Use https://svgtopng.com/ or similar"
echo "  3. Download as 48x48 and 216x216 PNG"
echo ""
exit 1
