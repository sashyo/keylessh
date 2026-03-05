#!/bin/bash
set -e

# =============================================================================
# KeyleSSH Marketplace Package Builder
# Creates the ZIP package required for Azure Partner Center submission
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

OUTPUT_DIR="$SCRIPT_DIR/dist"
PACKAGE_NAME="keylessh-marketplace"

print_header() {
    echo ""
    echo "==========================================="
    echo "$1"
    echo "==========================================="
}

print_header "KeyleSSH Marketplace Package Builder"

# Check for Azure CLI with Bicep
if ! az bicep version &> /dev/null; then
    echo "Installing Bicep..."
    az bicep install
fi

# Clean and create output directory
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Compile Bicep to ARM JSON
print_header "Compiling Bicep to ARM Template"
az bicep build --file main.bicep --outfile "$OUTPUT_DIR/mainTemplate.json"
echo "Generated: mainTemplate.json"

# Copy UI definition
cp createUiDefinition.json "$OUTPUT_DIR/"
echo "Copied: createUiDefinition.json"

# Create the ZIP package
print_header "Creating Package"
cd "$OUTPUT_DIR"
zip -r "../$PACKAGE_NAME.zip" .
cd "$SCRIPT_DIR"

print_header "Package Created!"
echo ""
echo "Output: $SCRIPT_DIR/$PACKAGE_NAME.zip"
echo ""
echo "Contents:"
unzip -l "$PACKAGE_NAME.zip"
echo ""
echo "Next Steps:"
echo ""
echo "1. Go to Partner Center: https://partner.microsoft.com/dashboard"
echo ""
echo "2. Create new offer: Marketplace offers → New offer → Azure Application"
echo ""
echo "3. Select plan type: Solution Template"
echo ""
echo "4. Upload the package: $PACKAGE_NAME.zip"
echo ""
echo "5. Required additional assets:"
echo "   - Logo 48x48 PNG"
echo "   - Logo 216x216 PNG"
echo "   - Screenshots (1280x720)"
echo "   - Description and documentation"
echo ""
echo "6. Submit for certification (takes 3-5 business days)"
echo ""
