#!/usr/bin/env bash
# Build the "BG Horn" Teams app package (manifest + icons -> zip).
#
# The manifest id (Teams app GUID) is stable and lives in the template.
# Domain and AAD client id are substituted here so the same template
# serves the test domain and the production cutover:
#
#   APEX=s.bghorn.ac.at CLIENT_ID=<guid> ./package.sh
#
# Remember: the Entra Application ID URI must equal the manifest's
# webApplicationInfo.resource (api://auth.<APEX>/<CLIENT_ID>).
#
# Icons are committed artifacts, generated from the school branding in
# the bghorn.ac.at repo (media/logo.png, media/favicon.ico):
#   magick media/logo.png -resize 176x176 -background white \
#     -gravity center -extent 192x192 -alpha remove -alpha off color.png
#   magick media/favicon.ico -resize 32x32 -fill white -colorize 100 \
#     PNG32:outline.png   # Teams wants white-on-transparent here
set -euo pipefail
cd "$(dirname "$0")"

APEX="${APEX:-s.bghorn.ac.at}"
CLIENT_ID="${CLIENT_ID:-9bbc5abe-5eaf-4f2f-a000-35f9d6dd47d0}"

sed -e "s/@APEX@/${APEX}/g" -e "s/@CLIENT_ID@/${CLIENT_ID}/g" \
  manifest.template.json > manifest.json

out="bg-horn-teams-${APEX}.zip"
rm -f "$out"
if command -v zip >/dev/null; then
  zip -j "$out" manifest.json color.png outline.png
else
  nix run m#zip -- -j "$out" manifest.json color.png outline.png
fi
echo "wrote $out"
