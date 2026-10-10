#!/bin/sh
# Name: GET DEVICE SECRETS
# Author: DeDRM
# DontUseFBInk
#
# Copies the files DeDRM's account-secret path reads out of a jailbroken Kindle's
# internal storage onto the USB partition, in the layout kindlekey.get_device_setting()
# looks for.  See README.md in this directory.
#
# Run it by putting this file in the Kindle's documents folder, ejecting, tapping it on
# the device like a book, and plugging the USB cable back in.

OUT=/mnt/us/de-drm-secrets
mkdir -p "$OUT"

date > "$OUT/status.txt"
id >> "$OUT/status.txt"

# acsr holds the ACCOUNT_SECRET lock parameter; without it a voucher version 10001 or
# later cannot be decrypted.  token.txt and activeprofile.txt say which account and
# device the secret belongs to, which is what a wrong-secret failure needs to diagnose.
for f in /var/local/java/prefs/acsr /var/local/token/token.txt /var/local/token/activeprofile.txt; do
  if [ -e "$f" ]; then
    cp "$f" "$OUT/$(basename "$f")" && echo "OK   $f" >> "$OUT/status.txt"
  else
    echo "MISS $f" >> "$OUT/status.txt"
  fi
done

sync
