# Getting a Kindle's account secret

Some KFX books are locked with an `ACCOUNT_SECRET` lock parameter in addition to the
device serial (voucher envelope versions from 10001 on).  A serial number alone cannot
decrypt one of those; the account secret is also needed.

That secret is pushed to the device by Amazon over the `legacy.SET.ACSR` ToDo topic and
written to `/var/local/java/prefs/acsr`.  `/var/local` is internal storage, and USB mass
storage exports only the FAT partition, so the file is not visible while the Kindle is
plugged in.  It cannot be derived from the serial: it is per-account and per-registration,
and a factory reset or a deregistration deletes it.

The plugin reads the secret from `de-drm-secrets/` on any mounted Kindle volume, so this
script's only job is to put it there.

## Running the script

Jailbroken device required, because reading `/var/local` needs root.

1. Copy `extract_device_secrets.sh` into the Kindle's `documents` folder.
2. Eject and unplug.
3. On the device, tap the script like a book.  Scriptlets in `documents` are indexed as
   books, and `# DontUseFBInk` in the header stops the output being piped to the screen,
   which is what you want for a credential file.
4. Plug the cable back in.

You should now have `de-drm-secrets/` at the root of the mounted Kindle, containing
`acsr` plus a `status.txt` recording which source paths were found and under which uid.
`status.txt` is the first thing to read if the plugin reports the secret as missing.

With a root shell on the device instead, the same thing by hand:

```sh
mkdir -p /mnt/us/de-drm-secrets
cp /var/local/java/prefs/acsr /mnt/us/de-drm-secrets/
```

## If you cannot jailbreak

A 40-character account secret from another source can be dropped in as
`de-drm-secrets/account_secret` instead of `acsr`.  Note that a present-but-unreadable
`acsr` takes precedence and does not fall back to `account_secret`, so leave only one of
the two files in place.
