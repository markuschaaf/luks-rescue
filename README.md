# luks-rescue
Decrypt "unreadable" LUKS AEAD images

I hacked this in a hurry to regain access to a crashed computer. The
harddrive was encrypted with `aes-gcm-plain64`. Although the LUKS header
was seemingly intact, Linux wouldn't let me read a single sector. Every
sector reported a bad AEAD tag.

`luks-rescue` will find the encrypted data in an image file and copy
the decrypted plaintext to another file. You will need the master key,
which you may extract with:
<pre>
cryptsetup luksDump --dump-master-key --master-key-file <i>keyfile</i> <i>image</i>
</pre>

## Usage
<pre>
luks-rescue image_file=... master_key_file=... sector_count=...
</pre>
optional parameters (with defaults):
`sector_size=512`, `alignment=32K`, `certainty=25%`

output parameters:
`data_file=...`, `tag_file=...`

If you don't know sector size or sector count, `cryptsetup open` the
device and use `fdisk -l`.
