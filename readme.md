# rsa-finder
A quick and dirty, and *very* naive approach to searching for RSA keys in blobs (memory dumps for instance). Not complete, but it did solve at least one CTF challenge, so it's useful sometimes :)

Based on this: <http://www.turing321.com/hex_edit/hexprobe/binary_file.htm>, but with some tweaks from observations for the specific challenge I was working on. The turing321-link is a better reference for this sort of thing.

**NOTE:** There is a big chance that this will not work out of the box for future specific needs, it is more a clue finder than a full forensics tool.

## build
```
go build .
```

## usage
```
./rsa-finder [-insane] filename.bin
```
Use `-insane` to bypass most sanity checks on the key. Will present with loads of more results, but may find something that wasn't found otherwise (such as public keys without private components).
