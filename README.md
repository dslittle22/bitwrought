# bitwrought

bitwrought is a file integrity checker written primarily for MacOS (but it _should_ work on linux). It stores file hashes and last modified timestamps as extended attributes on the file you point it toward. The next time you run it on those files, it will recalculate hashes based on the file contents and compare it with the saved values.

If the hashes match, the data hasn't changed. If the hashes are different but the file metadata says it was modified after the previously saved value, the file was likely modified. If the hashes do not match but the file metadata says it was not modified after the value saved, the file may have suffered from bit rot or data corruption.

The name "bitwrought" is a pun: "bit rot" is when some data that was written to disk appears different when read later. This can happen for any number of reasons: the data could have been copied around on disk incorrectly, or physical degredation could have flipped some bits. In practice, this can be ruinous: your treasured photo or video library, for example, could suffer bit rot and be corrupted. You then unknowingly back up the corrupted library, overwriting any uncorrupted backups. At some point in the future, you try unsucessfully to open the library. The files, along with any backups, are corrupted.

Preventing this requires two things: 1) a way to notify you that files have been changed, and 2) a way to retrieve a backup from before the file changed. bitwrought fills the first role, and will tell you about the status of your files when you run it. bitwrought does NOT fill the second role: it doesn't make any backups of files. Are you wrought about your bits? Run bitwrought!

# Installation

Head on over to the [Releases](https://github.com/dslittle22/bitwrought/releases) page and download the zip. It comes with this README as well. Then put the binary anywhere you like to put binaries.

## For rust nerds

You can also `cargo install bitwrought` if you have the necessary [tooling](https://www.rust-lang.org/tools/install).

# Usage

Run `bitwrought PATH` to check the file at path, or all files residing in `PATH`. By default, bitwrought does not check directories recursively, but the behavior can be changed with the `--recursive` option. bitwrought's saved xattrs can also be removed with the `--delete` option. For each file specified:

- if the file has no attributes saved by bitwrought, it will calculate a file hash and save that value, as well the last modified timestamp in file metadata, in `xattr`s on the file.
- if the file has a hash, it calculates a new one and compares it to the saved one. The last modified timestamp in file metadata is compared to bitwrought's last modified timestamp (saved in an `xattr`) to determine if the file was modified or could have suffered from bit rot.

```
Usage: bitwrought [OPTIONS] <path>...

Arguments:
  <path>...  one or more files or directories

Options:
  -r, --recursive  check all files in the directory recursively
  -d, --delete     delete hash and timestamp xattrs saved by bitwrought
  -v, --verbose    verbose output
  -h, --help       Print help
  -V, --version    Print version
```

# FAQ

Q: If my file suffers from bit rot, why should you expect that the saved extended attributes remain intact?

A: [APFS checksums its own metadata, but not user data](https://arstechnica.com/gadgets/2016/06/a-zfs-developers-analysis-of-the-good-and-bad-in-apples-new-apfs-file-system/3/), meaning that if a file suffers from bit rot, there is a high chance the extended attributes are fine.

Q: How should I use bitwrought?

A: I think the best use case for bitwrought is for files that you care about that seldom change. For example, you might run bitwrought on a folder of music or photos.

Q: Is bitwrought fast?

A: Reasonably, yes. It is only single threaded right now, which limits its speed. But on my local machine it takes a couple of minutes per gigabyte. All data reads are buffered so it can handle large files, and changing the buffer size has surprisingly little impact on the speed of the program.
