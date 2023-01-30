Plan: make a CLI in rust that allows you to call the utility with files:

- default of all files within the directory it's run in
- you can pass in a list of filenames (absolute or relative) as arguments to the program
- you can specify a (relative or absolute) file which lists all filenames you want to check (--file=~/Documents/list.txt)

Checksums and previous write generation counters are stored as xattr's on the files.

Things I haven't fully thought through:

- soft / hard links
- permissions error

```
statuses = [no_file, bad_permissions new, ok, modified, wrought]
file_statuses = []

for file in files
    if file does not exist:
        file_statuses.append(no_file)
        break
    if can't access file:
        file_statuses.append(bad_permissions)
        break
    if no entry:
        calculate hash
        getaddrlist(write generation counter)
        save entry
        file_statuses.append(new)
        break

    retrieve saved hash
    retrieve previous write generation counter
    getaddrlist(write generation counter)

    if write generation counters don't match:
        calculate hash
        getaddrlist(write generation counter)
        save entry
        file_statuses.append(modified)
        break

    calculate hash
    if hash matches:
        file_statuses.append(ok)

    else:
        file_statuses.append(wrought)
```
