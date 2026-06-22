# crashed Writeup

## Challenge Information
- **Title:** crashed
- **Category:** Forensics
- **Description:** My friends keep pressing my power button, this time my whole pc shut down while I was doing my practice paper :( Help me recover it please

## Initial Analysis
The provided file `crashed.E01` is an Expert Witness Format (EWF) forensic image. 

First, I checked the partition layout and filesystem. Using `fls` from Sleuthkit, I identified that the image contains a standard Linux root filesystem (Ext4).

```bash
fls crashed.E01
```

## Exploration
I explored the home directory of the user `johnsieberr` (inode 787). I found a `flag.txt` (inode 1800), but its content was just "a", which seemed like a distraction.

```bash
icat crashed.E01 1800
# Output: a
```

The challenge description mentioned a "practice paper" and a sudden shutdown. In Linux filesystems, orphaned files recovered after a crash are often placed in the `lost+found` directory.

## Finding the Flag
I checked the `lost+found` directory (inode 11) and found an orphaned file named `#1795`.

```bash
fls -r crashed.E01 11
# Output: r/r 1795: #1795
```

Reading the content of inode 1795 revealed the "practice paper":

```bash
icat crashed.E01 1795
```

Content:
```
1) Where are orphaned files placed in a Linux system by fsck 
Ans: lost+found

2a) What are the basic properties of a recursive function?
Ans: A base case, calling itself recursively and approach the base case as it's state changes.

2b) Write, in python, a recursive function that returns a list of all numbers from an input list.
Ans: 
def recurse_number(lst):
  if len(lst) <= 0:
    return []
  curr = lst[0]
  if isinstance(curr, int):
    return [curr] + recurse_number(lst[1:])
  return [] + recurse_number(lst[1:])

2c) Run your code with input ['s', 'c', 't', 'f', '{', 'p', 0, 'w', 3, 'r', '_', 0, 'f', 'f', '}']
Ans: [0, 3, 0]
```

The input list in question 2c contains the characters of the flag:
`['s', 'c', 't', 'f', '{', 'p', 0, 'w', 3, 'r', '_', 0, 'f', 'f', '}']`

By combining these elements (and converting the integers 0, 3, 0 to their string representations), I obtained the flag.

## Flag
`sctf{p0w3r_0ff}`
