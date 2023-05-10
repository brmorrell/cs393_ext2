# Project Writeup

## Goals

I set out to implement some of the possible improvements to the ext2 filesystem project we started earlier in the semester.  My original plan was to add
 - `cat` for large files
 - `mkdir` to create directories
 - `rm` to remove files
 - `unmount` to save the changes back to the filesystem
 

## Implemented Extensions:

In the end, I managed to implement quite a bit more than I planned, and encountered some interesting code artifacts along the way.  I will detail those in the following sections.  The current set of features I have implemented (beyond the original project) is
 - `cat <file_name>` for large files
 - `mkdir <dir_name>` to create directories
  - `mkdir -p <dir_path>` to create a path of directories
 - `rm <name>` to remove/unlink files and empty directories
  - `rm -r <name>` to recursively clear out directories, only deleting files if the last link is deleted
 - `link <source_name> <destination_name>` to create hard links to files from additional locations
 - `unmount` to save the changes back to the filesystem
 - `import <host_file> <destination>` to bring files in from the host filesystem as exact byte-for-byte copies
 - `export <source_file> <host_target>` to do the opposite, and put a file from the ext2 system onto the host system
 - `mv <source_name> <destination_name>` to efficiently link & unlink in one command
 
Additionally, all "name" arguments can take a path to a file instead of needing to be in the same directory.  For `mkdir -p <dir_path>`, the path still needs to be all-new, since it already needs to take a path instead of a name.

When implementing these extensions, I split the functions between the `Ext2` struct and the `inode` struct, as they made sense at the time.  This may have lead to some issues, but I don't know if they could have been prevented by using a different structure.  Most of the separation was driven by my sense of what made sense for the inode to do, which is mainly getting blocks from the inode and writing to the file it describes.  The full set of functions and their documentation can be found by running `cargo doc` and `cargo doc --open`.

## Peculiarities and fixed bugs

First, there was a bug in the original code hat i needed to fix - it adds extra blocks to the end of the filesystem equal to `block_offset`.  This is because it takes a slice equal to the number of total blocks in order to read the blocks into the `Ext2` struct during construction, but it already moved forward by `block_offset` blocks when reading the superblock and block group descriptors.  I found this bug when implementing `unmount` and my written file was exactly `3072` bytes longer than the original, with empty blocks at the end.  This bug is very simple to fix, and probably important to deal with since those last blocks would be out of bounds.

Most of my difficulties had to do with the borrow checker.  Specifically, I repeatedly had to deal with needing mutable references in multiple places at once.  The root of this issue is that getting the inode using the convenient getter function(s) takes a reference to `self`, the `Ext2` struct that we are working on.  Then, when modifying the inode's file data later, we need to mutate `self`, and rust doesn't like that we could be modifying the inode reference we are still holding onto (and it shouldn't like that - it would be very unsafe to do that!).  To solve this, I had to get the inode manually whenever we mutate `self` within the same method (by copying the code from `get_mut_inode`).  This allows us to pass around the mutable reference to `self` without worrying.

Another tricky bug I had to deal with, although possibly not worth mentioning for any reason other than to document its symptoms, was a bug in my bitmap math.  It was just a bug in the `dealloc` functions, where they were grabbing the wrong byte when flipping a bit.  This bug was very tricky to track down though, because the symptoms initially appeared bizarre.  Sometimes, removing a file would not result in any issues - because of how I was testing it, this appeared to be true for certain files (that had convenient inode numbers).  When other files were removed (and I now know that this was unintentionally freeing unrelated inodes), I could then create new directories only to find that directory entries within other directories were modified.  This in some cases resulted in recursive directories, so I was looking for bugs that would somehow edit those directory entries during `remove`.  In reality, what was happening was that the inode (and sometimes blocks) for the already existing directory was marked as free, and allocated to the new directory as well.  Then, in constructing the new directory, the data blocks were overwritten with new data, and it only happened to show up in the old inode because the inodes pointed to the same data blocks.  The moral of this story is really just that if directories are being modified by seemingly unrelated actions, it may be helpful to check that all of the inodes and data blocks are marked free or used as appropriate.

## Potential Improvements

There are a few things that could be considered potential improvements from the way I wrote this code.  First, changing which structs own which functions may help with the borrow checker difficulties, although I think the bigger solution would be to change the function signatures of `append_to_file` and `write_block` to require only the specific parts of the `Ext2` struct that they need to access, rather than taking a mutable reference to the full struct.

I also allowed directory entries to have any size, rather than aligning them to every 4 bytes.  This change would not take much (probably just changing the `dir_entry_as_bytes` function that produces directory entries), but it also doesn't do much in my eyes - the code is perfectly capable of handling arbitrary entry sizes, and I wouldn't change any of it as a result of limiting the possible sizes.

I neglected the creation of rigorous tests, so that would be a very reasonable next step in this project.  Other than that, I would consider adding an ability to take the filesystem as a command line argument (which would naturally require loading the file at runtime).  There are also all of the originally suggested extensions that I chose not to implement, such as `mount` or making it `#[nostd]` compatible.

There are still some bugs I'm finding and working out - check back in a few days and there may be some updates to the repo.  I may also add code examples to the documentation

##  Update 5/10

Fixed a bug relating to pointer blocks - large files would have issues before because indirect pointer blocks were not accessed correctly by `set_block`.  Should be all good now, as `set_block` will alloc/dealloc pointer blocks as necessary.  Also lost+found appears a little broken, not sure what that's about but I hadn't been testing on it and it appears it reads as containing blank directory entries?

### Original readme:

This is a starting point for parsing and navigating ext2 file systems.
`cargo run` will start a session that looks like a shell. All you can
do for now are the `ls`, and `cd` commands.
It's left as an exercise to implement `cat` to view the contents of files,
and removing other limitations.

Here's an example session:
```
% cargo run
   <building and intro stuff>
:> ls
.	..	lost+found	test_directory	hello.txt	
:> cat hello.txt
cat not yet implemented
:> cd test_directory
:> ls
.	..	file_in_folder.txt	
:> cd file_in_folder.txt    # <- whoops
:> ls
'm a file inside a folder.  # <- whoops^2
	
:> 
```

Limitations (also possible exercises):

 - see "TODO" in `cd` command - you can currently `cd` into a text
   file - whoops!
 - implement `cat` command to view text files
 - currently it only parses small directories, remove this limitation
 - implement `mkdir`
 - implement `link <source name> <destination path>` to create hard
   links
 - write tests
 - write more tests
 - implement `rm` (aka unlink) for plain files
 - make `link` robust against ... (what should `link` be robust
   against?)
 - once modifications can be made, implement `unmount` which cleanly
   writes modifications back to the "device" (file)
 - implement `import` to get a file from the "host" filesystem into
   ours
 - implement a `mount <host-file> <dirname>` command to mount a local file as an ext2
   filesystem over an empty directory.


Big projects:

 - make it `#[no_std]` compatible
 - instead of reading from a big byte-buffer, read from a device into
   manually managed page-sized buffers
 - implement a buffer cache
 - implement `fsck` - identify different inconsistencies and find them
 - implement a simple line editor (ed?) to create text files in the
   filesystem

Bigger projects:

 - ext4 support?
 - integrate with reedos kernel memory allocation
 - integrate caching with kernel VM

Credits: Reed College CS393 students, @tzlil on the Rust #osdev discord
