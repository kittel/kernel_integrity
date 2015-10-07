Kernel Integrity Check
======================

This tool is for both validating the kernel code integrity of a running VM as
well as to check the integrity of kernel stack structures with the aim to find
control structures for return-oriented-programming like approaches.


Usage
-----

#### Mounting guest filesystem

When mounting the guest filesystem, you may want to automatically
update symlink destinations:

Guest-VM-absolute symlinks stay mountpoint-relative that way:

`sshfs -o transform_symlinks vm@vmhost:/ mountpoint/`
