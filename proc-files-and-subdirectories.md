# proc - process information pseudo-filesystem

DESCRIPTION         
The proc filesystem is a pseudo-filesystem which provides an interface to kernel data structures.  It is commonly mounted at /proc.
Most of the files in the proc filesystem are read-only, but some files are writable, allowing kernel variables to be changed.

Mount options
The proc filesystem supports the following mount options:

### hidepid=n (since Linux 3.3)
This option controls who can access the information in /proc/[pid] directories.  The argument, n, is one of the following values:

- 0 : Everybody may access all /proc/[pid] directories.  This is the traditional behavior, and the default if this mount option is not specified.

- 1 : Users may not access files and subdirectories inside any /proc/[pid] directories but their own (the /proc/[pid] directories themselves remain visible).  Sensitive files such as /proc/[pid]/cmdline and /proc/[pid]/status are now protected against other users.  This makes it impossible to learn whether any user is running a specific program (so long as the program doesn't otherwise reveal itself by its behavior).

- 2 : As for mode 1, but in addition the /proc/[pid] directories belonging to other users become invisible.  This means that /proc/[pid] entries can no longer be used to discover the PIDs on the system.  This doesn't hide the fact that a process with a specific PID value exists (it can be learned by other means, for example, by "kill -0 $PID"), but it hides a process's UID and GID, which could otherwise be learned by employing stat(2) on a /proc/[pid] directory.  This greatly complicates an attacker's task of gathering information about running processes (e.g., discovering whether some daemon is running with elevated privileges, whether another user is running some sensitive program, whether other users are running any program at all, and so on).

### gid=gid (since Linux 3.3)
Specifies the ID of a group whose members are authorized to learn process information otherwise prohibited by hidepid (i.e., users in this group behave as though /proc was mounted with hidepid=0).  This group should be used instead of approaches such as putting nonroot users into the sudoers(5) file.

## Overview
Underneath /proc, there are the following general groups of files and subdirectories:

### /proc/[pid] subdirectories
Each one of these subdirectories contains files and subdirectories exposing information about the process with the corresponding process ID.

Underneath each of the /proc/[pid] directories, a *task* subdirectory contains subdirectories of the form task/[tid], which contain corresponding information about each of the threads in the process, where tid is the kernel thread ID of the thread.

The /proc/[pid] subdirectories are visible when iterating through /proc with getdents(2) (and thus are visible when one uses ls(1) to view the contents of /proc).

### /proc/[tid] subdirectories
Each one of these subdirectories contains files and subdirectories exposing information about the thread with the corresponding thread ID.  The contents of these directories are the same as the corresponding /proc/[pid]/task/[tid] directories.

The /proc/[tid] subdirectories are not visible when iterating through /proc with getdents(2) (and thus are not visible when one uses ls(1) to view the contents of /proc).

### /proc/self
When a process accesses this magic symbolic link, it resolves to the process's own /proc/[pid] directory.

### /proc/thread-self
When a thread accesses this magic symbolic link, it resolves to the process's own /proc/self/task/[tid] directory.

### /proc/[a-z]*
Various other files and subdirectories under /proc expose system-wide information.

All of the above are described in more detail below.

Files and directories
The following list provides details of many of the files and directories under the /proc hierarchy.

### /proc/[pid]
There is a numerical subdirectory for each running process; the subdirectory is named by the process ID.  Each /proc/[pid] subdirectory contains the pseudo-files and directories described below.

The files inside each /proc/[pid] directory are normally owned by the effective user and effective group ID of the process. However, as a security measure, the ownership is made root:root if the process's "dumpable" attribute is set to a value other than 1.

Before Linux 4.11, root:root meant the "global" root user ID and group ID (i.e., UID 0 and GID 0 in the initial user namespace).  Since Linux 4.11, if the process is in a noninitial user namespace that has a valid mapping for user (group) ID 0 inside the namespace, then the user (group) ownership of the files under /proc/[pid] is instead made the same as the root user (group) ID of the namespace.  This means that inside a container, things work as expected for the container "root" user.

The process's "dumpable" attribute may change for the following reasons:

*  The attribute was explicitly set via the prctl(2) PR_SET_DUMPABLE operation.

*  The attribute was reset to the value in the file /proc/sys/fs/suid_dumpable (described below), for the reasons described in prctl(2).

Resetting the "dumpable" attribute to 1 reverts the ownership of the /proc/[pid]/* files to the process's effective UID and GID.

### /proc/[pid]/attr
The files in this directory provide an API for security modules.  The contents of this directory are files that can be read and written in order to set security-related attributes. This directory was added to support SELinux, but the intention was that the API be general enough to support other security modules.  For the purpose of explanation, examples of how SELinux uses these files are provided below.

This directory is present only if the kernel was configured with CONFIG_SECURITY.

### /proc/[pid]/attr/current (since Linux 2.6.0)
The contents of this file represent the current security attributes of the process.

```
In SELinux, this file is used to get the security context of a process.  Prior to Linux 2.6.11, this file could not be used to set the security context (a write was always denied), since SELinux limited process security transitions to execve(2) (see the description of /proc/[pid]/attr/exec, below).  Since Linux 2.6.11, SELinux lifted this restriction and began supporting "set" operations via writes to this node if authorized by policy, although use of this operation is only suitable for applications that are trusted to maintain any desired separation between the old and new security contexts.
```
```
Prior to Linux 2.6.28, SELinux did not allow threads within a multi-threaded process to set their security context via this node as it would yield an inconsistency among the security contexts of the threads sharing the same memory space.  Since Linux 2.6.28, SELinux lifted this restriction and began supporting "set" operations for threads within a multithreaded process if the new security context is bounded by the old security context, where the bounded relation is defined in policy and guarantees that the new security context has a subset of the permissions of the old security context.
```
Other security modules may choose to support "set" operations via writes to this node.

### /proc/[pid]/attr/exec (since Linux 2.6.0)
This file represents the attributes to assign to the process upon a subsequent execve(2).

```
In SELinux, this is needed to support role/domain transitions, and execve(2) is the preferred point to make such transitions because it offers better control over the initialization of the process in the new security label and the inheritance of state.  In SELinux, this attribute is reset on execve(2) so that the new program reverts to the default behavior for any execve(2) calls that it may make.  In SELinux, a process can set only its own /proc/[pid]/attr/exec attribute.
```

### /proc/[pid]/attr/fscreate (since Linux 2.6.0)
This file represents the attributes to assign to files created by subsequent calls to open(2), mkdir(2), symlink(2), and mknod(2)

```
SELinux employs this file to support creation of a file (using the aforementioned system calls) in a secure state, so that there is no risk of inappropriate access being obtained between the time of creation and the time that attributes are set.  In SELinux, this attribute is reset on execve(2), so that the new program reverts to the default behavior for any file creation calls it may make, but the attribute will persist across multiple file creation calls within a program unless it is explicitly reset.  In SELinux, a process can set only its own /proc/[pid]/attr/fscreate attribute.
```

### /proc/[pid]/attr/keycreate (since Linux 2.6.18)
If a process writes a security context into this file, all subsequently created keys (add_key(2)) will be labeled with this context.  For further information, see the kernel source file Documentation/security/keys/core.rst (or file Documentation/security/keys.txt on Linux between 3.0 and 4.13, or Documentation/keys.txt before Linux 3.0).

### /proc/[pid]/attr/prev (since Linux 2.6.0)
This file contains the security context of the process before the last execve(2); that is, the previous value of /proc/[pid]/attr/current.

### /proc/[pid]/attr/socketcreate (since Linux 2.6.18)
If a process writes a security context into this file, all subsequently created sockets will be labeled with this context.

### /proc/[pid]/autogroup (since Linux 2.6.38)
See sched(7).

### /proc/[pid]/auxv (since 2.6.0)
This contains the contents of the ELF interpreter information passed to the process at exec time.  The format is one unsigned long ID plus one unsigned long value for each entry. The last entry contains two zeros.  See also getauxval(3).
Permission to access this file is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS check; see ptrace(2).

### /proc/[pid]/cgroup (since Linux 2.6.24)
See cgroups(7).

### /proc/[pid]/clear_refs (since Linux 2.6.22)
This is a write-only file, writable only by owner of the process.

The following values may be written to the file:

* 1 (since Linux 2.6.22) - Reset the PG_Referenced and ACCESSED/YOUNG bits for all the pages associated with the process.  (Before kernel 2.6.32, writing any nonzero value to this file had this effect.)

* 2 (since Linux 2.6.32) - Reset the PG_Referenced and ACCESSED/YOUNG bits for all anonymous pages associated with the process.

* 3 (since Linux 2.6.32) - Reset the PG_Referenced and ACCESSED/YOUNG bits for all file-mapped pages associated with the process.

Clearing the PG_Referenced and ACCESSED/YOUNG bits provides a method to measure approximately how much memory a process is using.  One first inspects the values in the "Referenced" fields for the VMAs shown in /proc/[pid]/smaps to get an idea of the memory footprint of the process.  One then clears the PG_Referenced and ACCESSED/YOUNG bits and, after some measured time interval, once again inspects the values in the "Referenced" fields to get an idea of the change in memory footprint of the process during the measured interval.  If one is interested only in inspecting the selected mapping types, then the value 2 or 3 can be used instead of 1.

Further values can be written to affect different properties:

* 4 (since Linux 3.11) - Clear the soft-dirty bit for all the pages associated with the process.  This is used (in conjunction with /proc/[pid]/pagemap) by the check-point restore system to discover which pages of a process have been dirtied since the file /proc/[pid]/clear_refs was written to.

* 5 (since Linux 4.0) - Reset the peak resident set size ("high water mark") to the process's current resident set size value.

Writing any value to /proc/[pid]/clear_refs other than those listed above has no effect. The /proc/[pid]/clear_refs file is present only if the CONFIG_PROC_PAGE_MONITOR kernel configuration option is enabled.

### /proc/[pid]/cmdline
This read-only file holds the complete command line for the process, unless the process is a zombie.  In the latter case, there is nothing in this file: that is, a read on this file will return 0 characters.  The command-line arguments appear in this file as a set of strings separated by null bytes ('\0'), with a further null byte after the last string.

### /proc/[pid]/comm (since Linux 2.6.33)
This file exposes the process's comm value—that is, the command name associated with the process.  Different threads in the same process may have different comm values, accessible via /proc/[pid]/task/[tid]/comm.  A thread may modify its comm value, or that of any of other thread in the same thread group (see the discussion of CLONE_THREAD in clone(2)), by writing to the file /proc/self/task/[tid]/comm.  Strings longer than TASK_COMM_LEN (16) characters are silently truncated.
This file provides a superset of the prctl(2) PR_SET_NAME and PR_GET_NAME operations, and is employed by pthread_setname_np(3) when used to rename threads other than the caller.

### /proc/[pid]/coredump_filter (since Linux 2.6.23)
See core(5).

### /proc/[pid]/cpuset (since Linux 2.6.12)
See cpuset(7).

### /proc/[pid]/cwd
This is a symbolic link to the current working directory of the process.  To find out the current working directory of process 20, for instance, you can do this:
```
$ cd /proc/20/cwd; /bin/pwd
```
Note that the pwd command is often a shell built-in, and might not work properly.  In bash(1), you may use pwd -P.

In a multithreaded process, the contents of this symbolic link are not available if the main thread has already terminated (typically by calling pthread_exit(3)). Permission to dereference or read (readlink(2)) this symbolic link is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS check; see ptrace(2).

### /proc/[pid]/environ
This file contains the initial environment that was set when the currently executing program was started via execve(2). The entries are separated by null bytes ('\0'), and there may be a null byte at the end.  Thus, to print out the environment of process 1, you would do:
```
$ cat /proc/1/environ | tr '\000' '\n'
```

If, after an execve(2), the process modifies its environment (e.g., by calling functions such as putenv(3) or modifying the environ(7) variable directly), this file will not reflect those changes. Furthermore, a process may change the memory location that this file refers via prctl(2) operations such as PR_SET_MM_ENV_START.
Permission to access this file is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS check; see ptrace(2).

### /proc/[pid]/exe
Under Linux 2.2 and later, this file is a symbolic link containing the actual pathname of the executed command.  This symbolic link can be dereferenced normally; attempting to open it will open the executable.  You can even type /proc/[pid]/exe to run another copy of the same executable that is being run by process [pid].  If the pathname has been unlinked, the symbolic link will contain the string '(deleted)' appended to the original pathname.  In a multi‐ threaded process, the contents of this symbolic link are not available if the main thread has already terminated (typically by calling pthread_exit(3)).
Permission to dereference or read (readlink(2)) this symbolic link is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS check; see ptrace(2).

Under Linux 2.0 and earlier, /proc/[pid]/exe is a pointer to the binary which was executed, and appears as a symbolic link. A readlink(2) call on this file under Linux 2.0 returns a string in the format:
###### [device]:inode
For example, [0301]:1502 would be inode 1502 on device major 03 (IDE, MFM, etc. drives) minor 01 (first partition on the first drive).

find(1) with the -inum option can be used to locate the file.

