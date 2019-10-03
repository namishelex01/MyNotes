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


> In SELinux, this file is used to get the security context of a process.  Prior to Linux 2.6.11, this file could not be used to set the security context (a write was always denied), since SELinux limited process security transitions to execve(2) (see the description of /proc/[pid]/attr/exec, below).  Since Linux 2.6.11, SELinux lifted this restriction and began supporting "set" operations via writes to this node if authorized by policy, although use of this operation is only suitable for applications that are trusted to maintain any desired separation between the old and new security contexts.
> Prior to Linux 2.6.28, SELinux did not allow threads within a multi-threaded process to set their security context via this node as it would yield an inconsistency among the security contexts of the threads sharing the same memory space.  Since Linux 2.6.28, SELinux lifted this restriction and began supporting "set" operations for threads within a multithreaded process if the new security context is bounded by the old security context, where the bounded relation is defined in policy and guarantees that the new security context has a subset of the permissions of the old security context.

Other security modules may choose to support "set" operations via writes to this node.

### /proc/[pid]/attr/exec (since Linux 2.6.0)
This file represents the attributes to assign to the process upon a subsequent execve(2).

> In SELinux, this is needed to support role/domain transitions, and execve(2) is the preferred point to make such transitions because it offers better control over the initialization of the process in the new security label and the inheritance of state.  In SELinux, this attribute is reset on execve(2) so that the new program reverts to the default behavior for any execve(2) calls that it may make.  In SELinux, a process can set only its own /proc/[pid]/attr/exec attribute.


### /proc/[pid]/attr/fscreate (since Linux 2.6.0)
This file represents the attributes to assign to files created by subsequent calls to open(2), mkdir(2), symlink(2), and mknod(2)

> SELinux employs this file to support creation of a file (using the aforementioned system calls) in a secure state, so that there is no risk of inappropriate access being obtained between the time of creation and the time that attributes are set.  In SELinux, this attribute is reset on execve(2), so that the new program reverts to the default behavior for any file creation calls it may make, but the attribute will persist across multiple file creation calls within a program unless it is explicitly reset.  In SELinux, a process can set only its own /proc/[pid]/attr/fscreate attribute.


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


## /proc/[pid]/fd/
This is a subdirectory containing one entry for each file which the process has open, named by its file descriptor, and which is a symbolic link to the actual file.  Thus, 0 is stan‐dard input, 1 standard output, 2 standard error, and so on.

For file descriptors for pipes and sockets, the entries will be symbolic links whose content is the file type with the
inode.  A readlink(2) call on this file returns a string inthe format:

type:[inode]

For example, socket:[2248868] will be a socket and its inode is 2248868.  For sockets, that inode can be used to find more information in one of the files under /proc/net/.

For file descriptors that have no corresponding inode (e.g., file descriptors produced by bpf(2), epoll_create(2), eventfd(2), inotify_init(2), perf_event_open(2), signalfd(2), timerfd_create(2), and userfaultfd(2)), the entry will be a symbolic link with contents of the form

anon_inode:<file-type>

In many cases (but not all), the file-type is surrounded by square brackets. 
For example, an epoll file descriptor will have a symbolic link whose content is the string anon_inode:[eventpoll]. 
In a multithreaded process, the contents of this directory are not available if the main thread has already terminated (typi‐ cally by calling pthread_exit(3)).

Programs that take a filename as a command-line argument, but don't take input from standard input if no argument is sup‐ plied, and programs that write to a file named as a command- line argument, but don't send their output to standard output if no argument is supplied, can nevertheless be made to use
standard input or standard output by using ## /proc/[pid]/fd files as command-line arguments.  For example, assuming that -i is the flag designating an input file and -o is the flag designating an output file: 
$ foobar -i /proc/self/fd/0 -o /proc/self/fd/1 ...

and you have a working filter.

/proc/self/fd/N is approximately the same as /dev/fd/N in some UNIX and UNIX-like systems.  Most Linux MAKEDEV scripts sym‐ bolically link /dev/fd to /proc/self/fd, in fact.

Most systems provide symbolic links /dev/stdin, /dev/stdout, and /dev/stderr, which respectively link to the files 0, 1, and 2 in /proc/self/fd.  Thus the example command above could be written as: 
$ foobar -i /dev/stdin -o /dev/stdout ...

Permission to dereference or read (readlink(2)) the symbolic links in this directory is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS check; see ptrace(2).

Note that for file descriptors referring to inodes (pipes and sockets, see above), those inodes still have permission bits and ownership information distinct from those of the

## /proc/[pid]/fd entry, and that the owner may differ from the
user and group IDs of the process.  An unprivileged process may lack permissions to open them, as in this example: 
$ echo test | sudo -u nobody cat
test
$ echo test | sudo -u nobody cat /proc/self/fd/0
cat: /proc/self/fd/0: Permission denied

File descriptor 0 refers to the pipe created by the shell and owned by that shell's user, which is not nobody, so cat does not have permission to create a new file descriptor to read from that inode, even though it can still read from its exist‐ ing file descriptor 0.

## /proc/[pid]/fdinfo/ (since Linux 2.6.22)
This is a subdirectory containing one entry for each file which the process has open, named by its file descriptor.  The files in this directory are readable only by the owner of the process.  The contents of each file can be read to obtain information about the corresponding file descriptor.  The con‐
tent depends on the type of file referred to by the corre‐ sponding file descriptor. 
For regular files and directories, we see something like:

$ cat /proc/12015/fdinfo/4
pos:    1000
flags:  01002002
mnt_id: 21

The fields are as follows:

pos    This is a decimal number showing the file offset.

flags  This is an octal number that displays the file access mode and file status flags (see open(2)).  If the close-on-exec file descriptor flag is set, then flags will also include the value O_CLOEXEC. 

Before Linux 3.1, this field incorrectly displayed the setting of O_CLOEXEC at the time the file was opened, rather than the current setting of the close-on-exec flag. 
mnt_id This field, present since Linux 3.15, is the ID of the mount point containing this file.  See the description of ## /proc/[pid]/mountinfo.

For eventfd file descriptors (see eventfd(2)), we see (since Linux 3.8) the following fields: 
pos: 0
flags:    02
mnt_id:   10
eventfd-count:               40

eventfd-count is the current value of the eventfd counter, in hexadecimal.

For epoll file descriptors (see epoll(7)), we see (since Linux 3.8) the following fields: 
pos: 0
flags:    02
mnt_id:   10
tfd:        9 events:       19 data: 74253d2500000009
tfd:        7 events:       19 data: 74253d2500000007

Each of the lines beginning tfd describes one of the file descriptors being monitored via the epoll file descriptor (see epoll_ctl(2) for some details).  The tfd field is the number of the file descriptor.  The events field is a hexadecimal mask of the events being monitored for this file descriptor.
The data field is the data value associated with this file descriptor. 
For signalfd file descriptors (see signalfd(2)), we see (since Linux 3.8) the following fields: 
pos: 0
flags:    02
mnt_id:   10
sigmask:  0000000000000006

sigmask is the hexadecimal mask of signals that are accepted via this signalfd file descriptor.  (In this example, bits 2 and 3 are set, corresponding to the signals SIGINT and SIGQUIT; see signal(7).) 
For inotify file descriptors (see inotify(7)), we see (since Linux 3.8) the following fields: 
pos: 0
flags:    00
mnt_id:   11
inotify wd:2 ino:7ef82a sdev:800001 mask:800afff ignored_mask:0 fhandle-bytes:8 fhandle-type:1 f_handle:2af87e00220ffd73
inotify wd:1 ino:192627 sdev:800001 mask:800afff ignored_mask:0 fhandle-bytes:8 fhandle-type:1 f_handle:27261900802dfd73

Each of the lines beginning with "inotify" displays informa‐ tion about one file or directory that is being monitored.  The fields in this line are as follows:

wd     A watch descriptor number (in decimal).

ino    The inode number of the target file (in hexadecimal).

sdev   The ID of the device where the target file resides (in
hexadecimal).

mask   The mask of events being monitored for the target file
(in hexadecimal).

If the kernel was built with exportfs support, the path to the target file is exposed as a file handle, via three hexadecimal fields: fhandle-bytes, fhandle-type, and f_handle.

For fanotify file descriptors (see fanotify(7)), we see (since Linux 3.8) the following fields: 
pos: 0
flags:    02
mnt_id:   11
fanotify flags:0 event-flags:88002
fanotify ino:19264f sdev:800001 mflags:0 mask:1 ignored_mask:0 fhandle-bytes:8 fhandle-type:1 f_handle:4f261900a82dfd73

The fourth line displays information defined when the fanotify group was created via fanotify_init(2): 
flags  The flags argument given to fanotify_init(2) (expressed in hexadecimal). 
event-flags
The event_f_flags argument given to fanotify_init(2) (expressed in hexadecimal). 
Each additional line shown in the file contains information about one of the marks in the fanotify group.  Most of these fields are as for inotify, except:

mflags The flags associated with the mark (expressed in hexadecimal).

mask   The events mask for this mark (expressed in hexadecimal).

ignored_mask
The mask of events that are ignored for this mark (expressed in hexadecimal).

For details on these fields, see fanotify_mark(2).

For timerfd file descriptors (see timerfd(2)), we see (since Linux 3.17) the following fields:

pos:    0
flags:  02004002
mnt_id: 13
clockid: 0
ticks: 0
settime flags: 03
it_value: (7695568592, 640020877)
it_interval: (0, 0)

clockid
This is the numeric value of the clock ID (correspond‐ ing to one of the CLOCK_* constants defined via <time.h>) that is used to mark the progress of the timer (in this example, 0 is CLOCK_REALTIME).

ticks  This is the number of timer expirations that have occurred, (i.e., the value that read(2) on it would return).

settime flags
This field lists the flags with which the timerfd was last armed (see timerfd_settime(2)), in octal (in this example, both TFD_TIMER_ABSTIME and TFD_TIMER_CANCEL_ON_SET are set).

it_value
This field contains the amount of time until the timer will next expire, expressed in seconds and nanoseconds. This is always expressed as a relative value, regard‐ less of whether the timer was created using the TFD_TIMER_ABSTIME flag.

it_interval
This field contains the interval of the timer, in sec‐ onds and nanoseconds.  (The it_value and it_interval fields contain the values that timerfd_gettime(2) on this file descriptor would return.) 

## /proc/[pid]/gid_map (since Linux 3.5)
See user_namespaces(7).

## /proc/[pid]/io (since kernel 2.6.20)
This file contains I/O statistics for the process, for example:

```
# cat /proc/3828/io
rchar: 323934931
wchar: 323929600
syscr: 632687
syscw: 632675
read_bytes: 0
write_bytes: 323932160
cancelled_write_bytes: 0
```
The fields are as follows:

rchar: characters read
The number of bytes which this task has caused to be read from storage.  This is simply the sum of bytes which this process passed to read(2) and similar system calls.  It includes things such as terminal I/O and is unaffected by whether or not actual physical disk I/O
was required (the read might have been satisfied from pagecache). 

wchar: characters written
The number of bytes which this task has caused, or shall cause to be written to disk.  Similar caveats apply here as with rchar.

syscr: read syscalls
Attempt to count the number of read I/O operations—that is, system calls such as read(2) and pread(2). 

syscw: write syscalls
Attempt to count the number of write I/O operations— that is, system calls such as write(2) and pwrite(2). 

read_bytes: bytes read
Attempt to count the number of bytes which this process really did cause to be fetched from the storage layer. This is accurate for block-backed filesystems.

write_bytes: bytes written
Attempt to count the number of bytes which this process caused to be sent to the storage layer. 

cancelled_write_bytes:
The big inaccuracy here is truncate.  If a process writes 1MB to a file and then deletes the file, it will in fact perform no writeout.  But it will have been accounted as having caused 1MB of write.  In other words: this field represents the number of bytes which
this process caused to not happen, by truncating page‐ cache.  A task can cause "negative" I/O too.  If this task truncates some dirty pagecache, some I/O which another task has been accounted for (in its write_bytes) will not be happening.

Note: In the current implementation, things are a bit racy on 32-bit systems: if process A reads process B's ## /proc/[pid]/io while process B is updating one of these 64-bit counters, process A could see an intermediate result. 

Permission to access this file is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS check; see ptrace(2).

## /proc/[pid]/limits (since Linux 2.6.24)
This file displays the soft limit, hard limit, and units of
measurement for each of the process's resource limits (see
getrlimit(2)).  Up to and including Linux 2.6.35, this file is
protected to allow reading only by the real UID of the
process.  Since Linux 2.6.36, this file is readable by all
users on the system.

## /proc/[pid]/map_files/ (since kernel 3.3)
This subdirectory contains entries corresponding to memory- mapped files (see mmap(2)).  Entries are named by memory region start and end address pair (expressed as hexadecimal numbers), and are symbolic links to the mapped files them‐ selves.  Here is an example, with the output wrapped and reformatted to fit on an 80-column display:

```
# ls -l /proc/self/map_files/
lr--------. 1 root root 64 Apr 16 21:31
      3252e00000-3252e20000 -> /usr/lib64/ld-2.15.so
...
```
Although these entries are present for memory regions that were mapped with the MAP_FILE flag, the way anonymous shared memory (regions created with the MAP_ANON | MAP_SHARED flags) is implemented in Linux means that such regions also appear on this directory.  Here is an example where the target file is the deleted /dev/zero one:
```
lrw-------. 1 root root 64 Apr 16 21:33
      7fc075d2f000-7fc075e6f000 -> /dev/zero (deleted)
```
This directory appears only if the CONFIG_CHECKPOINT_RESTORE kernel configuration option is enabled.  Privilege (CAP_SYS_ADMIN) is required to view the contents of this directory. 

## /proc/[pid]/maps
A file containing the currently mapped memory regions and their access permissions.  See mmap(2) for some further infor‐ mation about memory mappings.

Permission to access this file is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS check; see ptrace(2). 
The format of the file is:
```
address           perms offset  dev   inode       pathname
00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon
00651000-00652000 r--p 00051000 08:02 173521      /usr/bin/dbus-daemon
00652000-00655000 rw-p 00052000 08:02 173521      /usr/bin/dbus-daemon
00e03000-00e24000 rw-p 00000000 00:00 0           [heap]
00e24000-011f7000 rw-p 00000000 00:00 0           [heap]
...
35b1800000-35b1820000 r-xp 00000000 08:02 135522  /usr/lib64/ld-2.15.so
35b1a1f000-35b1a20000 r--p 0001f000 08:02 135522  /usr/lib64/ld-2.15.so
35b1a20000-35b1a21000 rw-p 00020000 08:02 135522  /usr/lib64/ld-2.15.so
35b1a21000-35b1a22000 rw-p 00000000 00:00 0
35b1c00000-35b1dac000 r-xp 00000000 08:02 135870  /usr/lib64/libc-2.15.so
35b1dac000-35b1fac000 ---p 001ac000 08:02 135870  /usr/lib64/libc-2.15.so
35b1fac000-35b1fb0000 r--p 001ac000 08:02 135870  /usr/lib64/libc-2.15.so
35b1fb0000-35b1fb2000 rw-p 001b0000 08:02 135870  /usr/lib64/libc-2.15.so
...
f2c6ff8c000-7f2c7078c000 rw-p 00000000 00:00 0    [stack:986]
...
7fffb2c0d000-7fffb2c2e000 rw-p 00000000 00:00 0   [stack]
7fffb2d48000-7fffb2d49000 r-xp 00000000 00:00 0   [vdso]
```
The address field is the address space in the process that the mapping occupies.  The perms field is a set of permissions: 
r = read
w = write
x = execute
s = shared
p = private (copy on write)

The offset field is the offset into the file/whatever; dev is the device (major:minor); inode is the inode on that device. 0 indicates that no inode is associated with the memory region, as would be the case with BSS (uninitialized data). 
The pathname field will usually be the file that is backing the mapping.  For ELF files, you can easily coordinate with the offset field by looking at the Offset field in the ELF program headers (readelf -l). 
There are additional helpful pseudo-paths:

[stack]
  The initial process's (also known as the main
  thread's) stack.

[stack:<tid>] (from Linux 3.4 to 4.4)
  A thread's stack (where the <tid> is a thread ID).
  It corresponds to the ## /proc/[pid]/task/[tid]/
  path.  This field was removed in Linux 4.5, since
  providing this information for a process with
  large numbers of threads is expensive.

[vdso] The virtual dynamically linked shared object.  See
  vdso(7).

[heap] The process's heap.

If the pathname field is blank, this is an anonymous mapping as obtained via mmap(2).  There is no easy way to coordinate this back to a process's source, short of running it through gdb(1), strace(1), or similar pathname is shown unescaped except for newline characters, which are replaced with an octal escape sequence.  As a result, it is not possible to determine whether the original pathname contained a newline character or the literal \e012 character sequence.  If the mapping is file-backed and the file has been deleted, the string " (deleted)" is appended to the pathname.  Note that this is ambiguous too.

Under Linux 2.0, there is no field giving pathname.

## /proc/[pid]/mem
This file can be used to access the pages of a process's mem‐ ory through open(2), read(2), and lseek(2). 
Permission to access this file is governed by a ptrace access mode PTRACE_MODE_ATTACH_FSCREDS check; see ptrace(2). 

## /proc/[pid]/mountinfo (since Linux 2.6.26)
This file contains information about mount points in the process's mount namespace (see mount_namespaces(7)).  It sup‐ plies various information (e.g., propagation state, root of mount for bind mounts, identifier for each mount and its par‐ ent) that is missing from the (older) ## /proc/[pid]/mounts file,
and fixes various other problems with that file (e.g., nonex‐ tensibility, failure to distinguish per-mount versus per- superblock options).

The file contains lines of the form:

36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
(1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)

The numbers in parentheses are labels for the descriptions
below:

(1)  mount ID: a unique ID for the mount (may be reused after
umount(2)).

(2)  parent ID: the ID of the parent mount (or of self for the
root of this mount namespace's mount tree).

If a new mount is stacked on  of a previous existing mount (so that it hides the existing mount) at pathname P, then the parent of the new mount is the previous mount at that location.  Thus, when looking at all the mounts stacked at a particular location, the -most mount is the one that is not the parent of any other mount at the same location.  (Note, however, that this -most mount will be accessible only if the longest path subprefix of P that is a mount point is not itself hidden by a stacked mount.)

If the parent mount point lies outside the process's root directory (see chroot(2)), the ID shown here won't have a corresponding record in mountinfo whose mount ID (field 1) matches this parent mount ID (because mount points that lie outside the process's root directory are not shown in mountinfo).  As a special case of this point, the process's root mount point may have a parent mount (for the initramfs filesystem) that lies outside the process's root directory, and an entry for that mount point will not appear in mountinfo.

(3)  major:minor: the value of st_dev for files on this filesystem (see stat(2)).

(4)  root: the pathname of the directory in the filesystem which forms the root of this mount.

(5)  mount point: the pathname of the mount point relative to the process's root directory.

(6)  mount options: per-mount options (see mount(2)).

(7)  optional fields: zero or more fields of the form "tag[:value]"; see below.

(8)  separator: the end of the optional fields is marked by a single hyphen.

(9)  filesystem type: the filesystem type in the form "type[.subtype]".

(10) mount source: filesystem-specific information or "none".

(11) super options: per-superblock options (see mount(2)).

Currently, the possible optional fields are shared, master, propagate_from, and unbindable.  See mount_namespaces(7) for a description of these fields.  Parsers should ignore all unrecognized optional fields. 
For more information on mount propagation see: Documentation/filesystems/sharedsubtree.txt in the Linux kernel source tree.

## /proc/[pid]/mounts (since Linux 2.4.19)
This file lists all the filesystems currently mounted in the process's mount namespace (see mount_namespaces(7)).  The for‐ mat of this file is documented in fstab(5).

Since kernel version 2.6.15, this file is pollable: after opening the file for reading, a change in this file (i.e., a filesystem mount or unmount) causes select(2) to mark the file descriptor as having an exceptional condition, and poll(2) and epoll_wait(2) mark the file as having a priority event (POLLPRI).  (Before Linux 2.6.30, a change in this file was indi‐ cated by the file descriptor being marked as readable for select(2), and being marked as having an error condition for poll(2) and epoll_wait(2).) 

## /proc/[pid]/mountstats (since Linux 2.6.17)
This file exports information (statistics, configuration information) about the mount points in the process's mount namespace (see mount_namespaces(7)).  Lines in this file have the form: 
device /dev/sda7 mounted on /home with fstype ext3 [statistics]
(       1      )            ( 2 )             (3 ) (4)

The fields in each line are:

(1)  The name of the mounted device (or "nodevice" if there is
no corresponding device).

(2)  The mount point within the filesystem tree.

(3)  The filesystem type.

(4)  Optional statistics and configuration information.  Cur‐ rently (as at Linux 2.6.26), only NFS filesystems export information via this field.

This file is readable only by the owner of the process.

## /proc/[pid]/net (since Linux 2.6.25)
See the description of /proc/net.

## /proc/[pid]/ns/ (since Linux 3.0)
This is a subdirectory containing one entry for each namespace that supports being manipulated by setns(2).  For more infor‐ mation, see namespaces(7).

## /proc/[pid]/numa_maps (since Linux 2.6.14)
See numa(7).

## /proc/[pid]/oom_adj (since Linux 2.6.11)
This file can be used to adjust the score used to select which process should be killed in an out-of-memory (OOM) situation. The kernel uses this value for a bit-shift operation of the process's oom_score value: valid values are in the range -16 to +15, plus the special value -17, which disables OOM-killing altogether for this process.  A positive score increases the likelihood of this process being killed by the OOM-killer; a negative score decreases the likelihood.

The default value for this file is 0; a new process inherits its parent's oom_adj setting.  A process must be privileged (CAP_SYS_RESOURCE) to update this file.

Since Linux 2.6.36, use of this file is deprecated in favor of /proc/[pid]/oom_score_adj.

## /proc/[pid]/oom_score (since Linux 2.6.11)
This file displays the current score that the kernel gives to this process for the purpose of selecting a process for the OOM-killer.  A higher score means that the process is more likely to be selected by the OOM-killer.  The basis for this score is the amount of memory used by the process, with increases (+) or decreases (-) for factors including:

* whether the process is privileged (-).

Before kernel 2.6.36 the following factors were also used in the calculation of oom_score:

* whether the process creates a lot of children using fork(2) (+);

* whether the process has been running a long time, or has used a lot of CPU time (-);

* whether the process has a low nice value (i.e., > 0) (+); and

* whether the process is making direct hardware access (-).

The oom_score also reflects the adjustment specified by the oom_score_adj or oom_adj setting for the process.

## /proc/[pid]/oom_score_adj (since Linux 2.6.36)
This file can be used to adjust the badness heuristic used to select which process gets killed in out-of-memory conditions.

The badness heuristic assigns a value to each candidate task ranging from 0 (never kill) to 1000 (always kill) to determine which process is targeted.  The units are roughly a proportion along that range of allowed memory the process may allocate from, based on an estimation of its current memory and swap use.  For example, if a task is using all allowed memory, its badness score will be 1000.  If it is using half of its allowed memory, its score will be 500.

There is an additional factor included in the badness score: root processes are given 3% extra memory over other tasks.

The amount of "allowed" memory depends on the context in which the OOM-killer was called.  If it is due to the memory assigned to the allocating task's cpuset being exhausted, the allowed memory represents the set of mems assigned to that cpuset (see cpuset(7)).  If it is due to a mempolicy's node(s) being exhausted, the allowed memory represents the set of mem‐ policy nodes.  If it is due to a memory limit (or swap limit) being reached, the allowed memory is that configured limit. Finally, if it is due to the entire system being out of mem‐ ory, the allowed memory represents all allocatable resources.

The value of oom_score_adj is added to the badness score before it is used to determine which task to kill.  Acceptable values range from -1000 (OOM_SCORE_ADJ_MIN) to +1000 (OOM_SCORE_ADJ_MAX).  This allows user space to control the preference for OOM-killing, ranging from always preferring a certain task or completely disabling it from OOM killing.  The lowest possible value, -1000, is equivalent to disabling OOM- killing entirely for that task, since it will always report a badness score of 0. 
Consequently, it is very simple for user space to define the amount of memory to consider for each task.  Setting an oom_score_adj value of +500, for example, is roughly equiva‐ lent to allowing the remainder of tasks sharing the same sys‐ tem, cpuset, mempolicy, or memory controller resources to use at least 50% more memory.  A value of -500, on the other hand, would be roughly equivalent to discounting 50% of the task's allowed memory from being considered as scoring against the task. 
For backward compatibility with previous kernels, /proc/[pid]/oom_adj can still be used to tune the badness score.  Its value is scaled linearly with oom_score_adj.

Writing to ## /proc/[pid]/oom_score_adj or ## /proc/[pid]/oom_adj will change the other with its scaled value.

The choom(1) program provides a command-line interface for adjusting the oom_score_adj value of a running process or a newly executed command.

## /proc/[pid]/pagemap (since Linux 2.6.25)
This file shows the mapping of each of the process's virtual pages into physical page frames or swap area.  It contains one 64-bit value for each virtual page, with the bits set as fol‐ lows: 
63     If set, the page is present in RAM.

62     If set, the page is in swap space

61 (since Linux 3.5)
  The page is a file-mapped page or a shared anonymous page.

60–57 (since Linux 3.11)
  Zero

56 (since Linux 4.2)
  The page is exclusively mapped.

55 (since Linux 3.11)
  PTE is soft-dirty (see the kernel source file Documentation/admin-guide/mm/soft-dirty.rst).

54–0   If the page is present in RAM (bit 63), then these bits provide the page frame number, which can be used to index /proc/kpageflags and /proc/kpagecount.  If the page is present in swap (bit 62), then bits 4–0 give the swap type, and bits 54–5 encode the swap offset.

Before Linux 3.11, bits 60–55 were used to encode the base-2 log of the page size.

To employ /proc/[pid]/pagemap efficiently, use /proc/[pid]/maps to determine which areas of memory are actually mapped and seek to skip over unmapped regions.

The /proc/[pid]/pagemap file is present only if the CONFIG_PROC_PAGE_MONITOR kernel configuration option is enabled.

Permission to access this file is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS check; see ptrace(2).

## /proc/[pid]/personality (since Linux 2.6.28)
This read-only file exposes the process's execution domain, as set by personality(2).  The value is displayed in hexadecimal notation.

Permission to access this file is governed by a ptrace access mode PTRACE_MODE_ATTACH_FSCREDS check; see ptrace(2). 

## /proc/[pid]/root
UNIX and Linux support the idea of a per-process root of the filesystem, set by the chroot(2) system call.  This file is a symbolic link that points to the process's root directory, and behaves in the same way as exe, and fd/*. Note however that this file is not merely a symbolic link.  It provides the same view of the filesystem (including namespaces and the set of per-process mounts) as the process itself.  An example illustrates this point.  In one terminal, we start a shell in new user and mount namespaces, and in that shell we create some new mount points:
```
$ PS1='sh1# ' unshare -Urnm
sh1# mount -t tmpfs tmpfs /etc  # Mount empty tmpfs at /etc
sh1# mount --bind /usr /dev     # Mount /usr at /dev
sh1# echo $$
27123
```
In a second terminal window, in the initial mount namespace, we look at the contents of the corresponding mounts in the initial and new namespaces:
```
$ PS1='sh2# ' sudo sh
sh2# ls /etc | wc -l                  # In initial NS
309
sh2# ls /proc/27123/root/etc | wc -l  # /etc in other NS
0                                     # The empty tmpfs dir
sh2# ls /dev | wc -l                  # In initial NS
205
sh2# ls /proc/27123/root/dev | wc -l  # /dev in other NS
11                                    # Actually bind
                                # mounted to /usr
sh2# ls /usr | wc -l                  # /usr in initial NS
11
```
In a multithreaded process, the contents of the /proc/[pid]/root symbolic link are not available if the main thread has already terminated (typically by calling pthread_exit(3)).

Permission to dereference or read (readlink(2)) this symbolic link is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS check; see ptrace(2).

## /proc/[pid]/seccomp (Linux 2.6.12 to 2.6.22)
This file can be used to read and change the process's secure computing (seccomp) mode setting.  It contains the value 0 if the process is not in seccomp mode, and 1 if the process is in strict seccomp mode (see seccomp(2)).  Writing 1 to this file places the process irreversibly in strict seccomp mode.  (Fur‐
ther attempts to write to the file fail with the EPERM error.)

In Linux 2.6.23, this file went away, to be replaced by the prctl(2) PR_GET_SECCOMP and PR_SET_SECCOMP operations (and later by seccomp(2) and the Seccomp field in ## /proc/[pid]/status). 

## /proc/[pid]/setgroups (since Linux 3.19)
See user_namespaces(7).

## /proc/[pid]/smaps (since Linux 2.6.14)
This file shows memory consumption for each of the process's mappings.  (The pmap(1) command displays similar information, in a form that may be easier for parsing.)  For each mapping there is a series of lines such as the following: 

00400000-0048a000 r-xp 00000000 fd:03 960637       /bin/bash
Size:                552 kB
Rss:                 460 kB
Pss:                 100 kB
Shared_Clean:        452 kB
Shared_Dirty:          0 kB
Private_Clean:         8 kB
Private_Dirty:         0 kB
Referenced:          460 kB
Anonymous:             0 kB
AnonHugePages:         0 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
Swap:                  0 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Locked:                0 kB
ProtectionKey:         0
VmFlags: rd ex mr mw me dw

The first of these lines shows the same information as is dis‐ played for the mapping in ## /proc/[pid]/maps.  The following lines show the size of the mapping, the amount of the mapping that is currently resident in RAM ("Rss"), the process's pro‐ portional share of this mapping ("Pss"), the number of clean and dirty shared pages in the mapping, and the number of clean and dirty private pages in the mapping.  "Referenced" indi‐ cates the amount of memory currently marked as referenced or accessed.  "Anonymous" shows the amount of memory that does not belong to any file.  "Swap" shows how much would-be-anonymous memory is also used, but out on swap.

The "KernelPageSize" line (available since Linux 2.6.29) is the page size used by the kernel to back the virtual memory area.  This matches the size used by the MMU in the majority of cases.  However, one counter-example occurs on PPC64 ker‐ nels whereby a kernel using 64kB as a base page size may still use 4kB pages for the MMU on older processors.  To distinguish the two attributes, the "MMUPageSize" line (also available since Linux 2.6.29) reports the page size used by the MMU.

The "Locked" indicates whether the mapping is locked in memory or not.

The "ProtectionKey" line (available since Linux 4.9, on x86 only) contains the memory protection key (see pkeys(7)) associated with the virtual memory area.  This entry is present only if the kernel was built with the CONFIG_X86_INTEL_MEM‐ ORY_PROTECTION_KEYS configuration option.

The "VmFlags" line (available since Linux 3.8) represents the kernel flags associated with the virtual memory area, encoded using the following two-letter codes:

rd  - readable
wr  - writable
ex  - executable
sh  - shared
mr  - may read
mw  - may write
me  - may execute
ms  - may share
gd  - stack segment grows down
pf  - pure PFN range
dw  - disabled write to the mapped file
lo  - pages are locked in memory
io  - memory mapped I/O area
sr  - sequential read advise provided
rr  - random read advise provided
dc  - do not copy area on fork
de  - do not expand area on remapping
ac  - area is accountable
nr  - swap space is not reserved for the area
ht  - area uses huge tlb pages
nl  - non-linear mapping
ar  - architecture specific flag
dd  - do not include area into core dump
sd  - soft-dirty flag
mm  - mixed map area
hg  - huge page advise flag
nh  - no-huge page advise flag
mg  - mergeable advise flag

"ProtectionKey" field contains the memory protection key (see pkeys(5)) associated with the virtual memory area.  Present only if the kernel was built with the CONFIG_X86_INTEL_MEM‐ ORY_PROTECTION_KEYS configuration option. (since Linux 4.6) 
The /proc/[pid]/smaps file is present only if the CONFIG_PROC_PAGE_MONITOR kernel configuration option is enabled.

## /proc/[pid]/stack (since Linux 2.6.29)
This file provides a symbolic trace of the function calls in this process's kernel stack.  This file is provided only if the kernel was built with the CONFIG_STACKTRACE configuration option.

Permission to access this file is governed by a ptrace access mode PTRACE_MODE_ATTACH_FSCREDS check; see ptrace(2).

## /proc/[pid]/stat
Status information about the process.  This is used by ps(1). It is defined in the kernel source file fs/proc/array.c.

The fields, in order, with their proper scanf(3) format specifiers, are listed below.  Whether or not certain of these fields display valid information is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS | PTRACE_MODE_NOAUDIT check (refer to ptrace(2)).  If the check denies access, then the field value is displayed as 0.  The affected fields are indicated with the marking [PT].

(1) pid  %d
The process ID.

(2) comm  %s
The filename of the executable, in parentheses. This is visible whether or not the executable is swapped out.

(3) state  %c
One of the following characters, indicating process state:

R  Running

S  Sleeping in an interruptible wait

D  Waiting in uninterruptible disk sleep

Z  Zombie

T  Sped (on a signal) or (before Linux 2.6.33)
   trace sped

t  Tracing s (Linux 2.6.33 onward)

W  Paging (only before Linux 2.6.0)

X  Dead (from Linux 2.6.0 onward)

x  Dead (Linux 2.6.33 to 3.13 only)

K  Wakekill (Linux 2.6.33 to 3.13 only)

W  Waking (Linux 2.6.33 to 3.13 only)

P  Parked (Linux 3.9 to 3.13 only)

(4) ppid  %d
The PID of the parent of this process.

(5) pgrp  %d
The process group ID of the process.

(6) session  %d
The session ID of the process.

(7) tty_nr  %d
The controlling terminal of the process.  (The minor device number is contained in the combination of bits 31 to 20 and 7 to 0; the major device number is in bits 15 to 8.)

(8) tpgid  %d
The ID of the foreground process group of the controlling terminal of the process.

(9) flags  %u
The kernel flags word of the process.  For bit meanings, see the PF_* defines in the Linux kernel source file include/linux/sched.h.  Details depend on the kernel version.

The format for this field was %lu before Linux 2.6.

(10) minflt  %lu
The number of minor faults the process has made which have not required loading a memory page from disk.

(11) cminflt  %lu
The number of minor faults that the process's waited-for children have made.

(12) majflt  %lu
The number of major faults the process has made which have required loading a memory page from disk.

(13) cmajflt  %lu
The number of major faults that the process's waited-for children have made.

(14) utime  %lu
Amount of time that this process has been scheduled in user mode, measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).  This includes guest time, guest_time (time spent running a virtual CPU, see below), so that applications that are not aware of the guest time field do not lose that time from their calculations.

(15) stime  %lu
Amount of time that this process has been scheduled in kernel mode, measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).

(16) cutime  %ld
Amount of time that this process's waited-for children have been scheduled in user mode, measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).  (See also times(2).)  This includes guest time, cguest_time (time spent running a virtual CPU, see below).

(17) cstime  %ld
Amount of time that this process's waited-for chil‐ dren have been scheduled in kernel mode, measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).

(18) priority  %ld
(Explanation for Linux 2.6) For processes running a real-time scheduling policy (policy below; see sched_setscheduler(2)), this is the negated scheduling priority, minus one; that is, a number in the range -2 to -100, corresponding to real-time priorities 1 to 99.  For processes running under a non- real-time scheduling policy, this is the raw nice value (setpriority(2)) as represented in the kernel. The kernel stores nice values as numbers in the range 0 (high) to 39 (low), corresponding to the user-visible nice range of -20 to 19. Before Linux 2.6, this was a scaled value based on the scheduler weighting given to this process.

(19) nice  %ld
The nice value (see setpriority(2)), a value in the range 19 (low priority) to -20 (high priority).

(20) num_threads  %ld
Number of threads in this process (since Linux 2.6). Before kernel 2.6, this field was hard coded to 0 as a placeholder for an earlier removed field.

(21) itrealvalue  %ld
The time in jiffies before the next SIGALRM is sent to the process due to an interval timer.  Since kernel 2.6.17, this field is no longer maintained, and is hard coded as 0.

(22) starttime  %llu
The time the process started after system boot. In kernels before Linux 2.6, this value was expressed in jiffies.  Since Linux 2.6, the value is expressed in clock ticks (divide by sysconf(_SC_CLK_TCK)).

The format for this field was %lu before Linux 2.6.

(23) vsize  %lu
Virtual memory size in bytes.

(24) rss  %ld
Resident Set Size: number of pages the process has in real memory.  This is just the pages which count toward text, data, or stack space.  This does not include pages which have not been demand-loaded in, or which are swapped out. 

(25) rsslim  %lu
Current soft limit in bytes on the rss of the process; see the description of RLIMIT_RSS in getrlimit(2).

(26) startcode  %lu  [PT]
The address above which program text can run.

(27) endcode  %lu  [PT]
The address below which program text can run.

(28) startstack  %lu  [PT]
The address of the start (i.e., bottom) of the stack.

(29) kstkesp  %lu  [PT]
The current value of ESP (stack pointer), as found in the kernel stack page for the process.

(30) kstkeip  %lu  [PT]
The current EIP (instruction pointer).

(31) signal  %lu
The bitmap of pending signals, displayed as a decimal number.  Obsolete, because it does not provide information on real-time signals; use /proc/[pid]/status instead.

(32) blocked  %lu
The bitmap of blocked signals, displayed as a decimal number.  Obsolete, because it does not provide information on real-time signals; use /proc/[pid]/status instead.

(33) sigignore  %lu
The bitmap of ignored signals, displayed as a decimal number.  Obsolete, because it does not provide information on real-time signals; use /proc/[pid]/status instead.

(34) sigcatch  %lu
The bitmap of caught signals, displayed as a decimal number.  Obsolete, because it does not provide information on real-time signals; use /proc/[pid]/status instead.

(35) wchan  %lu  [PT]
This is the "channel" in which the process is waiting.  It is the address of a location in the kernel where the process is sleeping.  The corresponding symbolic name can be found in ## /proc/[pid]/wchan.

(36) nswap  %lu
Number of pages swapped (not maintained).

(37) cnswap  %lu
Cumulative nswap for child processes (not maintained).

(38) exit_signal  %d  (since Linux 2.1.22)
Signal to be sent to parent when we die.

(39) processor  %d  (since Linux 2.2.8)
CPU number last executed on.

(40) rt_priority  %u  (since Linux 2.5.19)
Real-time scheduling priority, a number in the range 1 to 99 for processes scheduled under a real-time policy, or 0, for non-real-time processes (see sched_setscheduler(2)).

(41) policy  %u  (since Linux 2.5.19)
Scheduling policy (see sched_setscheduler(2)). Decode using the SCHED_* constants in linux/sched.h.

The format for this field was %lu before Linux 2.6.22.

(42) delayacct_blkio_ticks  %llu  (since Linux 2.6.18)
Aggregated block I/O delays, measured in clock ticks (centiseconds).

(43) guest_time  %lu  (since Linux 2.6.24)
Guest time of the process (time spent running a virtual CPU for a guest operating system), measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).

(44) cguest_time  %ld  (since Linux 2.6.24)
Guest time of the process's children, measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).

(45) start_data  %lu  (since Linux 3.3)  [PT]
Address above which program initialized and uninitialized (BSS) data are placed.

(46) end_data  %lu  (since Linux 3.3)  [PT]
Address below which program initialized and uninitialized (BSS) data are placed.

(47) start_brk  %lu  (since Linux 3.3)  [PT]
Address above which program heap can be expanded with brk(2).

(48) arg_start  %lu  (since Linux 3.5)  [PT]
Address above which program command-line arguments (argv) are placed.

(49) arg_end  %lu  (since Linux 3.5)  [PT]
Address below program command-line arguments (argv) are placed.

(50) env_start  %lu  (since Linux 3.5)  [PT]
Address above which program environment is placed.

(51) env_end  %lu  (since Linux 3.5)  [PT]
Address below which program environment is placed.

(52) exit_code  %d  (since Linux 3.5)  [PT]
The thread's exit status in the form reported by waitpid(2).

## /proc/[pid]/statm
Provides information about memory usage, measured in pages.
The columns are:

size       (1) total program size
     (same as VmSize in ## /proc/[pid]/status)
resident   (2) resident set size
     (same as VmRSS in ## /proc/[pid]/status)
shared     (3) number of resident shared pages (i.e., backed by a file)
     (same as RssFile+RssShmem in ## /proc/[pid]/status)
text       (4) text (code)
lib        (5) library (unused since Linux 2.6; always 0)
data       (6) data + stack
dt         (7) dirty pages (unused since Linux 2.6; always 0)

## /proc/[pid]/status
Provides much of the information in ## /proc/[pid]/stat and /proc/[pid]/statm in a format that's easier for humans to parse.  Here's an example:
```
$ cat /proc/$$/status
Name:   bash
Umask:  0022
State:  S (sleeping)
Tgid:   17248
Ngid:   0
Pid:    17248
PPid:   17200
TracerPid:      0
Uid:    1000    1000    1000    1000
Gid:    100     100     100     100
FDSize: 256
Groups: 16 33 100
NStgid: 17248
NSpid:  17248
NSpgid: 17248
NSsid:  17200
VmPeak:     131168 kB
VmSize:     131168 kB
VmLck:           0 kB
VmPin:           0 kB
VmHWM:       13484 kB
VmRSS:       13484 kB
RssAnon:     10264 kB
RssFile:      3220 kB
RssShmem:        0 kB
VmData:      10332 kB
VmStk:         136 kB
VmExe:         992 kB
VmLib:        2104 kB
VmPTE:          76 kB
VmPMD:          12 kB
VmSwap:          0 kB
HugetlbPages:          0 kB        # 4.4
CoreDumping:   0                       # 4.15
Threads:        1
SigQ:   0/3067
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000010000
SigIgn: 0000000000384004
SigCgt: 000000004b813efb
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: ffffffffffffffff
CapAmb:   0000000000000000
NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       vulnerable
Cpus_allowed:   00000001
Cpus_allowed_list:      0
Mems_allowed:   1
Mems_allowed_list:      0
voluntary_ctxt_switches:        150
nonvoluntary_ctxt_switches:     545
```
The fields are as follows:

* Name: Command run by this process.

* Umask: Process umask, expressed in octal with a leading
zero; see umask(2).  (Since Linux 4.7.)

* State: Current state of the process.  One of "R (running)",
"S (sleeping)", "D (disk sleep)", "T (sped)", "T (tracing
s)", "Z (zombie)", or "X (dead)".

* Tgid: Thread group ID (i.e., Process ID).

* Ngid: NUMA group ID (0 if none; since Linux 3.13).

* Pid: Thread ID (see gettid(2)).

* PPid: PID of parent process.

* TracerPid: PID of process tracing this process (0 if not being traced).

* Uid, Gid: Real, effective, saved set, and filesystem UIDs (GIDs).

* FDSize: Number of file descriptor slots currently allocated.

* Groups: Supplementary group list.

* NStgid: Thread group ID (i.e., PID) in each of the PID namespaces of which [pid] is a member.  The leftmost entry shows the value with respect to the PID namespace of the process that mounted this procfs (or the root namespace if mounted by the kernel), followed by the value in successively nested inner namespaces.  (Since Linux 4.1.)

* NSpid: Thread ID in each of the PID namespaces of which [pid] is a member.  The fields are ordered as for NStgid. (Since Linux 4.1.)

* NSpgid: Process group ID in each of the PID namespaces of which [pid] is a member.  The fields are ordered as for NSt‐ gid.  (Since Linux 4.1.)

* NSsid: descendant namespace session ID hierarchy Session ID in each of the PID namespaces of which [pid] is a member. The fields are ordered as for NStgid.  (Since Linux 4.1.)

* VmPeak: Peak virtual memory size.

* VmSize: Virtual memory size.

* VmLck: Locked memory size (see mlock(2)).

* VmPin: Pinned memory size (since Linux 3.2).  These are pages that can't be moved because something needs to directly access physical memory.

* VmHWM: Peak resident set size ("high water mark").

* VmRSS: Resident set size.  Note that the value here is the sum of RssAnon, RssFile, and RssShmem.

* RssAnon: Size of resident anonymous memory.  (since Linux 4.5).

* RssFile: Size of resident file mappings.  (since Linux 4.5).

* RssShmem: Size of resident shared memory (includes System V shared memory, mappings from tmpfs(5), and shared anonymous mappings).  (since Linux 4.5).

* VmData, VmStk, VmExe: Size of data, stack, and text segments.

* VmLib: Shared library code size.

* VmPTE: Page table entries size (since Linux 2.6.10).

* VmPMD: Size of second-level page tables (added in Linux 4.0; removed in Linux 4.15).

* VmSwap: Swapped-out virtual memory size by anonymous private pages; shmem swap usage is not included (since Linux 2.6.34).

* HugetlbPages: Size of hugetlb memory portions (since Linux 4.4).

* CoreDumping: Contains the value 1 if the process is currently dumping core, and 0 if it is not (since Linux 4.15). This information can be used by a monitoring process to avoid killing a process that is currently dumping core, which could result in a corrupted core dump file.

* Threads: Number of threads in process containing this thread.

* SigQ: This field contains two slash-separated numbers that relate to queued signals for the real user ID of this process.  The first of these is the number of currently queued signals for this real user ID, and the second is the resource limit on the number of queued signals for this process (see the description of RLIMIT_SIGPENDING in getrlimit(2)). 

* SigPnd, ShdPnd: Mask (expressed in hexadecimal) of signals pending for thread and for process as a whole (see pthreads(7) and signal(7)).

* SigBlk, SigIgn, SigCgt: Masks (expressed in hexadeximal) indicating signals being blocked, ignored, and caught (see signal(7)).

* CapInh, CapPrm, CapEff: Masks (expressed in hexadeximal) of capabilities enabled in inheritable, permitted, and effec‐ tive sets (see capabilities(7)).

* CapBnd: Capability bounding set, expressed in hexadecimal (since Linux 2.6.26, see capabilities(7)).

* CapAmb: Ambient capability set, expressed in hexadecimal (since Linux 4.3, see capabilities(7)).

* NoNewPrivs: Value of the no_new_privs bit (since Linux 4.10, see prctl(2)).

* Seccomp: Seccomp mode of the process (since Linux 3.8, see seccomp(2)).  0 means SECCOMP_MODE_DISABLED; 1 means SEC‐ COMP_MODE_STRICT; 2 means SECCOMP_MODE FILTER.  This field is provided only if the kernel was built with the CONFIG_SECCOMP kernel configuration option enabled.

* Speculation_Store_Bypass: Speculation flaw mitigation state (since Linux 4.17, see prctl(2)).

* Cpus_allowed: Hexadecimal mask of CPUs on which this process may run (since Linux 2.6.24, see cpuset(7)).

* Cpus_allowed_list: Same as previous, but in "list format" (since Linux 2.6.26, see cpuset(7)).

* Mems_allowed: Mask of memory nodes allowed to this process (since Linux 2.6.24, see cpuset(7)).

* Mems_allowed_list: Same as previous, but in "list format" (since Linux 2.6.26, see cpuset(7)).

* voluntary_ctxt_switches, nonvoluntary_ctxt_switches: Number of voluntary and involuntary context switches (since Linux 2.6.23).

## /proc/[pid]/syscall (since Linux 2.6.27)
This file exposes the system call number and argument regis‐ ters for the system call currently being executed by the process, followed by the values of the stack pointer and pro‐ gram counter registers.  The values of all six argument regis‐ ters are exposed, although most system calls use fewer registers.

If the process is blocked, but not in a system call, then the file displays -1 in place of the system call number, followed by just the values of the stack pointer and program counter. If process is not blocked, then the file contains just the string "running". This file is present only if the kernel was configured with CONFIG_HAVE_ARCH_TRACEHOOK.

Permission to access this file is governed by a ptrace access mode PTRACE_MODE_ATTACH_FSCREDS check; see ptrace(2).

## /proc/[pid]/task (since Linux 2.6.0)
This is a directory that contains one subdirectory for each thread in the process.  The name of each subdirectory is the numerical thread ID ([tid]) of the thread (see gettid(2)).

Within each of these subdirectories, there is a set of files with the same names and contents as under the /proc/[pid] directories.  For attributes that are shared by all threads, the contents for each of the files under the task/[tid] subdi‐ rectories will be the same as in the corresponding file in the parent  /proc/[pid] directory (e.g., in a multithreaded process, all of the task/[tid]/cwd files will have the same value as the ## /proc/[pid]/cwd file in the parent directory, since all of the threads in a process share a working direc‐ tory).  For attributes that are distinct for each thread, the corresponding files under task/[tid] may have different values (e.g., various fields in each of the task/[tid]/status files may be different for each thread), or they might not exist in /proc/[pid] at all.

In a multithreaded process, the contents of the /proc/[pid]/task directory are not available if the main thread has already terminated (typically by calling pthread_exit(3)).
