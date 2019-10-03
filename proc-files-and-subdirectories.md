# proc - process information pseudo-filesystem

DESCRIPTION         
The proc filesystem is a pseudo-filesystem which provides an interface to kernel data structures.  It is commonly mounted at /proc.  Typically, it is mounted automatically by the system, but it can also be mounted manually using a command such as:

$ mount -t proc proc /proc

Most of the files in the proc filesystem are read-only, but some files are writable, allowing kernel variables to be changed.

Mount options
The proc filesystem supports the following mount options:

hidepid=n (since Linux 3.3)
This option controls who can access the information in /proc/[pid] directories.  The argument, n, is one of the following values:

- 0   Everybody may access all /proc/[pid] directories.  This is the traditional behavior, and the default if this mount option is not specified.

- 1   Users may not access files and subdirectories inside any /proc/[pid] directories but their own (the /proc/[pid] directories themselves remain visible).  Sensitive files such as /proc/[pid]/cmdline and /proc/[pid]/status are now protected against other users.  This makes it impossible to learn whether any user is running a specific program (so long as the program doesn't otherwise reveal itself by its behavior).

- 2   As for mode 1, but in addition the /proc/[pid] directories belonging to other users become invisible.  This means that /proc/[pid] entries can no longer be used to discover the PIDs on the system.  This doesn't hide the fact that a process with a specific PID value exists (it can be learned by other means, for example, by "kill -0 $PID"), but it hides a process's UID and GID, which could otherwise be learned by employing stat(2) on a /proc/[pid] directory.  This greatly complicates an attacker's task of gathering information about running processes (e.g., discovering whether some daemon is running with elevated privileges, whether another user is running some sensitive program, whether other users are running any program at all, and so on).

gid=gid (since Linux 3.3)
Specifies the ID of a group whose members are authorized to learn process information otherwise prohibited by hidepid (i.e., users in this group behave as though /proc was mounted with hidepid=0).  This group should be used instead of approaches such as putting nonroot users into the sudoers(5) file.

Overview
Underneath /proc, there are the following general groups of files and subdirectories:

/proc/[pid] subdirectories
Each one of these subdirectories contains files and subdirectories exposing information about the process with the corresponding process ID.

Underneath each of the /proc/[pid] directories, a task subdirectory contains subdirectories of the form task/[tid], which contain corresponding information about each of the threads in the process, where tid is the kernel thread ID of the thread.

The /proc/[pid] subdirectories are visible when iterating through /proc with getdents(2) (and thus are visible when one uses ls(1) to view the contents of /proc).

/proc/[tid] subdirectories
Each one of these subdirectories contains files and subdirec‐
tories exposing information about the thread with the corre‐
sponding thread ID.  The contents of these directories are the
same as the corresponding /proc/[pid]/task/[tid] directories.

The /proc/[tid] subdirectories are not visible when iterating
through /proc with getdents(2) (and thus are not visible when
one uses ls(1) to view the contents of /proc).

/proc/self
When a process accesses this magic symbolic link, it resolves
to the process's own /proc/[pid] directory.

/proc/thread-self
When a thread accesses this magic symbolic link, it resolves
to the process's own /proc/self/task/[tid] directory.
