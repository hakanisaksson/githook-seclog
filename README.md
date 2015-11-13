# NAME

**post-recieve.gitseclog.pl**

# SYNOPSIS

Git post-receive hook that checks every incoming commit and creates a security log.
It is assumed that ssh is used to push changes to the repo.

# OPTIONS

N/A

# DESCRIPTION

This script checks the pushed changes and creates a security log, it will examine the commits and create events for each file added, modified or deleted. Currently the log contains the following fields by default: TIME,USER,CLIENT\_IP,REPO,COMMIT,AUTHOR,ACTION,FILE.

This is a git post-receive hook, and is not ment to run from the command line.
Copy or link this script to &lt;repo>.git/hooks/ in a bare repo and name it post-receive.
Make sure it has the execute bit set and that syslogd is configured to receive the log events properly.
If a logfile is used, ensure that the calling user(s) can write to the log.

Notes about post-receive hooks:
The pre-receive hook is NOT called with arguments for each ref updated,
it recives on stdin a line of the format "oldrev newrev refname".
The value in oldrev will be 40 zeroes if the refname is propsed to be created (i.e. new branch)
The value in newrev will be 40 zeroes if the refname is propsed to be deleted (i.e. delete branch)
The values on both will be non-zero if refname is propsed to be updated
post-receive is called after the repository has been updata and can thus not alter the outcome of the push even if errors are detected.

# KNOWN ISSUES

This script can not give a complete picture of how the git repo is accessed, simply because of how git works. The log this script produce has to be combined with other logs from sshd and httpd to cover read accesses. There exists no hook that is called when someone simply reads a repo, also keep in mind that commit's can be pushed by other people than the author of that commit, hower this script logs both the commit author and the ssh-user doing the push. Obviously this script will have a performance impact when it's called.

# AUTHOR

Håkan Isaksson
