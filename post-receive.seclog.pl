#!/usr/bin/env perl

=encoding utf-8

=pod

=head1 NAME

B<post-recieve.gitseclog.pl>

=head1 SYNOPSIS

Git post-receive hook that checks every incoming commit and creates a security log.
It is assumed that ssh is used to push changes to the repo.

=head1 OPTIONS

N/A

=head1 DESCRIPTION

This script checks the pushed changes and creates a security log, it will examine the commits and create events for each file added, modified or deleted. Currently the log contains the following fields by default: TIME,USER,CLIENT_IP,REPO,COMMIT,AUTHOR,ACTION,FILE.

This is a git post-receive hook, and is not ment to run from the command line.
Copy or link this script to <repo>.git/hooks/ in a bare repo and name it post-receive.
Make sure it has the execute bit set and that syslogd is configured to receive the log events properly.
If a logfile is used, ensure that the calling user(s) can write to the log.

Notes about post-receive hooks:
The pre-receive hook is NOT called with arguments for each ref updated,
it recives on stdin a line of the format "oldrev newrev refname".
The value in oldrev will be 40 zeroes if the refname is propsed to be created (i.e. new branch)
The value in newrev will be 40 zeroes if the refname is propsed to be deleted (i.e. delete branch)
The values on both will be non-zero if refname is propsed to be updated
post-receive is called after the repository has been updata and can thus not alter the outcome of the push even if errors are detected.

=head1 KNOWN ISSUES

This script can not give a complete picture of how the git repo is accessed, simply because of how git works. The log this script produce has to be combined with other logs from sshd and httpd to cover read accesses. There exists no hook that is called when someone simply reads a repo, also keep in mind that commit's can be pushed by other people than the author of that commit, hower this script logs both the commit author and the ssh-user doing the push. Obviously this script will have a performance impact when it's called.

=head1 AUTHOR

Håkan Isaksson, 2013

=cut

use strict;
use warnings;
use FindBin;
use POSIX;
use Sys::Syslog;
use Sys::Hostname;
use Data::Dumper;
use File::Basename qw(basename);
use Fcntl qw(:flock);
use Pod::Usage;

### Conditionally load YAML if the module exists
my $HAVEYAML = eval {
    require YAML;
    1;
};

my %CFG = (
    "DEBUG" => 0,  ### Print debug information
    "SYSLOG" => 1, ### Send messages to syslog as well as file
    "FACILITY" => 'local5', ### Syslog facility
    #"LOGFILE" => '/var/git/logs/git-seclog.log',
    "ENVFIELDS" => [ 'TIME','USER','CLIENT_IP','REPO' ],
    "EVENTFIELDS" => [ 'COMMIT','AUTHOR','ACTION','FILE' ],
    "DELIMITER" => ',', ### Field delimiter
    "EMPTY" => '', ### What to put in empty fields
    );

my %INFO;       ### Log info, mainly information from %ENV, common for all events
my @EVENTS;     ### List of Hashes with events
my $OK=0;       ### Exit status
my $LOG_OPEN=0; ### Is the logfile open?

#my $YAMLFILE = $FindBin::Bin."/".basename($FindBin::Script,".pl").".yaml";
my $YAMLFILE = "/var/git/bin/post-receive.seclog.yaml";

sub log_msg {
    my $msg = shift;
    my $fh = shift;
    if ( $LOG_OPEN ) {
        my $str="";
        my $sys="";
        foreach my $key ( @{ $CFG{ENVFIELDS} } ) {
            $key=uc($key);
            if (defined $INFO{$key}) {
                $str.=$INFO{$key}.$CFG{DELIMITER};
                $sys.=$INFO{$key}.$CFG{DELIMITER} if $key ne 'TIME';
            } else {
                $str.=$CFG{EMPTY}.$CFG{DELIMITER};
                $sys.=$CFG{EMPTY}.$CFG{DELIMITER};
            }
        }
        print $fh $str.$msg."\n";
        syslog("$CFG{FACILITY}|notice",$sys.$msg) if $CFG{SYSLOG} && $msg ne "";
    }
}

sub msg {
    my $msg = shift;
    print STDERR $msg."\n";
    syslog("$CFG{FACILITY}|info","$msg") if $CFG{SYSLOG} && $msg ne "";
}

sub debug {
    my $msg = shift;
    msg "[DEBUG] $0: $msg" if $CFG{DEBUG};
    syslog("$CFG{FACILITY}|debug","$msg") if $CFG{SYSLOG} && $CFG{DEBUG};
}

sub error {
    my $msg = shift;
    msg "[ERROR] $0: $msg";
    syslog("$CFG{FACILITY}|error","$msg") if $CFG{SYSLOG};
    exit(1);
}

#
# Load or create config file if it does not exists, uses YAML
#
sub load_config {
    return 0 if ! $HAVEYAML;
    if ( -f "$YAMLFILE") {
        my $data = YAML::LoadFile( $YAMLFILE );
        foreach my $key (keys %{$data}) {
            $CFG{$key} = $data->{$key};
        }
        debug("loaded $YAMLFILE");
    } else {
        my $data = \%CFG;
        YAML::DumpFile( $YAMLFILE, $data );
        debug("created $YAMLFILE");
    }
    return 1;
}

#
# Open logfile and syslog if appropriate
#
sub open_log {

    if ($CFG{SYSLOG}) {
        $Sys::Syslog::host=Sys::Hostname::hostname();
        openlog('gitseclog','pid',$CFG{FACILITY});
    }

    if ($CFG{LOGFILE}) {
        open(LOG_FH,">>".$CFG{LOGFILE}) or error("Can't open $CFG{LOGFILE}: $!");
        flock(LOG_FH, LOCK_EX);
        $LOG_OPEN=1;
        debug("open $CFG{LOGFILE}");
    }
    return *LOG_FH;
}

#
# Get user session info from ENV
#
sub get_env {
    my $info = shift;
    $info->{'USER'}=$ENV{USER};
    $info->{'CLIENT_IP'}= (split(/ /,$ENV{SSH_CLIENT}))[0];
    $info->{'TIME'}=strftime("%Y-%m-%d %H:%M:%S", localtime(time()));
    $info->{'HOST'}=$ENV{HOST};
    $info->{'REPO'}=`readlink -f $ENV{GIT_DIR}`;
    chomp($info->{'REPO'});
}

#
# Add event hash to @EVENTS
#
sub add_event {
    my $event = shift;
    push(@EVENTS, $event);
}

#
# Print events to logfile
#
sub log_events {
    my $str;
    debug "EVENTS= ".Dumper(\@EVENTS);
    foreach my $event (@EVENTS) {
        my $str="";
        foreach my $key (@{$CFG{EVENTFIELDS}}) {
            $key=lc($key);
            if (defined $event->{$key}) {
                $str.=$event->{$key}.$CFG{DELIMITER};
            } else {
                $str.=$CFG{EMPTY}.$CFG{DELIMITER};
            }
        }
        $str=~ s/,$//; 
        log_msg($str, \*LOG_FH);

    }
}

#
# Check the commit(s) and create an event list for logging
#
sub check_commits {
    my ($oldrev, $newrev, $refname) = @_;
    debug("check_commits: oldrev=$oldrev newrev=$newrev refname=$refname");

    my $author="";
    my $oldiszero=0; $oldiszero=1 if $oldrev =~ /^0+$/;
    my $newiszero=0; $newiszero=1 if $newrev =~ /^0+$/;

    my $revs="$oldrev..$newrev";
    $revs=$newrev if $oldiszero;
    
    my $commit = $newrev;
    if (! $newiszero) {
        debug("git show -s --format='%an' $newrev");
        $author=`git show -s --format='%an' $newrev`; chomp($author);
        debug("git rev-parse --short $newrev");
        $commit=`git rev-parse --short $newrev`; chomp($commit);
    }

    add_event( { action => "CREATED", file => "$refname"}) if $oldiszero;
    add_event( { action => "REMOVED", file => "$refname"}) if $newiszero;

    debug("git diff --name-status $revs 2> /dev/null");
    for my $line ( split /\n/, `git diff --name-status $revs 2>/dev/null` ) {
        debug("output from diff: $line");
        my ($ac, $file) = split(/\s/,$line);
        $ac="ADDED" if $ac eq "A";
        $ac="DELETED" if $ac eq "D";
        $ac="MODIFIED" if $ac eq "M";
        add_event( { action => $ac, file => $file, commit => $commit, author=>$author } );

    }

    log_events();
    return 0;
}


#
# Sanity testing
#
if ( ! defined $ENV{GIT_DIR} ) {
    pod2usage({ -verbose => 2});
}

#
# Main loop, receives input from git on STDIN
#
load_config();
my $LOG_FH = open_log();
get_env(\%INFO);
debug "INFO=".Dumper(\%INFO);

while (<>) {
    chomp;
    my ($oldrev, $newrev, $refname) = split(/ /);
    $OK = check_commits($oldrev, $newrev, $refname);
}

debug "exit code = $OK" if $CFG{DEBUG} eq 1;
exit($OK);

END {
    close($LOG_FH) if $LOG_OPEN;
    closelog() if $CFG{SYSLOG};
}
