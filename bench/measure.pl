#!/usr/bin/env perl
# measure.pl <out> <command> [args...]
#
# Runs the command and writes one line to <out>, then exits with the command's status:
#
#   <wall ms> <tree peak rss bytes> <largest process rss bytes> <user us> <sys us>
#
# Perl, because neither bash nor Node can read wait4()'s rusage and this machine has no
# /usr/bin/time. Linux only.
#
# - Wall time covers fork to reap, so starting Perl is not part of it.
# - CPU and the largest process come from wait4(), exact. They include every descendant
#   that was waited for, which is the whole tree unless something daemonizes. CPU is summed;
#   ru_maxrss is the largest single process, not a sum.
# - The tree peak is the largest sum of VmHWM over the processes alive at once, sampled from
#   /proc every 10 ms by a separate process. A wrapper that stays alive around the manager
#   counts too. It is never below the exact largest process.
use strict;
use warnings;
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC);

my %WAIT4 = (x86_64 => 61, aarch64 => 260, riscv64 => 260);
my ($arch) = `uname -m` =~ /(\S+)/;
my $nr = $WAIT4{$arch} or die "measure: no wait4 syscall number for $arch\n";
my ($out, @cmd) = @ARGV;
die "usage: measure.pl <out> <command> [args...]\n" unless @cmd;
# struct rusage is 144 bytes on 64-bit Linux: two timevals, then ru_maxrss in KiB.
my ($status, $usage) = (pack("i", 0), "\0" x 144);
pipe(my $from_sampler, my $to_sampler) or die "measure: pipe: $!\n";

my $t0 = clock_gettime(CLOCK_MONOTONIC);
my $pid = fork() // die "measure: fork: $!\n";
if (!$pid) {
  { no warnings "exec"; exec { $cmd[0] } @cmd; }
  warn "measure: $cmd[0]: $!\n";
  exit 127;
}

my $sampler = fork() // die "measure: fork: $!\n";
if (!$sampler) {
  close $from_sampler;
  my ($peak, $stop) = (0, 0);
  $SIG{TERM} = sub { $stop = 1 };
  until ($stop) {
    my ($sum, @todo) = (0, $pid);
    while (defined(my $p = shift @todo)) {
      if (open my $fh, "<", "/proc/$p/status") {
        $sum += $1 if do { local $/; <$fh> // "" } =~ /^VmHWM:\s+(\d+)/m;
      }
      for my $file (glob "/proc/$p/task/*/children") {
        open my $fh, "<", $file or next;
        push @todo, split " ", do { local $/; <$fh> // "" };
      }
    }
    $peak = $sum if $sum > $peak;
    Time::HiRes::sleep(0.01);
  }
  print $to_sampler $peak * 1024, "\n";
  exit 0;
}
close $to_sampler;

my $got;
do { $got = syscall($nr, $pid + 0, $status, 0, $usage) } while ($got == -1 && $!{EINTR});
my $t1 = clock_gettime(CLOCK_MONOTONIC);
die "measure: wait4: $!\n" if $got != $pid;
kill "TERM", $sampler;
my $tree = <$from_sampler> // 0;
waitpid $sampler, 0;

my ($us, $uus, $ss, $sus, $maxrss) = unpack "q5", $usage;
$maxrss *= 1024;
$tree = $maxrss if $tree < $maxrss;
open my $fh, ">", $out or die "measure: $out: $!\n";
printf $fh "%d %d %d %d %d\n", ($t1 - $t0) * 1000, $tree, $maxrss, $us * 1e6 + $uus,
  $ss * 1e6 + $sus;
close $fh;
my $code = unpack "i", $status;
exit(($code & 127) ? 128 + ($code & 127) : $code >> 8);
