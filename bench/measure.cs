// bench.sh's timer on Windows, where there is no GNU time: measure.exe <out> <command line...>
// Runs the command in a job object, so every process it starts is counted, and writes one line
// to <out>:  <wall ms> <cpu ms> <peak KB> <exit status>
// CPU is user plus kernel time of the whole tree, exited children included. Peak is the job's
// peak committed memory: Windows keeps no peak working set for a tree of processes.
// Built by bench.sh with the C# compiler every Windows has (.NET Framework's csc.exe).
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

static class Measure {
  [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong a, b, c, d, e, f; }
  [StructLayout(LayoutKind.Sequential)] struct BasicLimit {
    public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags;
    public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit;
    public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
  }
  [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit {
    public BasicLimit Basic; public IoCounters Io;
    public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
  }
  [StructLayout(LayoutKind.Sequential)] struct Accounting {
    public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
    public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
  }
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct StartupInfo {
    public int cb; public string reserved, desktop, title; public int x, y, w, h, cx, cy, fill, flags;
    public short show, reserved2; public IntPtr reserved3, stdin, stdout, stderr;
  }
  [StructLayout(LayoutKind.Sequential)] struct ProcInfo { public IntPtr process, thread; public int pid, tid; }

  [DllImport("kernel32", SetLastError = true)] static extern IntPtr CreateJobObject(IntPtr a, string name);
  [DllImport("kernel32", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);
  [DllImport("kernel32")] static extern bool QueryInformationJobObject(IntPtr job, int cls, out ExtendedLimit info, int len, IntPtr ret);
  [DllImport("kernel32")] static extern bool QueryInformationJobObject(IntPtr job, int cls, out Accounting info, int len, IntPtr ret);
  [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool CreateProcess(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref StartupInfo si, out ProcInfo pi);
  [DllImport("kernel32")] static extern uint ResumeThread(IntPtr t);
  [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32")] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
  [DllImport("kernel32")] static extern IntPtr GetCommandLineW();

  static int Main(string[] args) {
    if (args.Length < 2) { Console.Error.WriteLine("usage: measure <out> <command line>"); return 2; }
    // The command line as given after <out>, quoting and all.
    string line = Marshal.PtrToStringUni(GetCommandLineW());
    int at = line.IndexOf(args[0], StringComparison.Ordinal) + args[0].Length;
    if (at < line.Length && line[at] == '"') at++;
    string cmd = line.Substring(at).TrimStart();
    IntPtr job = CreateJobObject(IntPtr.Zero, null);
    var si = new StartupInfo(); si.cb = Marshal.SizeOf(si);
    ProcInfo pi;
    const uint CREATE_SUSPENDED = 4;
    var clock = Stopwatch.StartNew();
    if (!CreateProcess(null, cmd, IntPtr.Zero, IntPtr.Zero, true, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi)) {
      Console.Error.WriteLine("measure: cannot start " + cmd + ": error " + Marshal.GetLastWin32Error());
      File.WriteAllText(args[0], "0 0 0 127\n");
      return 127;
    }
    // Suspended until it is in the job, so nothing it starts escapes the count.
    AssignProcessToJobObject(job, pi.process);
    ResumeThread(pi.thread);
    WaitForSingleObject(pi.process, 0xFFFFFFFF);
    long wall = clock.ElapsedMilliseconds;
    uint code; GetExitCodeProcess(pi.process, out code);
    ExtendedLimit ext; QueryInformationJobObject(job, 9, out ext, Marshal.SizeOf(typeof(ExtendedLimit)), IntPtr.Zero);
    Accounting acc; QueryInformationJobObject(job, 1, out acc, Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero);
    long cpu = (acc.TotalUserTime + acc.TotalKernelTime + 5000) / 10000; // 100 ns units
    File.WriteAllText(args[0], string.Format("{0} {1} {2} {3}\n", wall, cpu, (ulong)ext.PeakJobMemoryUsed / 1024, code));
    return (int)code;
  }
}
