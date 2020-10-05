#if ((UNITY_EDITOR_WIN || UNITY_STANDALONE_WIN) && !UNITY_WEBGL)
#define ISWINDOWS
#endif

#if ((UNITY_EDITOR_LINUX || UNITY_STANDALONE_LINUX) && !UNITY_WEBGL)
#define ISLINUX
#endif

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using BinaryTools.Elf; // To determine whether Linux EXE is 32- or 64-bit
using BinaryTools.Elf.Io; // Make sure it has a reader it's happy with...

#if ISLINUX
using c_uint = System.UInt32;
using pid_t = System.Int32;
#if UNITY_64
using c_ptr = System.UInt64;
using c_long = System.Int64; // Mandated to be same size as pointer on Linux
#else
using c_ptr = System.UInt32;
using c_long = System.Int32; // Mandated to be same size as pointer on Linux
#endif
#endif

namespace R1Engine {
    public class ProcessMemoryStream : Stream {
#if ISWINDOWS
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, long lpBaseAddress, byte[] lpBuffer, int dwSize, ref UIntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, long lpBaseAddress, byte[] lpBuffer, int dwSize, ref UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);
#elif ISLINUX
        // Taken from https://dev.to/v0idzz/linux-memory-manipulation-using-net-core-53ce
        [StructLayout(LayoutKind.Sequential)]
        unsafe struct iovec {
            public void* iov_base;
            public c_long iov_len;
        }

        [DllImport("libc")]
        private static extern unsafe c_long process_vm_readv(int pid,
                iovec* local_iov,
                c_ptr liovcnt,
                iovec* remote_iov,
                c_ptr riovcnt,
                c_ptr flags);

        [DllImport("libc")]
        private static extern unsafe c_long process_vm_writev(int pid,
                iovec* local_iov,
                c_ptr liovcnt,
                iovec* remote_iov,
                c_ptr riovcnt,
                c_ptr flags);
#endif

        const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        const int PROCESS_WM_READ = 0x0010;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_OPERATION = 0x0008;
        public enum Mode {
            Read,
            Write,
            AllAccess
        }

#if (ISWINDOWS || ISLINUX)
        public Process process;
        IntPtr processHandle = IntPtr.Zero;
#endif
        long currentAddress = 0;
        Mode mode = Mode.Read;
        string exeFile = "";
        bool is64bit = false;

        public string ExeFile => exeFile;

        public bool Is64BitProcess => is64bit;

        public ProcessMemoryStream(string name, Mode mode) {
#if (ISWINDOWS || ISLINUX)
            Process[] processes = Process.GetProcessesByName(name.Replace(".exe",""));
#if ISLINUX
            // If something's running through Wine, then Mono identifies it as "wine-preloader", because this is
            // what it finds when it does a readlink on "/proc/{pid}/exe".
            // Only solution I see is to search for all processes with that name and then use /proc/{pid}/comm to
            // find their real names...
            if ((processes.Length == 0) && name.EndsWith(".exe")) {
                Process[] wineProcesses = Process.GetProcessesByName("wine-preloader");
                foreach (var wineProcess in wineProcesses) {
                    string cmdLine = File.ReadAllLines($"/proc/{wineProcess.Id}/cmdline")[0].Split(new Char[] {'\0'})[0];
                    string realName = cmdLine.Split(new Char[] {'/', '\\'}).Last();
                    if (String.Equals(realName,name)) {
                        processes = new Process[] {wineProcess};
                        if (cmdLine.StartsWith("/"))
                            // It's an absolute path.
                            exeFile = cmdLine;
                        else 
                            // TODO: Maybe make this not assume that the traced process never "chdir"s...
                            exeFile = $"/proc/{wineProcess.Id}/cwd/{cmdLine}";
                        break;
                    }
                }
            }
            // Could also be 64-bit...
            if ((processes.Length == 0) && name.EndsWith(".exe")) {
                Process[] wineProcesses = Process.GetProcessesByName("wine64-preloader");
                foreach (var wineProcess in wineProcesses) {
                    string cmdLine = File.ReadAllLines($"/proc/{wineProcess.Id}/cmdline")[0].Split(new Char[] {'\0'})[0];
                    string realName = cmdLine.Split(new Char[] {'/', '\\'}).Last();
                    if (String.Equals(realName,name)) {
                        is64bit = true;
                        processes = new Process[] {wineProcess};
                        if (cmdLine.StartsWith("/"))
                            // It's an absolute path.
                            exeFile = cmdLine;
                        else 
                            // TODO: Maybe make this not assume that the traced process never "chdir"s...
                            exeFile = $"/proc/{wineProcess.Id}/cwd/{cmdLine}";
                        break;
                    }
                }
            }
#endif
            if (processes.Length == 0) throw new FileNotFoundException("Process not found");
            for (int i = 1; i < processes.Length; i++) {
                processes[i].Dispose();
            }
            process = processes[0];
            if (String.Equals(exeFile,"")) exeFile = process.MainModule.FileName;
#endif
            this.mode = mode;

#if ISWINDOWS
            int accessLevel = PROCESS_WM_READ;
            switch (mode) {
                case Mode.Read:
                    accessLevel = PROCESS_WM_READ; break;
                case Mode.Write:
                    accessLevel = PROCESS_VM_WRITE; break;
                case Mode.AllAccess:
                    accessLevel = PROCESS_ALL_ACCESS; break;
            }
            processHandle = OpenProcess(accessLevel, false, process.Id);
#endif
            
            // Check bit flavour...
#if ISWINDOWS
#if UNITY_64
	        const bool win64 = true;
#else
            IsWow64Process(Process.GetCurrentProcess().Handle, out var win64);
#endif
            IsWow64Process(processHandle, out var isWow64);
            is64bit = win64 && !isWow64;
            UnityEngine.Debug.Log($"Is current process 64-bit: {win64}");
            UnityEngine.Debug.Log($"Is game process 64-bit: {!isWow64}");
#elif ISLINUX
            var exestream = new FileStream(process.MainModule.FileName, FileMode.Open, FileAccess.Read);
            var exereader = new EndianBinaryReader(exestream, EndianBitConverter.NativeEndianness);
            ElfFile elfFile = ElfFile.ReadElfFile(exereader);
            is64bit = (elfFile.Header.Class == BinaryTools.Elf.ElfClass.Elf64);
#endif
        }

        public long GetProcessBaseAddress(string moduleName = null)
        {
#if (ISWINDOWS || ISLINUX)

            return (String.IsNullOrWhiteSpace(moduleName) ? process.MainModule : process.Modules.Cast<ProcessModule>().First(x => x.ModuleName == moduleName)).BaseAddress.ToInt64();
#else
            return 0;
#endif
        }

        public long BaseStreamOffset { get; set; }

        public long BaseAddress {
#if (ISWINDOWS || ISLINUX)
            get { return process.MainModule.BaseAddress.ToInt64(); }
#else
            get { return 0; }
#endif
        }

        public int MemorySize {
#if (ISWINDOWS || ISLINUX)
            get { return process.MainModule.ModuleMemorySize; } 
#else
            get { return 0; }
#endif
        }

        public override bool CanRead {
#if ISWINDOWS
            get { return (mode == Mode.Read || mode == Mode.AllAccess) && processHandle != IntPtr.Zero; }
#elif ISLINUX
            get { return (mode == Mode.Read || mode == Mode.AllAccess) && process.Id != 0; }
#else
            get { return false; }
#endif
        }

        public override bool CanSeek {
#if ISWINDOWS
            get { return processHandle != IntPtr.Zero; }
#elif ISLINUX
            get { return process.Id != 0; } // No handle on Linux - we just ptrace every time we want to do something.
#else
            get { return false; }
#endif
        }

        public override bool CanWrite {
#if ISWINDOWS
            get { return (mode == Mode.Write || mode == Mode.AllAccess) && processHandle != IntPtr.Zero; }
#elif ISLINUX
            get { return (mode == Mode.Write || mode == Mode.AllAccess) && process.Id != 0; }
#else
            get { return false; }
#endif
        }

        public override long Length {
            get {
                if (!CanSeek) throw new NotSupportedException();
                return MemorySize - BaseStreamOffset;
            }
        }

        public override long Position {
            get {
                if (!CanSeek) throw new NotSupportedException();
                return currentAddress - BaseStreamOffset;
            }
            set {
                if (!CanSeek) throw new NotSupportedException();
                currentAddress = value + BaseStreamOffset;
            }
        }

        public override void Flush() {
            return; // We're writing to RAM. No flushing necessary.
        }

        public override int Read(byte[] buffer, int offset, int count) {
            if (!CanRead) throw new NotSupportedException();
#if ISWINDOWS
            UIntPtr numBytesRead = UIntPtr.Zero;
            byte[] tempBuf = new byte[count];
            bool success = ReadProcessMemory(processHandle, currentAddress, tempBuf, count, ref numBytesRead);

            if (!success)
                throw new Win32Exception();

            if (numBytesRead != UIntPtr.Zero) {
                Seek(numBytesRead.ToUInt32(), SeekOrigin.Current);
                Array.Copy(tempBuf, 0, buffer, offset, numBytesRead.ToUInt32());
                return (int)numBytesRead.ToUInt32();
            } else {
                return 0;
            }
#elif ISLINUX
            int numBytesRead = 0;

            unsafe {
                // Based on https://dev.to/v0idzz/linux-memory-manipulation-using-net-core-53ce
                var tempBuf = stackalloc byte[count];
                var localIo = new iovec {
                    iov_base = tempBuf,
                    iov_len = count
                };
                var remoteIo = new iovec {
                    iov_base = (void*)currentAddress,
                    iov_len = count
                };

                numBytesRead = (int)process_vm_readv(process.Id, &localIo, 1, &remoteIo, 1, 0);

                if (numBytesRead > 0) {
                    Seek(numBytesRead, SeekOrigin.Current);
                    fixed (byte* pBuffer = buffer) {
                        for (int i=0; i<numBytesRead; i++) {
                            pBuffer[offset+i] = tempBuf[i];
                        }
                    }
                    return numBytesRead;
                } else {
                    return 0;
                }
            }
#else
            throw new NotImplementedException();
#endif
        }

        public override long Seek(long offset, SeekOrigin origin) {
            if (!CanSeek) throw new NotSupportedException();
            switch (origin) {
                case SeekOrigin.Begin:
                    currentAddress = offset + BaseStreamOffset;
                    break;
                case SeekOrigin.Current:
                    currentAddress += offset;
                    break;
                case SeekOrigin.End:
                    currentAddress = BaseAddress + MemorySize - offset;
                    break;
            }
            return currentAddress - BaseStreamOffset;
        }

        public override void SetLength(long value) {
            if (!CanSeek || !CanWrite) throw new NotSupportedException();
            // Actually we won't support it in general, so...
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count) {
            if (!CanWrite) throw new NotSupportedException();
#if ISWINDOWS
            UIntPtr numBytesWritten = UIntPtr.Zero;
            byte[] tempBuf = new byte[count];
            Array.Copy(buffer, offset, tempBuf, 0, count);
            bool success = WriteProcessMemory(processHandle, currentAddress, tempBuf, count, ref numBytesWritten);

            if (!success)
                throw new Win32Exception();

            if (numBytesWritten != UIntPtr.Zero) {
                Seek(numBytesWritten.ToUInt32(), SeekOrigin.Current);
            }
#elif ISLINUX
            int numBytesWritten = 0;

            unsafe {
                var tempBuf = stackalloc byte[count];
                fixed (byte* pBuffer = buffer) {
                    for (int i=0; i<count; i++) {
                        tempBuf[i] = pBuffer[offset+i];
                    }
                }

                // Based on https://dev.to/v0idzz/linux-memory-manipulation-using-net-core-53ce
                var localIo = new iovec {
                    iov_base = tempBuf,
                    iov_len = count
                };
                var remoteIo = new iovec {
                    iov_base = (void*)currentAddress,
                    iov_len = count
                };

                numBytesWritten = (int)process_vm_writev(process.Id, &localIo, 1, &remoteIo, 1, 0);
            }

            if (numBytesWritten > 0) {
                if (numBytesWritten > count)
                    numBytesWritten = count;
                Seek(numBytesWritten, SeekOrigin.Current);
            }
#else
            throw new NotImplementedException();
#endif
        }

        ~ProcessMemoryStream() {
            Dispose(false);
        }

        protected override void Dispose(bool disposing) {
            base.Dispose(disposing);
#if ISWINDOWS
            if (processHandle != IntPtr.Zero) {
                CloseHandle(processHandle);
                processHandle = IntPtr.Zero;
            }
#endif
#if (ISWINDOWS || ISLINUX)
            if (process != null) {
                process.Dispose();
                process = null;
            }
#endif
        }
    }
}
