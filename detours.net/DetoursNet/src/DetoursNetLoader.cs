using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Linq;

namespace DetoursNet
{
    public static class Loader
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", EntryPoint = "LoadLibraryW", CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibrary(string lpModuleName);

        [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("DetoursDll.dll")]
        private static extern long DetourAttach(ref IntPtr a, IntPtr b);
        [DllImport("DetoursDll.dll")]
        private static extern long DetourDetach(ref IntPtr a, IntPtr b);

        [DllImport("DetoursDll.dll")]
        private static extern long DetourUpdateThread(IntPtr a);

        [DllImport("DetoursDll.dll")]
        private static extern long DetourTransactionBegin();

        [DllImport("DetoursDll.dll")]
        private static extern long DetourTransactionCommit();

        [DllImport("DetoursDll.dll")]
        private static extern bool DetoursPatchIAT(IntPtr hModule, IntPtr import, IntPtr real);

        [DllImport("DetoursNetCLR.dll", CharSet = CharSet.Ansi)]
        private static extern void DetoursCLRSetGetProcAddressCache(IntPtr hModule, string procName, IntPtr real);

        /// <summary>
        /// Find all static method with custom attribute type
        /// </summary>
        /// <param name="assembly">Assembly object</param>
        /// <param name="attributeType">type of custom attribute</param>
        /// <returns>All method infos</returns>
        private static MethodInfo[] FindAttribute(this Assembly assembly, Type attributeType)
        {
            return assembly.GetTypes()
                .SelectMany(t => t.GetMethods())
                .Where(m => m.GetCustomAttributes(attributeType, false).Length > 0)
                .ToArray();
        }

        /// <summary>
        /// Main entry point of loader
        /// </summary>
        //public static int Start(string arguments)
        //{
        //    string assemblyName = arguments;
        //    //string assemblyName = System.Environment.GetEnvironmentVariable("DETOURSNET_ASSEMBLY_PLUGIN");

        //    Assembly assembly = Assembly.GetEntryAssembly(); //Assembly.LoadFrom(assemblyName);

        //    foreach(var method in assembly.FindAttribute(typeof(OnInitAttribute))) {
        //        method.Invoke(null, null);
        //    }

        //    MethodInfo[] methods = assembly.FindAttribute(typeof(DetoursAttribute));
        //    HookMethods(methods);

        //    return 0;
        //}

        //public static void HookMethods(MethodInfo[] methods)
        //{
        //    foreach (var method in methods)
        //    {
        //        var attribute = (DetoursAttribute)method.GetCustomAttributes(typeof(DetoursAttribute), false)[0];
        //        HookMethod(attribute.Module, method.Name, attribute.DelegateType, method);
        //    }
        //}

        private static bool GetProcAddressEx(string moduleName, string methodName, out IntPtr module, out IntPtr method)
        {
            method = IntPtr.Zero;
            module = LoadLibrary(moduleName);
            if (module == IntPtr.Zero)
            {
                return false;
            }

            method = GetProcAddress(module, methodName);
            if (method == IntPtr.Zero)
            {
                return false;
            }

            return true;
        }

        public static bool HookMethod(string moduleName, string methodName, Type delegateType, MethodInfo method, Delegate dlgt = null)
        {
            if (dlgt == null)
                dlgt = Delegate.CreateDelegate(delegateType, method);

            if (!GetProcAddressEx(moduleName, methodName, out IntPtr module, out IntPtr real))
                return false;

            return HookMethod(module, real, delegateType, method, dlgt);
        }

        public static bool HookMethod(IntPtr module, IntPtr targetFunc, Type delegateType, MethodInfo method, Delegate dlgt)
        {
            DelegateStore.Mine[method] = dlgt;

            // record pointer
            IntPtr import = targetFunc;
            Delegate hookDelegate = DelegateStore.Mine[method];
            IntPtr detour = Marshal.GetFunctionPointerForDelegate(hookDelegate);

            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            long res = DetourAttach(ref targetFunc, detour);
            if (res != 0)
                Console.WriteLine($"[{nameof(HookMethod)}] DetourAttach finished. res = {res} (NON ZERO!)");

            res = DetourTransactionCommit();
            if (res != 0)
                Console.WriteLine($"[{nameof(HookMethod)}] DetourTransactionCommit finished. res = {res} (NON ZERO!)");

            // Add function to pinvoke cache
            DetoursCLRSetGetProcAddressCache(module, method.Name, targetFunc);

            // and so on patch IAT of clr module
            // No checking return value. It might fail for many methods and that's ok.
            DetoursPatchIAT(GetModuleHandle("clr.dll"), import, targetFunc);

            DelegateStore.Real[method] = Marshal.GetDelegateForFunctionPointer(targetFunc, delegateType);
            return true;
        }

        public static bool HookIAT(IntPtr hModule, IntPtr import, IntPtr replacement)
        {
            return DetoursPatchIAT(hModule, import, replacement);
        }

        public static bool UnHookMethod(IntPtr module, IntPtr targetFunc, MethodInfo method)
        {
            Delegate origAfterJumpDelegate = DelegateStore.Real[method];
            Delegate hookDelegate = DelegateStore.Mine[method];
            IntPtr originAfterJump = Marshal.GetFunctionPointerForDelegate(origAfterJumpDelegate);
            IntPtr detour = Marshal.GetFunctionPointerForDelegate(hookDelegate);

            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());

            long res = DetourDetach(ref originAfterJump, detour);
            if (res != 0)
                Console.WriteLine($"[{nameof(UnHookMethod)}] DetourDetach finished. res = {res} (NON ZERO!)");

            res = DetourTransactionCommit();
            if (res != 0)
                Console.WriteLine($"[{nameof(UnHookMethod)}] DetourTransactionCommit finished. res = {res} (NON ZERO!)");

            // TODO: Also unhook from IAT of clr.dll??

            DelegateStore.Real.Remove(method);
            DelegateStore.Mine.Remove(method);
            return true;
        }
    }
}
