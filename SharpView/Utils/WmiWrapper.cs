using System;
using System.Collections.Generic;
using System.Management;
using System.Net;

namespace SharpView.Utils
{
    public static class WmiWrapper
    {
        public static ManagementClass GetClass(string nameSpace,
            string className,
            NetworkCredential credential = null,
            ImpersonationLevel impersonationLevel = ImpersonationLevel.Impersonate,
            AuthenticationLevel authenticationLevel = AuthenticationLevel.Default)
        {
            try
            {
                var options = new ConnectionOptions
                {
                    Impersonation = impersonationLevel,
                    Authentication = authenticationLevel,
                    Username = credential?.UserName,
                    Password = credential?.Password,
                    SecurePassword = credential?.SecurePassword,
                    EnablePrivileges = true
                };
                var scope = new ManagementScope(nameSpace, options);
                scope.Connect();

                var option = new ObjectGetOptions(null, TimeSpan.MaxValue, true);
                var path = new ManagementPath(className);
                var cls = new ManagementClass(scope, path, option);
                return cls;
            }
            catch (Exception ex)
            {
            }

            return null;
        }

        public static ManagementObject CreateInstance(ManagementClass cls)
        {
            if (cls == null) return null;

            try
            {
                return cls.CreateInstance();
            }
            catch (Exception)
            {
            }

            return null;
        }

        public static ManagementObjectCollection GetInstances(ManagementClass cls)
        {
            if (cls == null) return null;

            try
            {
                var option = new EnumerationOptions()
                {
                    ReturnImmediately = true,
                    UseAmendedQualifiers = true,
                    DirectRead = true
                };
                return cls.GetInstances(option);
            }
            catch (Exception)
            {
            }

            return null;
        }

        public static object CallMethod(ManagementClass cls, string method, Dictionary<string, object> args = null)
        {
            if (cls == null) return null;

            try
            {
                ManagementBaseObject inParams = null;
                if (args != null)
                {
                    inParams = cls.GetMethodParameters(method);
                    foreach (var arg in args)
                    {
                        inParams[arg.Key] = arg.Value;
                    }
                }
                
                var obj = cls.InvokeMethod(method, inParams, null);
                return obj;
            }
            catch (Exception)
            {
            }

            return null;
        }

        public static Dictionary<string, object> CallMethod(ManagementBaseObject baseObj, string method, Dictionary<string, object> args = null)
        {
            if (baseObj == null) return null;

            try
            {
                var obj = baseObj as ManagementObject;
                if (obj == null)
                    return null;
                ManagementBaseObject inParams = null;
                if (args != null)
                {
                    inParams = obj.GetMethodParameters(method);
                    foreach (var arg in args)
                    {
                        inParams[arg.Key] = arg.Value;
                    }
                }

                var retObj = obj.InvokeMethod(method, inParams, null);
                var rets = new Dictionary<string, object>();
                if (retObj == null) return rets;
                foreach (var p in retObj.Properties)
                {
                    rets.Add(p.Name, p.Value);
                }

                return rets;
            }
            catch (Exception)
            {
            }

            return null;
        }
    }
}
