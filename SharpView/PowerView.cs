using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.DirectoryServices;
using System.Xml;
using System.Runtime.InteropServices;
using System.DirectoryServices.ActiveDirectory;
using SharpView.Arguments;
using SharpView.Returns;
using SharpView.Enums;
using SharpView.Utils;
using SharpView.Interfaces;
using System.Diagnostics.Eventing.Reader;
using static SharpView.Utils.NativeMethods;
using System.Security.AccessControl;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Text;
using System.Security.Principal;

namespace SharpView
{
    public static class PowerView
    {
        public static void TestMethod(Args_Test args = null)
        {
            Logger.Write_Verbose("Called TestMethod!");
        }

        private static System.DirectoryServices.DirectorySearcher Get_DomainSearcher(Args_Get_DomainSearcher args = null)
        {
            if (args == null) args = new Args_Get_DomainSearcher();

            string TargetDomain = null;
            string BindServer = null;

            var userDnsDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");

            if (args.Domain.IsNotNullOrEmpty())
            {
                TargetDomain = args.Domain;

                if (userDnsDomain != null && userDnsDomain.Trim() != "")
                {
                    // see if we can grab the user DNS logon domain from environment variables
                    var UserDomain = userDnsDomain;
                    var logonServer = Environment.GetEnvironmentVariable("LOGONSERVER");
                    if (logonServer != null && logonServer.Trim() != "" && UserDomain.IsNotNullOrEmpty())
                    {
                        BindServer = $"{logonServer.Replace(@"\\", "")}.{UserDomain}";
                    }
                }
            }
            else if (args.Credential != null)
            {
                // if not -Domain is specified, but -Credential is, try to retrieve the current domain name with Get-Domain
                var DomainObject = Get_Domain(new Args_Get_Domain { Credential = args.Credential });
                BindServer = DomainObject.PdcRoleOwner.Name;
                TargetDomain = DomainObject.Name;
            }
            else if (userDnsDomain != null && userDnsDomain.Trim() != "")
            {
                // see if we can grab the user DNS logon domain from environment variables
                TargetDomain = userDnsDomain;
                var logonServer = Environment.GetEnvironmentVariable("LOGONSERVER");
                if (logonServer != null && logonServer.Trim() != "" && TargetDomain.IsNotNullOrEmpty())
                {
                    BindServer = $"{logonServer.Replace(@"\\", "")}.{TargetDomain}";
                }
            }
            else
            {
                // otherwise, resort to Get-Domain to retrieve the current domain object
                Logger.Write_Verbose("get-domain");
                var DomainObject = Get_Domain();
                BindServer = DomainObject.PdcRoleOwner.Name;
                TargetDomain = DomainObject.Name;
            }

            if (args.Server.IsNotNullOrEmpty())
            {
                // if there's not a specified server to bind to, try to pull a logon server from ENV variables
                BindServer = args.Server;
            }

            var SearchString = "LDAP://";

            if (BindServer != null && BindServer.Trim() != "")
            {
                SearchString += BindServer;
                if (TargetDomain.IsNotNullOrEmpty())
                {
                    SearchString += '/';
                }
            }

            if (args.SearchBasePrefix.IsNotNullOrEmpty())
            {
                SearchString += args.SearchBasePrefix + @",";
            }

            var DN = string.Empty;
            if (args.SearchBase.IsNotNullOrEmpty())
            {
                if (new Regex(@"^GC://").Match(args.SearchBase).Success)
                {
                    // if we're searching the global catalog, get the path in the right format
                    DN = args.SearchBase.ToUpper().Trim('/');
                    SearchString = string.Empty;
                }
                else
                {
                    if (new Regex(@"^LDAP://").Match(args.SearchBase).Success)
                    {
                        if (new Regex(@"LDAP://.+/.+").Match(args.SearchBase).Success)
                        {
                            SearchString = string.Empty;
                            DN = args.SearchBase;
                        }
                        else
                        {
                            DN = args.SearchBase.Substring(7);
                        }
                    }
                    else
                    {
                        DN = args.SearchBase;
                    }
                }
            }
            else
            {
                // transform the target domain name into a distinguishedName if an ADS search base is not specified
                if (TargetDomain != null && TargetDomain.Trim() != "")
                {
                    DN = $"DC={TargetDomain.Replace(".", ",DC=")}";
                }
            }

            SearchString += DN;
            Logger.Write_Verbose($@"[Get-DomainSearcher] search base: {SearchString}");

            System.DirectoryServices.DirectorySearcher Searcher = null;
            if (args.Credential != null)
            {
                Logger.Write_Verbose(@"[Get-DomainSearcher] Using alternate credentials for LDAP connection");
                // bind to the inital search object using alternate credentials
                var DomainObject = new System.DirectoryServices.DirectoryEntry(SearchString, args.Credential.UserName, args.Credential.Password);
                Searcher = new System.DirectoryServices.DirectorySearcher(DomainObject);
            }
            else
            {
                // bind to the inital object using the current credentials
                //Searcher = new System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
                var DomainObject = new System.DirectoryServices.DirectoryEntry(SearchString);
                Searcher = new System.DirectoryServices.DirectorySearcher(DomainObject);
            }

            Searcher.PageSize = args.ResultPageSize;
            Searcher.SearchScope = args.SearchScope;
            Searcher.CacheResults = false;
            Searcher.ReferralChasing = System.DirectoryServices.ReferralChasingOption.All;

            if (args.ServerTimeLimit != null)
            {
                Searcher.ServerTimeLimit = new TimeSpan(0, 0, args.ServerTimeLimit.Value);
            }

            if (args.Tombstone)
            {
                Searcher.Tombstone = true;
            }

            if (args.LDAPFilter.IsNotNullOrWhiteSpace())
            {
                Searcher.Filter = args.LDAPFilter;
            }

            if (args.SecurityMasks != null)
            {
                Searcher.SecurityMasks = args.SecurityMasks.Value;
            }

            if (args.Properties != null)
            {
                // handle an array of properties to load w/ the possibility of comma-separated strings
                var PropertiesToLoad = new List<string>();
                foreach (var item in args.Properties)
                {
                    PropertiesToLoad.AddRange(item.Split(','));
                }

                Searcher.PropertiesToLoad.AddRange(PropertiesToLoad.ToArray());
            }

            return Searcher;
        }

        private static LDAPProperty Convert_LDAPProperty(System.DirectoryServices.ResultPropertyCollection Properties)
        {
            var ObjectProperties = new LDAPProperty();

            foreach (string propName in Properties.PropertyNames)
            {
                if (string.Compare(propName, @"adspath", StringComparison.OrdinalIgnoreCase) != 0)
                {
                    if (string.Compare(propName, @"objectsid", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"sidhistory", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        // convert all listed sids (i.e. if multiple are listed in sidHistory)
                        var values = new List<string>();
                        foreach (var property in Properties[propName])
                        {
                            var sid = new System.Security.Principal.SecurityIdentifier(property as byte[], 0);
                            values.Add(sid.Value);
                        }
                        if (string.Compare(propName, @"objectsid", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.objectsid = values.ToArray();
                        else
                            ObjectProperties.sidhistory = values.ToArray();
                    }
                    else if (string.Compare(propName, @"grouptype", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.grouptype = (GroupType)Properties[propName][0];
                    }
                    else if (string.Compare(propName, @"samaccounttype", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.samaccounttype = (SamAccountType)Properties[propName][0];
                    }
                    else if (string.Compare(propName, @"objectguid", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        // convert the GUID to a string
                        ObjectProperties.objectguid = new Guid(Properties[propName][0] as byte[]).ToString();
                    }
                    else if (string.Compare(propName, @"useraccountcontrol", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.useraccountcontrol = (UACEnumValue)Properties[propName][0];
                    }
                    else if (string.Compare(propName, @"ntsecuritydescriptor", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        // $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                        var Descriptor = new System.Security.AccessControl.RawSecurityDescriptor(Properties[propName][0] as byte[], 0);
                        if (Descriptor.Owner != null)
                        {
                            ObjectProperties.Owner = Descriptor.Owner;
                        }
                        if (Descriptor.Group != null)
                        {
                            ObjectProperties.Group = Descriptor.Group;
                        }
                        if (Descriptor.DiscretionaryAcl != null)
                        {
                            ObjectProperties.DiscretionaryAcl = Descriptor.DiscretionaryAcl;
                        }
                        if (Descriptor.SystemAcl != null)
                        {
                            ObjectProperties.SystemAcl = Descriptor.SystemAcl;
                        }
                    }
                    else if (string.Compare(propName, @"accountexpires", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        if ((long)Properties[propName][0] >= DateTime.MaxValue.Ticks)
                        {
                            ObjectProperties.accountexpires = "NEVER";
                        }
                        else
                        {
                            ObjectProperties.accountexpires = DateTime.FromFileTime((long)Properties[propName][0]);
                        }
                    }
                    else if (string.Compare(propName, @"lastlogon", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"lastlogontimestamp", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"pwdlastset", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"lastlogoff", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"badPasswordTime", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"whencreated", StringComparison.OrdinalIgnoreCase) == 0 ||
                        string.Compare(propName, @"whenchanged", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        DateTime dt;
                        // convert timestamps
                        if (Properties[propName][0] is System.MarshalByRefObject)
                        {
                            // if we have a System.__ComObject
                            var Temp = Properties[propName][0];
                            var High = (Int32)Temp.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, Temp, null);
                            var Low = (Int32)Temp.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, Temp, null);
                            dt = DateTime.FromFileTime(Int64.Parse(string.Format("0x{0:x8}{1:x8}", High, Low)));
                        }
                        if (Properties[propName][0] is System.DateTime)
                        {
                            dt = (DateTime)Properties[propName][0];
                        }
                        else
                        {
                            // otherwise just a string
                            dt = DateTime.FromFileTime((long)Properties[propName][0]);
                        }
                        if (string.Compare(propName, @"lastlogon", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.lastlogon = dt;
                        else if (string.Compare(propName, @"lastlogontimestamp", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.lastlogontimestamp = dt;
                        else if (string.Compare(propName, @"pwdlastset", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.pwdlastset = dt;
                        else if (string.Compare(propName, @"lastlogoff", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.lastlogoff = dt;
                        else if (string.Compare(propName, @"badPasswordTime", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.badPasswordTime = dt;
                        else if (string.Compare(propName, @"whencreated", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.whencreated = dt;
                        else if (string.Compare(propName, @"whenchanged", StringComparison.OrdinalIgnoreCase) == 0)
                            ObjectProperties.whenchanged = dt;
                    }
                    else if (string.Compare(propName, @"name", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.name = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"distinguishedname", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.distinguishedname = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"dnsrecord", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.dnsrecord = Properties[propName][0];
                    }
                    else if (string.Compare(propName, @"samaccountname", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.samaccountname = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"member", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.member = Properties[propName].GetValues<string>().ToArray();
                    }
                    else if (string.Compare(propName, @"memberof", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.memberof = Properties[propName].GetValues<string>().ToArray();
                    }
                    else if (string.Compare(propName, @"cn", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.cn = Properties[propName].GetValues<string>().ToArray();
                    }
                    else if (string.Compare(propName, @"objectclass", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.objectclass = Properties[propName].GetValues<string>().ToArray();
                    }
                    else if (string.Compare(propName, @"managedby", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.managedby = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"siteobject", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.siteobject = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"ServicePrincipalName", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.ServicePrincipalName = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"dnshostname", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.dnshostname = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"gplink", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.gplink = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"gpoptions", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.gpoptions = (int)Properties[propName][0];
                    }
                    else if (string.Compare(propName, @"displayname", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.displayname = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"path", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.path = Properties[propName][0] as string;
                    }
                    else if (string.Compare(propName, @"siteobjectbl", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        ObjectProperties.siteobjectbl = Properties[propName][0] as string;
                    }
                    else if (Properties[propName][0] is System.MarshalByRefObject)
                    {
                        // try to convert misc com objects
                        var Prop = Properties[propName];
                        try
                        {
                            var Temp = Properties[propName][0];
                            var High = (Int32)Temp.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, Temp, null);
                            var Low = (Int32)Temp.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, Temp, null);
                            ObjectProperties.others.Add(propName, Int64.Parse(string.Format("0x{0:x8}{1:x8}", High, Low)));
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Convert-LDAPProperty] error: {e}");
                            ObjectProperties.others.Add(propName, Prop[0]);
                        }
                    }
                    else if (Properties[propName].Count == 1)
                    {
                        ObjectProperties.others.Add(propName, Properties[propName][0]);
                    }
                    else
                    {
                        ObjectProperties.others.Add(propName, Properties[propName]);
                    }
                }
            }
            return ObjectProperties;
        }

        public static System.DirectoryServices.ActiveDirectory.Domain Get_Domain(Args_Get_Domain args = null)
        {
            if (args == null) args = new Args_Get_Domain();

            if (args.Credential != null)
            {
                Logger.Write_Verbose("[Get-Domain] Using alternate credentials for Get-Domain");

                string TargetDomain;
                if (args.Domain.IsNotNullOrEmpty())
                {
                    TargetDomain = args.Domain;
                }
                else
                {
                    // if no domain is supplied, extract the logon domain from the PSCredential passed
                    TargetDomain = args.Credential.Domain;
                    Logger.Write_Verbose("[Get-Domain] Extracted domain '$TargetDomain' from -Credential");
                }

                var DomainContext = new System.DirectoryServices.ActiveDirectory.DirectoryContext(System.DirectoryServices.ActiveDirectory.DirectoryContextType.Domain,
                    TargetDomain,
                    args.Credential.UserName,
                    args.Credential.Password);

                try
                {
                    return System.DirectoryServices.ActiveDirectory.Domain.GetDomain(DomainContext);
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($"[Get-Domain] The specified domain '{TargetDomain}' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: {e}");
                }
            }
            else if (args.Domain.IsNotNullOrEmpty())
            {
                var DomainContext = new System.DirectoryServices.ActiveDirectory.DirectoryContext(System.DirectoryServices.ActiveDirectory.DirectoryContextType.Domain, args.Domain);
                try
                {
                    return System.DirectoryServices.ActiveDirectory.Domain.GetDomain(DomainContext);
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($"[Get-Domain] The specified domain '{args.Domain}' does not exist, could not be contacted, or there isn't an existing trust : {e}");
                }
            }
            else
            {
                try
                {
                    return System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($"[Get-Domain] Error retrieving the current domain: {e}");
                }
            }
            return null;
        }

        public static System.DirectoryServices.ActiveDirectory.Domain Get_NetDomain(Args_Get_Domain args = null)
        {
            return Get_Domain(args);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>
        /// <returns>System.DirectoryServices.SearchResult or LDAPProperty</returns>
        public static IEnumerable<object> Get_DomainComputer(Args_Get_DomainComputer args = null)
        {
            if (args == null) args = new Args_Get_DomainComputer();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var CompSearcher = Get_DomainSearcher(SearcherArguments);
            var Computers = new List<object>();

            if (CompSearcher != null)
            {
                var IdentityFilter = @"";
                var Filter = @"";
                if (args.Identity != null)
                {
                    foreach (var samName in args.Identity)
                    {
                        var IdentityInstance = samName.Replace(@"(", @"\28").Replace(@")", @"\29");
                        if (new Regex(@"^S-1-").Match(IdentityInstance).Success)
                        {
                            IdentityFilter += $@"(objectsid={IdentityInstance})";
                        }
                        else if (new Regex(@"^CN=").Match(IdentityInstance).Success)
                        {
                            IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                            if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                            {
                                // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                // and rebuild the domain searcher
                                var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                Logger.Write_Verbose($@"[Get-DomainComputer] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                CompSearcher = Get_DomainSearcher(SearcherArguments);
                                if (CompSearcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainComputer] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                }
                            }
                        }
                        else if (IdentityInstance.Contains(@"."))
                        {
                            IdentityFilter += $@"(|(name={IdentityInstance})(dnshostname={IdentityInstance}))";
                        }
                        else if (new Regex(@"^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$").Match(IdentityInstance).Success)
                        {
                            var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                            IdentityFilter += $@"(objectguid={GuidByteString})";
                        }
                        else
                        {
                            IdentityFilter += $@"(name={IdentityInstance})";
                        }
                    }
                }
                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += $@"(|{IdentityFilter})";
                }

                if (args.Unconstrained)
                {
                    Logger.Write_Verbose(@"[Get-DomainComputer] Searching for computers with for unconstrained delegation");
                    Filter += @"(userAccountControl:1.2.840.113556.1.4.803:=524288)";
                }
                if (args.TrustedToAuth)
                {
                    Logger.Write_Verbose(@"[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals");
                    Filter += @"(msds-allowedtodelegateto=*)";
                }
                if (args.Printers)
                {
                    Logger.Write_Verbose("[Get-DomainComputer] Searching for printers");
                    Filter += @"(objectCategory=printQueue)";
                }
                if (args.SPN.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainComputer] Searching for computers with SPN: {args.SPN}");
                    Filter += $@"(servicePrincipalName={args.SPN})";
                }
                if (args.OperatingSystem.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainComputer] Searching for computers with operating system: {args.OperatingSystem}");
                    Filter += $@"(operatingsystem={args.OperatingSystem})";
                }
                if (args.ServicePack.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainComputer] Searching for computers with service pack: {args.ServicePack}");
                    Filter += $@"(operatingsystemservicepack={args.ServicePack})";
                }
                if (args.SiteName.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainComputer] Searching for computers with site name: {args.SiteName}");
                    Filter += $@"(serverreferencebl={args.SiteName})";
                }
                if (args.LDAPFilter.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainComputer] Using additional LDAP filter: {args.LDAPFilter}");
                    Filter += $@"{args.LDAPFilter}";
                }
                // build the LDAP filter for the dynamic UAC filter value
                var uacs = args.UACFilter.ExtractValues();
                foreach (var uac in uacs)
                {
                    if (uac.IsNot())
                    {
                        Filter += $@"(!(userAccountControl:1.2.840.113556.1.4.803:={uac.GetValueAsInteger()}))";
                    }
                    else
                    {
                        Filter += $@"(userAccountControl:1.2.840.113556.1.4.803:={uac.GetValueAsInteger()})";
                    }
                }

                CompSearcher.Filter = $@"(&(samAccountType=805306369){Filter})";
                Logger.Write_Verbose($@"[Get-DomainComputer] Get-DomainComputer filter string: {CompSearcher.Filter}");

                if (args.FindOne)
                {
                    var result = CompSearcher.FindOne();
                    var Up = true;
                    if (args.Ping)
                    {
                        Up = TestConnection.Ping(result.Properties["dnshostname"][0] as string, 1);
                    }
                    if (Up)
                    {
                        if (args.Raw)
                        {
                            // return raw result objects
                            Computers.Add(result);
                        }
                        else
                        {
                            Computers.Add(Convert_LDAPProperty(result.Properties));
                        }
                    }
                }
                else
                {
                    var Results = CompSearcher.FindAll();
                    foreach (SearchResult result in Results)
                    {
                        var Up = true;
                        if (args.Ping)
                        {
                            Up = TestConnection.Ping(result.Properties["dnshostname"][0] as string, 1);
                        }
                        if (Up)
                        {
                            if (args.Raw)
                            {
                                // return raw result objects
                                Computers.Add(result);
                            }
                            else
                            {
                                Computers.Add(Convert_LDAPProperty(result.Properties));
                            }
                        }
                    }
                    if (Results != null)
                    {
                        try { Results.Dispose(); }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-DomainComputer] Error disposing of the Results object: {e}");
                        }
                    }
                }
                CompSearcher.Dispose();
            }
            return Computers;
        }

        public static IEnumerable<object> Get_NetComputer(Args_Get_DomainComputer args = null)
        {
            return Get_DomainComputer(args);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>
        /// <returns>System.DirectoryServices.SearchResult or LDAPProperty</returns>
        public static IEnumerable<object> Get_DomainController(Args_Get_DomainController args = null)
        {
            if (args == null) args = new Args_Get_DomainController();

            var Arguments = new Args_Get_DomainComputer();

            if (args.Domain.IsNotNullOrEmpty()) { Arguments.Domain = args.Domain; }
            if (args.Credential != null) { Arguments.Credential = args.Credential; }

            if (args.LDAP || args.Server.IsNotNullOrEmpty())
            {
                if (args.Server.IsNotNullOrEmpty()) { Arguments.Server = args.Server; }

                // UAC specification for domain controllers
                Arguments.LDAPFilter = @"(userAccountControl:1.2.840.113556.1.4.803:=8192)";

                return Get_DomainComputer(Arguments);
            }
            else
            {
                var FoundDomain = Get_Domain(new Args_Get_Domain
                {
                    Domain = Arguments.Domain,
                    Credential = Arguments.Credential
                });
                if (FoundDomain != null)
                {
                    var controllers = new List<object>();
                    foreach (var controller in FoundDomain.DomainControllers)
                    {
                        controllers.Add(controller);
                    }
                    return controllers;
                }
            }
            return null;
        }

        public static IEnumerable<object> Get_NetDomainController(Args_Get_DomainController args = null)
        {
            return Get_DomainController(args);
        }

        private static string Split_Path(string Path)
        {
            if (Path.IsNotNullOrEmpty() && Path.Split(new char[] { '\\' }).Length >= 3)
            {
                var Temp = Path.Split('\\')[2];
                if (Temp != null && Temp != "")
                {
                    return Temp;
                }
            }
            return null;
        }

        public static string[] Get_DomainFileServer(Args_Get_DomainFileServer args = null)
        {
            if (args == null) args = new Args_Get_DomainFileServer();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                LDAPFilter = "(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))",
                Properties = new string[] { "homedirectory", "scriptpath", "profilepath" },
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var retValues = new List<string>();

            if (args.Domain != null)
            {
                foreach (var TargetDomain in args.Domain)
                {
                    SearcherArguments.Domain = TargetDomain;
                    var UserSearcher = Get_DomainSearcher(SearcherArguments);
                    // get all results w/o the pipeline and uniquify them (I know it's not pretty)
                    foreach (SearchResult UserResult in UserSearcher.FindAll())
                    {
                        if (UserResult.Properties["homedirectory"] != null)
                        {
                            var val = Split_Path(UserResult.Properties["homedirectory"][0] as string);
                            if (!retValues.Any(x => x == val)) retValues.Add(val);
                        }
                        if (UserResult.Properties["scriptpath"] != null)
                        {
                            var val = Split_Path(UserResult.Properties["scriptpath"][0] as string);
                            if (!retValues.Any(x => x == val)) retValues.Add(val);
                        }
                        if (UserResult.Properties["profilepath"] != null)
                        {
                            var val = Split_Path(UserResult.Properties["profilepath"][0] as string);
                            if (!retValues.Any(x => x == val)) retValues.Add(val);
                        }
                    }
                }
            }
            else
            {
                var UserSearcher = Get_DomainSearcher(SearcherArguments);
                // get all results w/o the pipeline and uniquify them (I know it's not pretty)
                foreach (SearchResult UserResult in UserSearcher.FindAll())
                {
                    if (UserResult.Properties["homedirectory"] != null)
                    {
                        var val = Split_Path(UserResult.Properties["homedirectory"][0] as string);
                        if (!retValues.Any(x => x == val)) retValues.Add(val);
                    }
                    if (UserResult.Properties["scriptpath"] != null)
                    {
                        var val = Split_Path(UserResult.Properties["scriptpath"][0] as string);
                        if (!retValues.Any(x => x == val)) retValues.Add(val);
                    }
                    if (UserResult.Properties["profilepath"] != null)
                    {
                        var val = Split_Path(UserResult.Properties["profilepath"][0] as string);
                        if (!retValues.Any(x => x == val)) retValues.Add(val);
                    }
                }
            }
            return retValues.ToArray();
        }

        public static string[] Get_NetFileServer(Args_Get_DomainFileServer args = null)
        {
            return Get_DomainFileServer(args);
        }

        public static IEnumerable<string> Convert_ADName(Args_Convert_ADName args)
        {
            ADSNameType ADSInitType;
            string InitName;
            // https://msdn.microsoft.com/en-us/library/aa772266%28v=vs.85%29.aspx
            if (args.Server.IsNotNullOrEmpty())
            {
                ADSInitType = ADSNameType.Canonical;
                InitName = args.Server;
            }
            else if (args.Domain.IsNotNullOrEmpty())
            {
                ADSInitType = ADSNameType.DN;
                InitName = args.Domain;
            }
            else if (args.Credential != null)
            {
                ADSInitType = ADSNameType.DN;
                InitName = args.Credential.Domain;
            }
            else
            {
                // if no domain or server is specified, default to GC initialization
                ADSInitType = ADSNameType.NT4;
                InitName = null;
            }

            var Names = new List<string>();
            ADSNameType ADSOutputType;
            if (args.Identity != null)
            {
                foreach (var TargetIdentity in args.Identity)
                {
                    if (args.OutputType == null)
                    {
                        if (new Regex(@"^[A-Za-z]+\\[A-Za-z ]+").Match(TargetIdentity).Success)
                        {
                            ADSOutputType = ADSNameType.DomainSimple;
                        }
                        else
                        {
                            ADSOutputType = ADSNameType.NT4;
                        }
                    }
                    else
                    {
                        ADSOutputType = args.OutputType.Value;
                    }
                    var Translate = new ActiveDs.NameTranslate();

                    if (args.Credential != null)
                    {
                        try
                        {
                            Translate.InitEx((int)ADSInitType, InitName, args.Credential.UserName, args.Credential.Domain, args.Credential.Password);
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Convert-ADName] Error initializing translation for '{args.Identity}' using alternate credentials : {e}");
                        }
                    }
                    else
                    {
                        try
                        {
                            Translate.Init((int)ADSInitType, InitName);
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Convert-ADName] Error initializing translation for '{args.Identity}' : {e}");
                        }
                    }

                    // always chase all referrals
                    Translate.ChaseReferral = 0x60;

                    try
                    {
                        // 8 = Unknown name type -> let the server do the work for us
                        Translate.Set((int)ADSNameType.Unknown, TargetIdentity);
                        Names.Add(Translate.Get((int)ADSOutputType));
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[Convert-ADName] Error translating '{TargetIdentity}' : {e})");
                    }
                }
            }

            return Names;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>System.DirectoryServices.SearchResult or LDAPProperty</returns>
        public static IEnumerable<object> Get_DomainObject(Args_Get_DomainObject args = null)
        {
            if (args == null) args = new Args_Get_DomainObject();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ObjectSearcher = Get_DomainSearcher(SearcherArguments);
            var Objects = new List<object>();

            if (ObjectSearcher != null)
            {
                var IdentityFilter = "";
                var Filter = "";
                if (args.Identity != null)
                {
                    foreach (var samName in args.Identity)
                    {
                        var IdentityInstance = samName.Replace(@"(", @"\28").Replace(@")", @"\29");
                        if (new Regex(@"^S-1-").Match(IdentityInstance).Success)
                        {
                            IdentityFilter += $@"(objectsid={IdentityInstance})";
                        }
                        else if (new Regex(@"^(CN|OU|DC)=").Match(IdentityInstance).Success)
                        {
                            IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                            if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                            {
                                // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                // and rebuild the domain searcher
                                var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                Logger.Write_Verbose($@"[Get-DomainObject] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                ObjectSearcher = Get_DomainSearcher(SearcherArguments);
                                if (ObjectSearcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainObject] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                }
                            }
                        }
                        else if (new Regex(@"^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$").Match(IdentityInstance).Success)
                        {
                            var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                            IdentityFilter += $@"(objectguid={GuidByteString})";
                        }
                        else if (IdentityInstance.Contains(@"\"))
                        {
                            var ConvertedIdentityInstance = Convert_ADName(new Args_Convert_ADName
                            {
                                OutputType = ADSNameType.Canonical,
                                Identity = new string[] { IdentityInstance.Replace(@"\28", @"(").Replace(@"\29", @")") }
                            });
                            if (ConvertedIdentityInstance != null && ConvertedIdentityInstance.Any())
                            {
                                var ObjectDomain = ConvertedIdentityInstance.First().Substring(0, ConvertedIdentityInstance.First().IndexOf('/'));
                                var ObjectName = IdentityInstance.Split(new char[] { '\\' })[1];
                                IdentityFilter += $@"(samAccountName={ObjectName})";
                                SearcherArguments.Domain = ObjectDomain;
                                Logger.Write_Verbose($@"[Get-DomainObject] Extracted domain '{ObjectDomain}' from '{IdentityInstance}'");
                                ObjectSearcher = Get_DomainSearcher(SearcherArguments);
                            }
                        }
                        else if (IdentityInstance.Contains(@"."))
                        {
                            IdentityFilter += $@"(|(samAccountName={IdentityInstance})(name={IdentityInstance})(dnshostname={IdentityInstance}))";
                        }
                        else
                        {
                            IdentityFilter += $@"(|(samAccountName={IdentityInstance})(name={IdentityInstance})(displayname={IdentityInstance}))";
                        }
                    }
                }
                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += $@"(|{IdentityFilter})";
                }
                if (args.LDAPFilter.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainObject] Using additional LDAP filter: {args.LDAPFilter}");
                    Filter += $@"{args.LDAPFilter}";
                }
                // build the LDAP filter for the dynamic UAC filter value
                var uacs = args.UACFilter.ExtractValues();
                foreach (var uac in uacs)
                {
                    if (uac.IsNot())
                    {
                        Filter += $@"(!(userAccountControl:1.2.840.113556.1.4.803:={uac.GetValueAsInteger()}))";
                    }
                    else
                    {
                        Filter += $@"(userAccountControl:1.2.840.113556.1.4.803:={uac.GetValueAsInteger()})";
                    }
                }
                if (Filter != null && Filter != "")
                {
                    ObjectSearcher.Filter = $@"(&{Filter})";
                }
                Logger.Write_Verbose($@"[Get-DomainObject] Get-DomainComputer filter string: {ObjectSearcher.Filter}");

                if (args.FindOne)
                {
                    var result = ObjectSearcher.FindOne();
                    if (args.Raw)
                    {
                        // return raw result objects
                        Objects.Add(result);
                    }
                    else
                    {
                        Objects.Add(Convert_LDAPProperty(result.Properties));
                    }
                }
                else
                {
                    var Results = ObjectSearcher.FindAll();
                    foreach (SearchResult result in Results)
                    {
                        if (args.Raw)
                        {
                            // return raw result objects
                            Objects.Add(result);
                        }
                        else
                        {
                            Objects.Add(Convert_LDAPProperty(result.Properties));
                        }
                    }
                    if (Results != null)
                    {
                        try { Results.Dispose(); }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-DomainObject] Error disposing of the Results object: {e}");
                        }
                    }
                }
                ObjectSearcher.Dispose();
            }
            return Objects;
        }

        public static IEnumerable<object> Get_ADObject(Args_Get_DomainObject args = null)
        {
            return Get_DomainObject(args);
        }

        public static IEnumerable<object> Get_DomainUser(Args_Get_DomainUser args = null)
        {
            if (args == null) args = new Args_Get_DomainUser();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var UserSearcher = Get_DomainSearcher(SearcherArguments);
            var Users = new List<object>();

            if (UserSearcher != null)
            {
                var IdentityFilter = "";
                var Filter = "";
                if (args.Identity != null)
                {
                    foreach (var samName in args.Identity)
                    {
                        var IdentityInstance = samName.Replace(@"(", @"\28").Replace(@")", @"\29");
                        if (new Regex(@"^S-1-").Match(IdentityInstance).Success)
                        {
                            IdentityFilter += $@"(objectsid={IdentityInstance})";
                        }
                        else if (new Regex(@"^CN=").Match(IdentityInstance).Success)
                        {
                            IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                            if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                            {
                                // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                // and rebuild the domain searcher
                                var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                Logger.Write_Verbose($@"[Get-DomainUser] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                UserSearcher = Get_DomainSearcher(SearcherArguments);
                                if (UserSearcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainUser] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                }
                            }
                        }
                        else if (new Regex(@"^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$").Match(IdentityInstance).Success)
                        {
                            var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                            IdentityFilter += $@"(objectguid={GuidByteString})";
                        }
                        else if (IdentityInstance.Contains(@"\"))
                        {
                            var ConvertedIdentityInstance = Convert_ADName(new Args_Convert_ADName
                            {
                                OutputType = ADSNameType.Canonical,
                                Identity = new string[] { IdentityInstance.Replace(@"\28", @"(").Replace(@"\29", @")") }
                            });
                            if (ConvertedIdentityInstance != null && ConvertedIdentityInstance.Any())
                            {
                                var UserDomain = ConvertedIdentityInstance.First().Substring(0, ConvertedIdentityInstance.First().IndexOf('/'));
                                var UserName = IdentityInstance.Split(new char[] { '\\' })[1];
                                IdentityFilter += $@"(samAccountName={UserName})";
                                SearcherArguments.Domain = UserDomain;
                                Logger.Write_Verbose($@"[Get-DomainUser] Extracted domain '{UserDomain}' from '{IdentityInstance}'");
                                UserSearcher = Get_DomainSearcher(SearcherArguments);
                            }
                        }
                        else
                        {
                            IdentityFilter += $@"(samAccountName={IdentityInstance})";
                        }
                    }
                }

                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += $@"(|{IdentityFilter})";
                }

                if (args.SPN)
                {
                    Logger.Write_Verbose(@"[Get-DomainUser] Searching for non-null service principal names");
                    Filter += "(servicePrincipalName=*)";
                }
                if (args.AllowDelegation)
                {
                    Logger.Write_Verbose(@"[Get-DomainUser] Searching for users who can be delegated");
                    // negation of "Accounts that are sensitive and not trusted for delegation"
                    Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))";
                }
                if (args.DisallowDelegation)
                {
                    Logger.Write_Verbose(@"[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation");
                    Filter += "(userAccountControl:1.2.840.113556.1.4.803:=1048574)";
                }
                if (args.AdminCount)
                {
                    Logger.Write_Verbose(@"[Get-DomainUser] Searching for adminCount=1");
                    Filter += "(admincount=1)";
                }
                if (args.TrustedToAuth)
                {
                    Logger.Write_Verbose("[Get-DomainUser] Searching for users that are trusted to authenticate for other principals");
                    Filter += "(msds-allowedtodelegateto=*)";
                }
                if (args.PreauthNotRequired)
                {
                    Logger.Write_Verbose("[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate");
                    Filter += "(userAccountControl:1.2.840.113556.1.4.803:=4194304)";
                }
                if (args.LDAPFilter.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainUser] Using additional LDAP filter: {args.LDAPFilter}");
                    Filter += $@"{args.LDAPFilter}";
                }

                // build the LDAP filter for the dynamic UAC filter value
                var uacs = args.UACFilter.ExtractValues();
                foreach (var uac in uacs)
                {
                    if (uac.IsNot())
                    {
                        Filter += $@"(!(userAccountControl:1.2.840.113556.1.4.803:={uac.GetValueAsInteger()}))";
                    }
                    else
                    {
                        Filter += $@"(userAccountControl:1.2.840.113556.1.4.803:={uac.GetValueAsInteger()})";
                    }
                }

                UserSearcher.Filter = $@"(&(samAccountType=805306368){Filter})";
                Logger.Write_Verbose($@"[Get-DomainUser] filter string: {UserSearcher.Filter}");

                if (args.FindOne)
                {
                    var result = UserSearcher.FindOne();
                    if (args.Raw)
                    {
                        // return raw result objects
                        Users.Add(result);
                    }
                    else
                    {
                        Users.Add(Convert_LDAPProperty(result.Properties));
                    }
                }
                else
                {
                    var Results = UserSearcher.FindAll();
                    foreach (SearchResult result in Results)
                    {
                        if (args.Raw)
                        {
                            // return raw result objects
                            Users.Add(result);
                        }
                        else
                        {
                            Users.Add(Convert_LDAPProperty(result.Properties));
                        }
                    }
                    if (Results != null)
                    {
                        try { Results.Dispose(); }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-DomainUser] Error disposing of the Results object: {e}");
                        }
                    }
                }
                UserSearcher.Dispose();
            }
            return Users;
        }

        public static IEnumerable<object> Get_NetUser(Args_Get_DomainUser args = null)
        {
            return Get_DomainUser(args);
        }

        public static IEnumerable<object> Get_DomainGroup(Args_Get_DomainGroup args = null)
        {
            if (args == null) args = new Args_Get_DomainGroup();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ObjectArguments = new Args_Get_DomainObject
            {
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var GroupSearcher = Get_DomainSearcher(SearcherArguments);
            var Groups = new List<object>();

            if (GroupSearcher != null)
            {
                if (args.MemberIdentity != null)
                {
                    string[] OldProperties = null;
                    if (args.Properties != null)
                    {
                        OldProperties = SearcherArguments.Properties;
                    }

                    ObjectArguments.Identity = args.MemberIdentity;
                    ObjectArguments.Raw = true;

                    var Objects = Get_DomainObject(ObjectArguments);
                    if (Objects != null)
                    {

                    }
                    foreach (SearchResult obj in Objects)
                    {
                        // convert the user/group to a directory entry
                        var ObjectDirectoryEntry = obj.GetDirectoryEntry();

                        // cause the cache to calculate the token groups for the user/group
                        ObjectDirectoryEntry.RefreshCache(new string[] { @"tokenGroups" });
                        foreach (byte[] tokenGroup in ObjectDirectoryEntry.Properties[@"tokenGroups"])
                        {
                            // convert the token group sid
                            var GroupSid = new System.Security.Principal.SecurityIdentifier(tokenGroup, 0).Value;

                            // ignore the built in groups
                            if (new Regex(@"^S-1-5-32-.*").Match(GroupSid).Success == false)
                            {
                                ObjectArguments.Identity = new string[] { GroupSid };
                                ObjectArguments.Raw = false;
                                if (OldProperties != null) { ObjectArguments.Properties = OldProperties; }
                                var Group = Get_DomainObject(ObjectArguments);
                                if (Group != null)
                                {
                                    Groups.AddRange(Group);
                                }
                            }
                        }
                    }
                }
                else
                {
                    var IdentityFilter = "";
                    var Filter = "";
                    if (args.Identity != null)
                    {
                        foreach (var samName in args.Identity)
                        {
                            var IdentityInstance = samName.Replace(@"(", @"\28").Replace(@")", @"\29");
                            if (new Regex(@"^S-1-").Match(IdentityInstance).Success)
                            {
                                IdentityFilter += $@"(objectsid={IdentityInstance})";
                            }
                            else if (new Regex(@"^CN=").Match(IdentityInstance).Success)
                            {
                                IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                                if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                                {
                                    // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                    // and rebuild the domain searcher
                                    var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                    Logger.Write_Verbose($@"[Get-DomainGroup] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                    SearcherArguments.Domain = IdentityDomain;
                                    GroupSearcher = Get_DomainSearcher(SearcherArguments);
                                    if (GroupSearcher == null)
                                    {
                                        Logger.Write_Warning($@"[Get-DomainGroup] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                    }
                                }
                            }
                            else if (new Regex(@"^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$").Match(IdentityInstance).Success)
                            {
                                var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                                IdentityFilter += $@"(objectguid={GuidByteString})";
                            }
                            else if (IdentityInstance.Contains(@"\"))
                            {
                                var ConvertedIdentityInstance = Convert_ADName(new Args_Convert_ADName
                                {
                                    OutputType = ADSNameType.Canonical,
                                    Identity = new string[] { IdentityInstance.Replace(@"\28", @"(").Replace(@"\29", @")") }
                                });
                                if (ConvertedIdentityInstance != null && ConvertedIdentityInstance.Any())
                                {
                                    var GroupDomain = ConvertedIdentityInstance.First().Substring(0, ConvertedIdentityInstance.First().IndexOf('/'));
                                    var GroupName = IdentityInstance.Split(new char[] { '\\' })[1];
                                    IdentityFilter += $@"(samAccountName={GroupName})";
                                    SearcherArguments.Domain = GroupDomain;
                                    Logger.Write_Verbose($@"[Get-DomainUser] Extracted domain '{GroupDomain}' from '{IdentityInstance}'");
                                    GroupSearcher = Get_DomainSearcher(SearcherArguments);
                                }
                            }
                            else
                            {
                                IdentityFilter += $@"(|(samAccountName={IdentityInstance})(name={IdentityInstance}))";
                            }
                        }
                    }

                    if (IdentityFilter != null && IdentityFilter.Trim() != "")
                    {
                        Filter += $@"(|{IdentityFilter})";
                    }

                    if (args.AdminCount)
                    {
                        Logger.Write_Verbose(@"[Get-DomainGroup] Searching for adminCount=1");
                        Filter += "(admincount=1)";
                    }
                    if (args.GroupScope != null)
                    {
                        switch (args.GroupScope.Value)
                        {
                            case GroupScope.DomainLocal:
                                Filter = "(groupType:1.2.840.113556.1.4.803:=4)";
                                break;
                            case GroupScope.NotDomainLocal:
                                Filter = "(!(groupType:1.2.840.113556.1.4.803:=4))";
                                break;
                            case GroupScope.Global:
                                Filter = "(groupType:1.2.840.113556.1.4.803:=2)";
                                break;
                            case GroupScope.NotGlobal:
                                Filter = "(!(groupType:1.2.840.113556.1.4.803:=2))";
                                break;
                            case GroupScope.Universal:
                                Filter = "(groupType:1.2.840.113556.1.4.803:=8)";
                                break;
                            case GroupScope.NotUniversal:
                                Filter = "(!(groupType:1.2.840.113556.1.4.803:=8))";
                                break;
                            default:
                                break;
                        }
                        Logger.Write_Verbose($@"[Get-DomainGroup] Searching for group scope '{args.GroupScope.Value.ToString()}'");
                    }
                    if (args.GroupProperty != null)
                    {
                        switch (args.GroupProperty.Value)
                        {
                            case GroupProperty.Security:
                                Filter = "(groupType:1.2.840.113556.1.4.803:=2147483648)";
                                break;
                            case GroupProperty.Distribution:
                                Filter = "(!(groupType:1.2.840.113556.1.4.803:=2147483648))";
                                break;
                            case GroupProperty.CreatedBySystem:
                                Filter = "(groupType:1.2.840.113556.1.4.803:=1)";
                                break;
                            case GroupProperty.NotCreatedBySystem:
                                Filter = "(!(groupType:1.2.840.113556.1.4.803:=1))";
                                break;
                            default:
                                break;
                        }
                        Logger.Write_Verbose($@"[Get-DomainGroup] Searching for group property '{args.GroupProperty.Value.ToString()}'");
                    }
                    if (args.LDAPFilter.IsNotNullOrEmpty())
                    {
                        Logger.Write_Verbose($@"[Get-DomainGroup] Using additional LDAP filter: {args.LDAPFilter}");
                        Filter += $@"{args.LDAPFilter}";
                    }

                    GroupSearcher.Filter = $@"(&(objectCategory=group){Filter})";
                    Logger.Write_Verbose($@"[Get-DomainGroup] filter string: {GroupSearcher.Filter}");

                    if (args.FindOne)
                    {
                        var result = GroupSearcher.FindOne();
                        if (args.Raw)
                        {
                            // return raw result objects
                            Groups.Add(result);
                        }
                        else
                        {
                            Groups.Add(Convert_LDAPProperty(result.Properties));
                        }
                    }
                    else
                    {
                        var Results = GroupSearcher.FindAll();
                        foreach (SearchResult result in Results)
                        {
                            if (args.Raw)
                            {
                                // return raw result objects
                                Groups.Add(result);
                            }
                            else
                            {
                                Groups.Add(Convert_LDAPProperty(result.Properties));
                            }
                        }
                        if (Results != null)
                        {
                            try { Results.Dispose(); }
                            catch (Exception e)
                            {
                                Logger.Write_Verbose($@"[Get-DomainGroup] Error disposing of the Results object: {e}");
                            }
                        }
                    }
                    GroupSearcher.Dispose();
                }
            }
            return Groups;
        }

        public static IEnumerable<object> Get_NetGroup(Args_Get_DomainGroup args = null)
        {
            return Get_DomainGroup(args);
        }

        private static IEnumerable<string> Parse_Pkt(byte[] Pkt)
        {
            var bin = Pkt;
            var blob_version = BitConverter.ToUInt32(bin.Skip(0).Take(4).ToArray(), 0);
            var blob_element_count = BitConverter.ToUInt32(bin.Skip(4).Take(4).ToArray(), 0);
            var offset = 8;
            string prefix = null;
            string blob_name = null;
            List<string> target_list = null;
            int blob_data_end = 0;
            // https://msdn.microsoft.com/en-us/library/cc227147.aspx
            var object_list = new List<Dictionary<string, object>>();
            for (var i = 1; i <= blob_element_count; i++)
            {
                var blob_name_size_start = offset;
                var blob_name_size_end = offset + 1;
                var blob_name_size = BitConverter.ToUInt16(bin.Skip(blob_name_size_start).Take(blob_name_size_end + 1 - blob_name_size_start).ToArray(), 0);

                var blob_name_start = blob_name_size_end + 1;
                var blob_name_end = blob_name_start + blob_name_size - 1;
                blob_name = System.Text.Encoding.Unicode.GetString(bin.Skip(blob_name_start).Take(blob_name_end + 1 - blob_name_start).ToArray());

                var blob_data_size_start = blob_name_end + 1;
                var blob_data_size_end = blob_data_size_start + 3;
                var blob_data_size = BitConverter.ToUInt32(bin.Skip(blob_data_size_start).Take(blob_data_size_end + 1 - blob_data_size_start).ToArray(), 0);

                var blob_data_start = blob_data_size_end + 1;
                blob_data_end = (int)(blob_data_start + blob_data_size - 1);
                var blob_data = bin.Skip(blob_data_start).Take(blob_data_end + 1 - blob_data_start);
                if (blob_name == @"\siteroot") { }
                else if (blob_name == @"\domainroot*")
                {
                    // Parse DFSNamespaceRootOrLinkBlob object. Starts with variable length DFSRootOrLinkIDBlob which we parse first...
                    // DFSRootOrLinkIDBlob
                    var root_or_link_guid_start = 0;
                    var root_or_link_guid_end = 15;
                    var root_or_link_guid = blob_data.Skip(root_or_link_guid_start).Take(root_or_link_guid_end + 1 - root_or_link_guid_start);
                    var guid = new Guid(root_or_link_guid.ToArray()); // should match $guid_str
                    var prefix_size_start = root_or_link_guid_end + 1;
                    var prefix_size_end = prefix_size_start + 1;
                    var prefix_size = BitConverter.ToUInt16(blob_data.Skip(prefix_size_start).Take(prefix_size_end + 1 - prefix_size_start).ToArray(), 0);
                    var prefix_start = prefix_size_end + 1;
                    var prefix_end = prefix_start + prefix_size - 1;
                    prefix = System.Text.Encoding.Unicode.GetString(blob_data.Skip(prefix_start).Take(prefix_end + 1 - prefix_start).ToArray());

                    var short_prefix_size_start = prefix_end + 1;
                    var short_prefix_size_end = short_prefix_size_start + 1;
                    var short_prefix_size = BitConverter.ToUInt16(blob_data.Skip(short_prefix_size_start).Take(short_prefix_size_end + 1 - short_prefix_size_start).ToArray(), 0);
                    var short_prefix_start = short_prefix_size_end + 1;
                    var short_prefix_end = short_prefix_start + short_prefix_size - 1;
                    var short_prefix = System.Text.Encoding.Unicode.GetString(blob_data.Skip(short_prefix_start).Take(short_prefix_end + 1 - short_prefix_start).ToArray());

                    var type_start = short_prefix_end + 1;
                    var type_end = type_start + 3;
                    var type = BitConverter.ToUInt32(blob_data.Skip(type_start).Take(type_end + 1 - type_start).ToArray(), 0);

                    var state_start = type_end + 1;
                    var state_end = state_start + 3;
                    var state = BitConverter.ToUInt32(blob_data.Skip(state_start).Take(state_end + 1 - state_start).ToArray(), 0);

                    var comment_size_start = state_end + 1;
                    var comment_size_end = comment_size_start + 1;
                    var comment_size = BitConverter.ToUInt16(blob_data.Skip(comment_size_start).Take(comment_size_end + 1 - comment_size_start).ToArray(), 0);
                    var comment_start = comment_size_end + 1;
                    var comment_end = comment_start + comment_size - 1;
                    var comment = "";
                    if (comment_size >= 0)
                    {
                        comment = System.Text.Encoding.Unicode.GetString(blob_data.Skip(comment_start).Take(comment_end + 1 - comment_start).ToArray());
                    }
                    var prefix_timestamp_start = comment_end + 1;
                    var prefix_timestamp_end = prefix_timestamp_start + 7;
                    // https://msdn.microsoft.com/en-us/library/cc230324.aspx FILETIME
                    var prefix_timestamp = blob_data.Skip(prefix_timestamp_start).Take(prefix_timestamp_end + 1 - prefix_timestamp_start); // dword lowDateTime #dword highdatetime
                    var state_timestamp_start = prefix_timestamp_end + 1;
                    var state_timestamp_end = state_timestamp_start + 7;
                    var state_timestamp = blob_data.Skip(state_timestamp_start).Take(state_timestamp_end + 1 - state_timestamp_start);
                    var comment_timestamp_start = state_timestamp_end + 1;
                    var comment_timestamp_end = comment_timestamp_start + 7;
                    var comment_timestamp = blob_data.Skip(comment_timestamp_start).Take(comment_timestamp_end + 1 - comment_timestamp_start);
                    var version_start = comment_timestamp_end + 1;
                    var version_end = version_start + 3;
                    var version = BitConverter.ToUInt32(blob_data.Skip(version_start).Take(version_end + 1 - version_start).ToArray(), 0);

                    // Parse rest of DFSNamespaceRootOrLinkBlob here
                    var dfs_targetlist_blob_size_start = version_end + 1;
                    var dfs_targetlist_blob_size_end = dfs_targetlist_blob_size_start + 3;
                    var dfs_targetlist_blob_size = BitConverter.ToUInt32(blob_data.Skip(dfs_targetlist_blob_size_start).Take(dfs_targetlist_blob_size_end + 1 - dfs_targetlist_blob_size_start).ToArray(), 0);

                    var dfs_targetlist_blob_start = dfs_targetlist_blob_size_end + 1;
                    var dfs_targetlist_blob_end = (int)(dfs_targetlist_blob_start + dfs_targetlist_blob_size - 1);
                    var dfs_targetlist_blob = blob_data.Skip(dfs_targetlist_blob_start).Take(dfs_targetlist_blob_end + 1 - dfs_targetlist_blob_start);
                    var reserved_blob_size_start = dfs_targetlist_blob_end + 1;
                    var reserved_blob_size_end = reserved_blob_size_start + 3;
                    var reserved_blob_size = BitConverter.ToUInt32(blob_data.Skip(reserved_blob_size_start).Take(reserved_blob_size_end + 1 - reserved_blob_size_start).ToArray(), 0);

                    var reserved_blob_start = reserved_blob_size_end + 1;
                    var reserved_blob_end = (int)(reserved_blob_start + reserved_blob_size - 1);
                    var reserved_blob = blob_data.Skip(reserved_blob_start).Take(reserved_blob_end + 1 - reserved_blob_start);
                    var referral_ttl_start = reserved_blob_end + 1;
                    var referral_ttl_end = referral_ttl_start + 3;
                    var referral_ttl = BitConverter.ToUInt32(blob_data.Skip(referral_ttl_start).Take(referral_ttl_end + 1 - referral_ttl_start).ToArray(), 0);

                    // Parse DFSTargetListBlob
                    var target_count_start = 0;
                    var target_count_end = target_count_start + 3;
                    var target_count = BitConverter.ToUInt32(dfs_targetlist_blob.Skip(target_count_start).Take(target_count_end + 1 - target_count_start).ToArray(), 0);
                    var t_offset = target_count_end + 1;

                    for (var j = 1; j <= target_count; j++)
                    {
                        var target_entry_size_start = t_offset;
                        var target_entry_size_end = target_entry_size_start + 3;
                        var target_entry_size = BitConverter.ToUInt32(dfs_targetlist_blob.Skip(target_entry_size_start).Take(target_entry_size_end + 1 - target_entry_size_start).ToArray(), 0);
                        var target_time_stamp_start = target_entry_size_end + 1;
                        var target_time_stamp_end = target_time_stamp_start + 7;
                        // FILETIME again or special if priority rank and priority class 0
                        var target_time_stamp = dfs_targetlist_blob.Skip(target_time_stamp_start).Take(target_time_stamp_end + 1 - target_time_stamp_start);
                        var target_state_start = target_time_stamp_end + 1;
                        var target_state_end = target_state_start + 3;
                        var target_state = BitConverter.ToUInt32(dfs_targetlist_blob.Skip(target_state_start).Take(target_state_end + 1 - target_state_start).ToArray(), 0);

                        var target_type_start = target_state_end + 1;
                        var target_type_end = target_type_start + 3;
                        var target_type = BitConverter.ToUInt32(dfs_targetlist_blob.Skip(target_type_start).Take(target_type_end + 1 - target_type_start).ToArray(), 0);

                        var server_name_size_start = target_type_end + 1;
                        var server_name_size_end = server_name_size_start + 1;
                        var server_name_size = BitConverter.ToUInt16(dfs_targetlist_blob.Skip(server_name_size_start).Take(server_name_size_end + 1 - server_name_size_start).ToArray(), 0);

                        var server_name_start = server_name_size_end + 1;
                        var server_name_end = server_name_start + server_name_size - 1;
                        var server_name = System.Text.Encoding.Unicode.GetString(dfs_targetlist_blob.Skip(server_name_start).Take(server_name_end + 1 - server_name_start).ToArray());

                        var share_name_size_start = server_name_end + 1;
                        var share_name_size_end = share_name_size_start + 1;
                        var share_name_size = BitConverter.ToUInt16(dfs_targetlist_blob.Skip(share_name_size_start).Take(share_name_size_end + 1 - share_name_size_start).ToArray(), 0);
                        var share_name_start = share_name_size_end + 1;
                        var share_name_end = share_name_start + share_name_size - 1;
                        var share_name = System.Text.Encoding.Unicode.GetString(dfs_targetlist_blob.Skip(share_name_start).Take(share_name_end + 1 - share_name_start).ToArray());

                        if (target_list == null)
                            target_list = new List<string>();
                        target_list.Add($@"\\{server_name}\{share_name}");
                        t_offset = share_name_end + 1;
                    }
                }
                offset = blob_data_end + 1;
                var dfs_pkt_properties = new Dictionary<string, object>
            {
                { @"Name", blob_name },
                    { @"Prefix", prefix },
                    { @"TargetList", target_list }
            };
                object_list.Add(dfs_pkt_properties);
                prefix = null;
                blob_name = null;
                target_list = null;
            }

            var servers = new List<string>();
            if (object_list != null)
            {
                foreach (var item in object_list)
                {
                    var targetList = item[@"TargetList"] as string[];
                    if (targetList != null)
                    {
                        foreach (var target in targetList)
                        {
                            servers.Add(target.Split(new char[] { '\\' })[2]);
                        }
                    }
                }
            }

            return servers;
        }

        private static IEnumerable<DFSShare> Get_DomainDFSShareV1(Args_Get_DomainSearcher args = null)
        {
            if (args == null) args = new Args_Get_DomainSearcher();

            var DFSSearcher = Get_DomainSearcher(args);

            if (DFSSearcher != null)
            {
                var DFSShares = new List<DFSShare>();
                ResultPropertyCollection Properties = null;
                DFSSearcher.Filter = @"(&(objectClass=fTDfs))";

                try
                {
                    ResultPropertyValueCollection Pkt = null;
                    var Results = DFSSearcher.FindAll();
                    if (Results != null)
                    {
                        foreach (SearchResult result in Results)
                        {
                            Properties = result.Properties;
                            var RemoteNames = Properties[@"remoteservername"];
                            Pkt = Properties[@"pkt"];

                            if (RemoteNames != null)
                            {
                                foreach (string name in RemoteNames)
                                {
                                    try
                                    {
                                        if (name.Contains(@"\"))
                                        {

                                            DFSShares.Add(new DFSShare
                                            {
                                                Name = Properties[@"name"][0] as string,
                                                RemoteServerName = name.Split(new char[] { '\\' })[2]
                                            });
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        Logger.Write_Verbose($@"[Get-DomainDFSShare] Get-DomainDFSShareV1 error in parsing DFS share : {e}");
                                    }
                                }
                            }
                            try { Results.Dispose(); }
                            catch (Exception e)
                            {
                                Logger.Write_Verbose($@"[Get-DomainDFSShare] Get-DomainDFSShareV1 error disposing of the Results object: {e}");
                            }
                        }

                        DFSSearcher.Dispose();

                        if (Pkt != null && Pkt[0] != null)
                        {
                            var servers = Parse_Pkt(Pkt[0] as byte[]);
                            if (servers != null)
                            {
                                foreach (var server in servers)
                                {
                                    // If a folder doesn't have a redirection it will have a target like
                                    // \\null\TestNameSpace\folder\.DFSFolderLink so we do actually want to match
                                    // on 'null' rather than $Null
                                    if (server != null && server != @"null" &&
                                        DFSShares.Any(x => x.RemoteServerName == server))
                                    {
                                        DFSShares.Add(new DFSShare { Name = Properties[@"name"][0] as string, RemoteServerName = server });
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[Get-DomainDFSShare] Get-DomainDFSShareV1 error : {e}");
                }
                return DFSShares;
            }
            return null;
        }

        private static IEnumerable<DFSShare> Get_DomainDFSShareV2(Args_Get_DomainSearcher args = null)
        {
            if (args == null) args = new Args_Get_DomainSearcher();

            var DFSSearcher = Get_DomainSearcher(args);

            if (DFSSearcher != null)
            {
                var DFSShares = new List<DFSShare>();
                ResultPropertyCollection Properties = null;
                DFSSearcher.Filter = @"(&(objectClass=msDFS-Linkv2))";
                DFSSearcher.PropertiesToLoad.AddRange(new string[] { @"msdfs-linkpathv2", @"msDFS-TargetListv2" });

                try
                {
                    var Results = DFSSearcher.FindAll();
                    if (Results != null)
                    {
                        foreach (SearchResult result in Results)
                        {
                            Properties = result.Properties;
                            var target_list = Properties[@"msdfs-targetlistv2"][0] as byte[];
                            var xml = new XmlDocument();
                            xml.LoadXml(System.Text.Encoding.Unicode.GetString(target_list.Skip(2).Take(target_list.Length - 1 + 1 - 2).ToArray()));
                            if (xml.FirstChild != null)
                            {
                                foreach (XmlNode node in xml.FirstChild.ChildNodes)
                                {
                                    try
                                    {
                                        var Target = node.InnerText;
                                        if (Target.Contains(@"\"))
                                        {
                                            var DFSroot = Target.Split('\\')[3];
                                            var ShareName = Properties[@"msdfs-linkpathv2"][0] as string;
                                            DFSShares.Add(new DFSShare { Name = $@"{DFSroot}{ShareName}", RemoteServerName = Target.Split('\\')[2] });
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        Logger.Write_Verbose($@"[Get-DomainDFSShare] Get-DomainDFSShareV2 error in parsing target : {e}");
                                    }
                                }
                            }
                        }
                        try { Results.Dispose(); }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-DomainDFSShare] Error disposing of the Results object: {e}");
                        }
                    }
                    DFSSearcher.Dispose();
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[Get-DomainDFSShare] Get-DomainDFSShareV2 error : {e}");
                }
                return DFSShares;
            }
            return null;
        }

        public static IEnumerable<DFSShare> Get_DomainDFSShare(Args_Get_DomainDFSShare args = null)
        {
            if (args == null) args = new Args_Get_DomainDFSShare();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var DFSShares = new List<DFSShare>();

            if (args.Domain != null)
            {
                foreach (var TargetDomain in args.Domain)
                {
                    SearcherArguments.Domain = TargetDomain;
                    if (args.Version == Enums.Version.All || args.Version == Enums.Version.V1)
                    {
                        DFSShares.AddRange(Get_DomainDFSShareV1(SearcherArguments));
                    }
                    if (args.Version == Enums.Version.All || args.Version == Enums.Version.V2)
                    {
                        DFSShares.AddRange(Get_DomainDFSShareV2(SearcherArguments));
                    }
                }
            }
            else
            {
                if (args.Version == Enums.Version.All || args.Version == Enums.Version.V1)
                {
                    DFSShares.AddRange(Get_DomainDFSShareV1(SearcherArguments));
                }
                if (args.Version == Enums.Version.All || args.Version == Enums.Version.V2)
                {
                    DFSShares.AddRange(Get_DomainDFSShareV2(SearcherArguments));
                }
            }

            return DFSShares;
        }

        public static IEnumerable<DFSShare> Get_DFSshare(Args_Get_DomainDFSShare args = null)
        {
            return Get_DomainDFSShare(args);
        }

        private static string Get_Name(byte[] Raw)
        {
            int Length = Raw[0];
            int Segments = Raw[1];
            int Index = 2;
            string Name = "";

            while (Segments-- > 0)
            {
                int SegmentLength = Raw[Index++];
                while (SegmentLength-- > 0)
                {
                    Name += (char)Raw[Index++];
                }
                Name += ".";
            }
            return Name;
        }

        private static DNSRecord Convert_DNSRecord(byte[] DNSRecord)
        {
            // $RDataLen = [BitConverter]::ToUInt16($DNSRecord, 0)
            var RDataType = BitConverter.ToUInt16(DNSRecord, 2);
            var UpdatedAtSerial = BitConverter.ToUInt32(DNSRecord, 8);

            var TTLRaw = DNSRecord.Skip(12).Take(15 + 1 - 12);

            // reverse for big endian
            TTLRaw = TTLRaw.Reverse();
            var TTL = BitConverter.ToUInt32(TTLRaw.ToArray(), 0);

            var Age = BitConverter.ToUInt32(DNSRecord, 20);
            string TimeStamp = null;
            if (Age != 0)
            {
                TimeStamp = (new DateTime(1601, 1, 1, 0, 0, 0).AddHours(Age)).ToString();
            }
            else
            {
                TimeStamp = @"[static]";
            }

            var DNSRecordObject = new DNSRecord();
            string Data = null;

            if (RDataType == 1)
            {
                var IP = string.Format(@"{0}.{1}.{2}.{3}", DNSRecord[24], DNSRecord[25], DNSRecord[26], DNSRecord[27]);
                Data = IP;
                DNSRecordObject.RecordType = DnsRecordType.A;
            }

            else if (RDataType == 2)
            {
                var NSName = Get_Name(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                Data = NSName;
                DNSRecordObject.RecordType = DnsRecordType.NS;
            }

            else if (RDataType == 5)
            {
                var Alias = Get_Name(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                Data = Alias;
                DNSRecordObject.RecordType = DnsRecordType.CNAME;
            }

            else if (RDataType == 6)
            {
                // TODO: how to implement properly? nested object?
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.SOA;
            }

            else if (RDataType == 12)
            {
                var Ptr = Get_Name(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                Data = Ptr;
                DNSRecordObject.RecordType = DnsRecordType.PTR;
            }

            else if (RDataType == 13)
            {
                // TODO: how to implement properly? nested object?
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.HINFO;
            }

            else if (RDataType == 15)
            {
                // TODO: how to implement properly? nested object?
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.MX;
            }

            else if (RDataType == 16)
            {
                var TXT = "";
                int SegmentLength = DNSRecord[24];
                var Index = 25;

                while (SegmentLength-- > 0)
                {
                    TXT += (char)DNSRecord[Index++];
                }

                Data = TXT;
                DNSRecordObject.RecordType = DnsRecordType.TXT;
            }

            else if (RDataType == 28)
            {
                // TODO: how to implement properly? nested object?
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.AAAA;
            }

            else if (RDataType == 33)
            {
                // TODO: how to implement properly? nested object?
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.SRV;
            }

            else
            {
                Data = System.Convert.ToBase64String(DNSRecord.Skip(24).Take(DNSRecord.Length + 1 - 24).ToArray());
                DNSRecordObject.RecordType = DnsRecordType.UNKNOWN;
            }

            DNSRecordObject.UpdatedAtSerial = UpdatedAtSerial;
            DNSRecordObject.TTL = TTL;
            DNSRecordObject.Age = Age;
            DNSRecordObject.TimeStamp = TimeStamp;
            DNSRecordObject.Data = Data;
            return DNSRecordObject;
        }

        public static IEnumerable<DNSRecord> Get_DomainDNSRecord(Args_Get_DomainDNSRecord args = null)
        {
            if (args == null) args = new Args_Get_DomainDNSRecord();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                LDAPFilter = @"(objectClass=dnsNode)",
                SearchBasePrefix = $@"DC={args.ZoneName},CN=MicrosoftDNS,DC=DomainDnsZones",
                Domain = args.Domain,
                Server = args.Server,
                Properties = args.Properties,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Credential = args.Credential
            };
            var DNSSearcher = Get_DomainSearcher(SearcherArguments);

            SearchResult[] Results = null;
            List<DNSRecord> Outs = null;
            if (DNSSearcher != null)
            {
                if (args.FindOne) { Results = new SearchResult[] { DNSSearcher.FindOne() }; }
                else
                {
                    var items = DNSSearcher.FindAll();
                    if (items != null)
                    {
                        Results = new SearchResult[items.Count];
                        items.CopyTo(Results, 0);
                    }
                }
                if (Results != null)
                {
                    foreach (var result in Results)
                    {
                        DNSRecord Out = null;
                        try
                        {
                            var ldapProperty = Convert_LDAPProperty(result.Properties);
                            Out = new DNSRecord
                            {
                                name = ldapProperty.name,
                                distinguishedname = ldapProperty.distinguishedname,
                                dnsrecord = ldapProperty.dnsrecord,
                                whencreated = ldapProperty.whencreated,
                                whenchanged = ldapProperty.whenchanged,
                                ZoneName = args.ZoneName
                            };

                            // convert the record and extract the properties
                            DNSRecord Record = null;
                            if (Out.dnsrecord is System.DirectoryServices.ResultPropertyValueCollection)
                            {
                                // TODO: handle multiple nested records properly?
                                Record = Convert_DNSRecord((Out.dnsrecord as System.DirectoryServices.ResultPropertyValueCollection)[0] as byte[]);
                            }
                            else
                            {
                                Record = Convert_DNSRecord(Out.dnsrecord as byte[]);
                            }

                            if (Record != null)
                            {
                                if (Record.RecordType != null)
                                    Out.RecordType = Record.RecordType;
                                else if (Record.UpdatedAtSerial != null)
                                    Out.UpdatedAtSerial = Record.UpdatedAtSerial;
                                else if (Record.TTL != null)
                                    Out.TTL = Record.TTL;
                                else if (Record.Age != null)
                                    Out.Age = Record.Age;
                                else if (Record.TimeStamp != null)
                                    Out.TimeStamp = Record.TimeStamp;
                                else if (Record.Data.IsNotNullOrEmpty())
                                    Out.Data = Record.Data;
                                else if (Record.ZoneName.IsNotNullOrEmpty())
                                    Out.ZoneName = Record.ZoneName;
                                else if (Record.name.IsNotNullOrEmpty())
                                    Out.name = Record.name;
                                else if (Record.distinguishedname.IsNotNullOrEmpty())
                                    Out.distinguishedname = Record.distinguishedname;
                                else if (Record.dnsrecord != null)
                                    Out.dnsrecord = Record.dnsrecord;
                                else if (Record.whencreated != null)
                                    Out.whencreated = Record.whencreated;
                                else if (Record.whenchanged != null)
                                    Out.whenchanged = Record.whenchanged;
                            }
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Warning($@"[Get-DomainDNSRecord] Error: {e}");
                        }
                        if (Outs == null) Outs = new List<DNSRecord>();
                        Outs.Add(Out);
                    }
                }
                DNSSearcher.Dispose();
            }
            return Outs;
        }

        public static IEnumerable<DNSRecord> Get_DNSRecord(Args_Get_DomainDNSRecord args = null)
        {
            return Get_DomainDNSRecord(args);
        }

        public static IEnumerable<DNSZone> Get_DomainDNSZone(Args_Get_DomainDNSZone args = null)
        {
            if (args == null) args = new Args_Get_DomainDNSZone();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                LDAPFilter = @"(objectClass=dnsZone)",
                Domain = args.Domain,
                Server = args.Server,
                Properties = args.Properties,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Credential = args.Credential
            };
            var DNSSearcher1 = Get_DomainSearcher(SearcherArguments);

            SearchResult[] Results = null;
            List<DNSZone> Outs = null;
            if (DNSSearcher1 != null)
            {
                if (args.FindOne) { Results = new SearchResult[] { DNSSearcher1.FindOne() }; }
                else
                {
                    var items = DNSSearcher1.FindAll();
                    if (items != null)
                    {
                        Results = new SearchResult[items.Count];
                        items.CopyTo(Results, 0);
                    }
                }
                if (Results != null)
                {
                    foreach (var result in Results)
                    {
                        var Out = new DNSZone(Convert_LDAPProperty(result.Properties));
                        Outs.Add(Out);
                    }
                }
                DNSSearcher1.Dispose();
            }

            SearcherArguments.SearchBasePrefix = @"CN=MicrosoftDNS,DC=DomainDnsZones";
            var DNSSearcher2 = Get_DomainSearcher(SearcherArguments);

            if (DNSSearcher2 != null)
            {
                try
                {
                    if (args.FindOne) { Results = new SearchResult[] { DNSSearcher2.FindOne() }; }
                    else
                    {
                        var items = DNSSearcher2.FindAll();
                        if (items != null)
                        {
                            Results = new SearchResult[items.Count];
                            items.CopyTo(Results, 0);
                        }
                    }
                    if (Results != null)
                    {
                        foreach (var result in Results)
                        {
                            var Out = new DNSZone(Convert_LDAPProperty(result.Properties));
                            Outs.Add(Out);
                        }
                    }
                }
                catch
                {
                    Logger.Write_Verbose(@"[Get-DomainDNSZone] Error accessing 'CN=MicrosoftDNS,DC=DomainDnsZones'");
                }
                DNSSearcher2.Dispose();
            }
            return Outs;
        }

        public static IEnumerable<DNSZone> Get_DNSZone(Args_Get_DomainDNSZone args = null)
        {
            return Get_DomainDNSZone(args);
        }

        public static IEnumerable<ForeignGroupMember> Get_DomainForeignGroupMember(Args_Get_DomainForeignGroupMember args = null)
        {
            if (args == null) args = new Args_Get_DomainForeignGroupMember();

            var SearcherArguments = new Args_Get_DomainGroup
            {
                LDAPFilter = @"(member=*)",
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            // standard group names to ignore
            var ExcludeGroups = new string[] { @"Users", @"Domain Users", @"Guests" };

            var ForeignGroupMembers = new List<ForeignGroupMember>();
            var Results = Get_DomainGroup(SearcherArguments);
            Results = Results.Where(x => !ExcludeGroups.Contains((x as LDAPProperty).samaccountname));
            foreach (LDAPProperty result in Results)
            {
                var GroupName = result.samaccountname;
                var GroupDistinguishedName = result.distinguishedname;
                var GroupDomain = GroupDistinguishedName.Substring(GroupDistinguishedName.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");

                if (result.member != null)
                {
                    foreach (var item in result.member)
                    {
                        // filter for foreign SIDs in the cn field for users in another domain,
                        //   or if the DN doesn't end with the proper DN for the queried domain
                        var MemberDomain = item.Substring(item.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                        if (new Regex(@"CN=S-1-5-21.*-.*").Match(item).Success || GroupDomain != MemberDomain)
                        {
                            var MemberDistinguishedName = item;
                            var MemberName = item.Split(',')[0].Split('=')[1];

                            var ForeignGroupMember = new ForeignGroupMember
                            {
                                GroupDomain = GroupDomain,
                                GroupName = GroupName,
                                GroupDistinguishedName = GroupDistinguishedName,
                                MemberDomain = MemberDomain,
                                MemberName = MemberName,
                                MemberDistinguishedName = MemberDistinguishedName
                            };
                        }
                    }
                }
            }
            return ForeignGroupMembers;
        }

        public static IEnumerable<ForeignGroupMember> Find_ForeignGroup(Args_Get_DomainForeignGroupMember args = null)
        {
            return Get_DomainForeignGroupMember(args);
        }

        public static IEnumerable<ForeignUser> Get_DomainForeignUser(Args_Get_DomainForeignUser args = null)
        {
            if (args == null) args = new Args_Get_DomainForeignUser();

            var SearcherArguments = new Args_Get_DomainUser
            {
                LDAPFilter = @"(memberof=*)",
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ForeignUsers = new List<ForeignUser>();
            var Results = Get_DomainUser(SearcherArguments);
            foreach (LDAPProperty result in Results)
            {
                foreach (var Membership in result.memberof)
                {
                    var Index = Membership.IndexOf(@"DC=");
                    if (Index != 0)
                    {
                        var GroupDomain = Membership.Substring(Index).Replace(@"DC=", @"").Replace(@",", @".");
                        var UserDistinguishedName = result.distinguishedname;
                        var UserIndex = UserDistinguishedName.IndexOf(@"DC=");
                        var UserDomain = result.distinguishedname.Substring(UserIndex).Replace(@"DC=", @"").Replace(@",", @".");

                        if (GroupDomain != UserDomain)
                        {
                            // if the group domain doesn't match the user domain, display it
                            var GroupName = Membership.Split(',')[0].Split('=')[1];
                            var ForeignUser = new ForeignUser
                            {
                                UserDomain = UserDomain,
                                UserName = result.samaccountname,
                                UserDistinguishedName = result.distinguishedname,
                                GroupDomain = GroupDomain,
                                GroupName = GroupName,
                                GroupDistinguishedName = Membership
                            };
                        }
                    }
                }
            }
            return ForeignUsers;
        }

        public static IEnumerable<ForeignUser> Find_ForeignUser(Args_Get_DomainForeignUser args = null)
        {
            return Get_DomainForeignUser(args);
        }

        public static IEnumerable<string> ConvertFrom_SID(Args_ConvertFrom_SID args = null)
        {
            if (args == null) args = new Args_ConvertFrom_SID();

            var ADNameArguments = new Args_Convert_ADName
            {
                Domain = args.Domain,
                Server = args.Server,
                Credential = args.Credential
            };

            var Results = new List<string>();
            foreach (var TargetSid in args.ObjectSID)
            {
                var trimedTargetSid = TargetSid.Trim('*');
                try
                {
                    // try to resolve any built-in SIDs first - https://support.microsoft.com/en-us/kb/243330

                    if (trimedTargetSid == @"S-1-0") { Results.Add(@"Null Authority"); }
                    else if (trimedTargetSid == @"S -1-0-0") { Results.Add(@"Nobody"); }
                    else if (trimedTargetSid == @"S-1-1") { Results.Add(@"World Authority"); }
                    else if (trimedTargetSid == @"S-1-1-0") { Results.Add(@"Everyone"); }
                    else if (trimedTargetSid == @"S-1-2") { Results.Add(@"Local Authority"); }
                    else if (trimedTargetSid == @"S-1-2-0") { Results.Add(@"Local"); }
                    else if (trimedTargetSid == @"S-1-2-1") { Results.Add(@"Console Logon "); }
                    else if (trimedTargetSid == @"S-1-3") { Results.Add(@"Creator Authority"); }
                    else if (trimedTargetSid == @"S-1-3-0") { Results.Add(@"Creator Owner"); }
                    else if (trimedTargetSid == @"S-1-3-1") { Results.Add(@"Creator Group"); }
                    else if (trimedTargetSid == @"S-1-3-2") { Results.Add(@"Creator Owner Server"); }
                    else if (trimedTargetSid == @"S-1-3-3") { Results.Add(@"Creator Group Server"); }
                    else if (trimedTargetSid == @"S-1-3-4") { Results.Add(@"Owner Rights"); }
                    else if (trimedTargetSid == @"S-1-4") { Results.Add(@"Non-unique Authority"); }
                    else if (trimedTargetSid == @"S-1-5") { Results.Add(@"NT Authority"); }
                    else if (trimedTargetSid == @"S-1-5-1") { Results.Add(@"Dialup"); }
                    else if (trimedTargetSid == @"S-1-5-2") { Results.Add(@"Network"); }
                    else if (trimedTargetSid == @"S-1-5-3") { Results.Add(@"Batch"); }
                    else if (trimedTargetSid == @"S-1-5-4") { Results.Add(@"Interactive"); }
                    else if (trimedTargetSid == @"S-1-5-6") { Results.Add(@"Service"); }
                    else if (trimedTargetSid == @"S-1-5-7") { Results.Add(@"Anonymous"); }
                    else if (trimedTargetSid == @"S-1-5-8") { Results.Add(@"Proxy"); }
                    else if (trimedTargetSid == @"S-1-5-9") { Results.Add(@"Enterprise Domain Controllers"); }
                    else if (trimedTargetSid == @"S-1-5-10") { Results.Add(@"Principal Self"); }
                    else if (trimedTargetSid == @"S-1-5-11") { Results.Add(@"Authenticated Users"); }
                    else if (trimedTargetSid == @"S-1-5-12") { Results.Add(@"Restricted Code"); }
                    else if (trimedTargetSid == @"S-1-5-13") { Results.Add(@"Terminal Server Users"); }
                    else if (trimedTargetSid == @"S-1-5-14") { Results.Add(@"Remote Interactive Logon"); }
                    else if (trimedTargetSid == @"S-1-5-15") { Results.Add(@"This Organization "); }
                    else if (trimedTargetSid == @"S-1-5-17") { Results.Add(@"This Organization "); }
                    else if (trimedTargetSid == @"S-1-5-18") { Results.Add(@"Local System"); }
                    else if (trimedTargetSid == @"S-1-5-19") { Results.Add(@"NT Authority"); }
                    else if (trimedTargetSid == @"S-1-5-20") { Results.Add(@"NT Authority"); }
                    else if (trimedTargetSid == @"S-1-5-80-0") { Results.Add(@"All Services "); }
                    else if (trimedTargetSid == @"S-1-5-32-544") { Results.Add(@"BUILTIN\Administrators"); }
                    else if (trimedTargetSid == @"S-1-5-32-545") { Results.Add(@"BUILTIN\Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-546") { Results.Add(@"BUILTIN\Guests"); }
                    else if (trimedTargetSid == @"S-1-5-32-547") { Results.Add(@"BUILTIN\Power Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-548") { Results.Add(@"BUILTIN\Account Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-549") { Results.Add(@"BUILTIN\Server Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-550") { Results.Add(@"BUILTIN\Print Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-551") { Results.Add(@"BUILTIN\Backup Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-552") { Results.Add(@"BUILTIN\Replicators"); }
                    else if (trimedTargetSid == @"S-1-5-32-554") { Results.Add(@"BUILTIN\Pre-Windows 2000 Compatible Access"); }
                    else if (trimedTargetSid == @"S-1-5-32-555") { Results.Add(@"BUILTIN\Remote Desktop Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-556") { Results.Add(@"BUILTIN\Network Configuration Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-557") { Results.Add(@"BUILTIN\Incoming Forest Trust Builders"); }
                    else if (trimedTargetSid == @"S-1-5-32-558") { Results.Add(@"BUILTIN\Performance Monitor Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-559") { Results.Add(@"BUILTIN\Performance Log Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-560") { Results.Add(@"BUILTIN\Windows Authorization Access Group"); }
                    else if (trimedTargetSid == @"S-1-5-32-561") { Results.Add(@"BUILTIN\Terminal Server License Servers"); }
                    else if (trimedTargetSid == @"S-1-5-32-562") { Results.Add(@"BUILTIN\Distributed COM Users"); }
                    else if (trimedTargetSid == @"S-1-5-32-569") { Results.Add(@"BUILTIN\Cryptographic Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-573") { Results.Add(@"BUILTIN\Event Log Readers"); }
                    else if (trimedTargetSid == @"S-1-5-32-574") { Results.Add(@"BUILTIN\Certificate Service DCOM Access"); }
                    else if (trimedTargetSid == @"S-1-5-32-575") { Results.Add(@"BUILTIN\RDS Remote Access Servers"); }
                    else if (trimedTargetSid == @"S-1-5-32-576") { Results.Add(@"BUILTIN\RDS Endpoint Servers"); }
                    else if (trimedTargetSid == @"S-1-5-32-577") { Results.Add(@"BUILTIN\RDS Management Servers"); }
                    else if (trimedTargetSid == @"S-1-5-32-578") { Results.Add(@"BUILTIN\Hyper-V Administrators"); }
                    else if (trimedTargetSid == @"S-1-5-32-579") { Results.Add(@"BUILTIN\Access Control Assistance Operators"); }
                    else if (trimedTargetSid == @"S-1-5-32-580") { Results.Add(@"BUILTIN\Access Control Assistance Operators"); }
                    else
                    {
                        ADNameArguments.Identity = new string[] { TargetSid };
                        Results.AddRange(Convert_ADName(ADNameArguments));
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[ConvertFrom-SID] Error converting SID '{TargetSid}' : {e}");
                }
            }
            return Results;
        }

        public static IEnumerable<string> Convert_SidToName(Args_ConvertFrom_SID args = null)
        {
            return ConvertFrom_SID(args);
        }

        public static IEnumerable<GroupMember> Get_DomainGroupMember(Args_Get_DomainGroupMember args = null)
        {
            if (args == null) args = new Args_Get_DomainGroupMember();

            var SearcherArguments = new Args_Get_DomainSearcher()
            {
                Properties = new string[] { @"member", @"samaccountname", @"distinguishedname" },
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ADNameArguments = new Args_Convert_ADName
            {
                Domain = args.Domain,
                Server = args.Server,
                Credential = args.Credential
            };

            var GroupMembers = new List<GroupMember>();
            var GroupSearcher = Get_DomainSearcher(SearcherArguments);
            if (GroupSearcher != null)
            {
                string GroupFoundDomain = null;
                string GroupFoundName = null;
                string GroupFoundDN = null;
                List<string> Members = null;
                if (args.RecurseUsingMatchingRule)
                {
                    var GroupArguments = new Args_Get_DomainGroup()
                    {
                        Properties = SearcherArguments.Properties,
                        Domain = SearcherArguments.Domain,
                        LDAPFilter = SearcherArguments.LDAPFilter,
                        SearchBase = SearcherArguments.SearchBase,
                        Server = SearcherArguments.Server,
                        SearchScope = SearcherArguments.SearchScope,
                        ResultPageSize = SearcherArguments.ResultPageSize,
                        ServerTimeLimit = SearcherArguments.ServerTimeLimit,
                        Tombstone = SearcherArguments.Tombstone,
                        Credential = SearcherArguments.Credential,
                        Identity = args.Identity,
                        Raw = true
                    };
                    var Groups = Get_DomainGroup(GroupArguments);

                    if (Groups == null)
                    {
                        Logger.Write_Warning($@"[Get-DomainGroupMember] Error searching for group with identity: {args.Identity}");
                    }
                    else
                    {
                        var Group = Groups.First() as SearchResult;
                        GroupFoundName = Group.Properties[@"samaccountname"][0] as string;
                        GroupFoundDN = Group.Properties[@"distinguishedname"][0] as string;
                        if (args.Domain.IsNotNullOrEmpty())
                        {
                            GroupFoundDomain = args.Domain;
                        }
                        else
                        {
                            // if a domain isn't passed, try to extract it from the found group distinguished name
                            if (GroupFoundDN.IsNotNullOrEmpty())
                            {
                                GroupFoundDomain = GroupFoundDN.Substring(GroupFoundDN.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                            }
                        }
                        Logger.Write_Verbose($@"[Get-DomainGroupMember] Using LDAP matching rule to recurse on '{GroupFoundDN}', only user accounts will be returned.");
                        GroupSearcher.Filter = $@"(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:={GroupFoundDN}))";
                        GroupSearcher.PropertiesToLoad.AddRange(new string[] { @"distinguishedName" });
                        var Results = GroupSearcher.FindAll();
                        if (Results != null)
                        {
                            Members = new List<string>();
                            foreach (SearchResult result in Results)
                            {
                                Members.Add(result.Properties[@"distinguishedname"][0] as string);
                            }
                        }
                    }
                }
                else
                {
                    var IdentityFilter = @"";
                    var Filter = @"";
                    if (args.Identity != null)
                    {
                        foreach (var item in args.Identity)
                        {
                            var IdentityInstance = item.Replace(@"(", @"\28").Replace(@")", @"\29");
                            if (new Regex(@"^S-1-").Match(IdentityInstance).Success)
                            {
                                IdentityFilter += $@"(objectsid={IdentityInstance})";
                            }
                            else if (new Regex(@"^CN=").Match(IdentityInstance).Success)
                            {
                                IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                                if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                                {
                                    // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                    //   and rebuild the domain searcher
                                    var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"".Replace(@",", @"."));
                                    Logger.Write_Verbose($@"[Get-DomainGroupMember] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                    SearcherArguments.Domain = IdentityDomain;
                                    GroupSearcher = Get_DomainSearcher(SearcherArguments);
                                    if (GroupSearcher == null)
                                    {
                                        Logger.Write_Warning($@"[Get-DomainGroupMember] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                    }
                                }
                            }
                            else if (new Regex(@"^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$").Match(IdentityInstance).Success)
                            {
                                var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                                IdentityFilter += $@"(objectguid={GuidByteString})";
                            }
                            else if (IdentityInstance.Contains(@"\"))
                            {
                                var ConvertedIdentityInstance = Convert_ADName(new Args_Convert_ADName
                                {
                                    OutputType = ADSNameType.Canonical,
                                    Identity = new string[] { IdentityInstance.Replace(@"\28", @"(").Replace(@"\29", @")") }
                                });
                                if (ConvertedIdentityInstance != null && ConvertedIdentityInstance.Any())
                                {
                                    var GroupDomain = ConvertedIdentityInstance.First().Substring(0, ConvertedIdentityInstance.First().IndexOf('/'));
                                    var GroupName = IdentityInstance.Split(new char[] { '\\' })[1];
                                    IdentityFilter += $@"(samAccountName={GroupName})";
                                    SearcherArguments.Domain = GroupDomain;
                                    Logger.Write_Verbose($@"[Get-DomainGroupMember] Extracted domain '{GroupDomain}' from '{IdentityInstance}'");
                                    GroupSearcher = Get_DomainSearcher(SearcherArguments);
                                }
                            }
                            else
                            {
                                IdentityFilter += $@"(samAccountName={IdentityInstance})";
                            }
                        }
                    }

                    if (IdentityFilter != null && IdentityFilter.Trim() != @"")
                    {
                        Filter += $@"(|{IdentityFilter})";
                    }

                    if (args.LDAPFilter.IsNotNullOrEmpty())
                    {
                        Logger.Write_Verbose($@"[Get-DomainGroupMember] Using additional LDAP filter: {args.LDAPFilter}");
                        Filter += $@"{args.LDAPFilter}";
                    }

                    GroupSearcher.Filter = $@"(&(objectCategory=group){Filter})";
                    Logger.Write_Verbose($@"[Get-DomainGroupMember] Get-DomainGroupMember filter string: {GroupSearcher.Filter}");
                    SearchResult Result = null;
                    try
                    {
                        Result = GroupSearcher.FindOne();
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Warning($@"[Get-DomainGroupMember] Error searching for group with identity '{args.Identity}': {e}");
                        Members = new List<string>();
                    }

                    GroupFoundName = @"";
                    GroupFoundDN = @"";

                    if (Result != null)
                    {
                        var tmpProperty = Result.Properties[@"member"];
                        var tmpValues = new string[tmpProperty.Count];
                        tmpProperty.CopyTo(tmpValues, 0);
                        Members = tmpValues.ToList();
                        string RangedProperty = "";

                        if (Members.Count == 0)
                        {
                            // ranged searching, thanks @meatballs__ !
                            var Finished = false;
                            var Bottom = 0;
                            var Top = 0;

                            while (!Finished)
                            {
                                Top = Bottom + 1499;
                                var MemberRange = $@"member;range={Bottom}-{Top}";
                                Bottom += 1500;
                                GroupSearcher.PropertiesToLoad.Clear();
                                GroupSearcher.PropertiesToLoad.Add($@"{MemberRange}");
                                GroupSearcher.PropertiesToLoad.Add(@"samaccountname");
                                GroupSearcher.PropertiesToLoad.Add(@"distinguishedname");

                                try
                                {
                                    Result = GroupSearcher.FindOne();
                                    RangedProperty = Result.Properties.PropertyNames.GetFirstMatch(@"member;range=*");
                                    tmpProperty = Result.Properties[RangedProperty];
                                    tmpValues = new string[tmpProperty.Count];
                                    tmpProperty.CopyTo(tmpValues, 0);
                                    Members.AddRange(tmpValues.ToList());
                                    GroupFoundName = Result.Properties[@"samaccountname"][0] as string;
                                    GroupFoundDN = Result.Properties[@"distinguishedname"][0] as string;

                                    if (Members.Count == 0)
                                    {
                                        Finished = true;
                                    }
                                }
                                catch
                                {
                                    Finished = true;
                                }
                            }
                        }
                        else
                        {
                            GroupFoundName = Result.Properties[@"samaccountname"][0] as string;
                            GroupFoundDN = Result.Properties[@"distinguishedname"][0] as string;
                            tmpProperty = Result.Properties[RangedProperty];
                            tmpValues = new string[tmpProperty.Count];
                            tmpProperty.CopyTo(tmpValues, 0);
                            Members.AddRange(tmpValues.ToList());
                        }

                        if (args.Domain.IsNotNullOrEmpty())
                        {
                            GroupFoundDomain = args.Domain;
                        }
                        else
                        {
                            // if a domain isn't passed, try to extract it from the found group distinguished name
                            if (GroupFoundDN.IsNotNullOrEmpty())
                            {
                                GroupFoundDomain = GroupFoundDN.Substring(GroupFoundDN.IndexOf(@"DC=")).Replace(@"DC=", @"".Replace(@",", @"."));
                            }
                        }
                    }

                    var UseMatchingRule = false;
                    string MemberDomain = null;
                    foreach (var Member in Members)
                    {
                        ResultPropertyCollection Properties = null;
                        if (args.Recurse && UseMatchingRule)
                        {
                            //$Properties = $_.Properties
                        }
                        else
                        {
                            var ObjectSearcherArguments = new Args_Get_DomainObject
                            {
                                ADSPath = SearcherArguments.ADSPath,
                                Credential = SearcherArguments.Credential,
                                Domain = SearcherArguments.Domain,
                                DomainController = SearcherArguments.DomainController,
                                Filter = SearcherArguments.Filter,
                                LDAPFilter = SearcherArguments.LDAPFilter,
                                Properties = SearcherArguments.Properties,
                                ResultPageSize = SearcherArguments.ResultPageSize,
                                SearchBase = SearcherArguments.SearchBase,
                                SearchScope = SearcherArguments.SearchScope,
                                SecurityMasks = SearcherArguments.SecurityMasks,
                                Server = SearcherArguments.Server,
                                ServerTimeLimit = SearcherArguments.ServerTimeLimit,
                                Tombstone = SearcherArguments.Tombstone
                            };
                            ObjectSearcherArguments.Identity = new string[] { Member };
                            ObjectSearcherArguments.Raw = true;
                            ObjectSearcherArguments.Properties = new string[] { @"distinguishedname", @"cn", @"samaccountname", @"objectsid", @"objectclass" };
                            var Object = Get_DomainObject(ObjectSearcherArguments)?.FirstOrDefault() as SearchResult;
                            Properties = Object.Properties;
                        }

                        if (Properties != null)
                        {
                            var GroupMember = new GroupMember
                            {
                                GroupDomain = GroupFoundDomain,
                                GroupName = GroupFoundName,
                                GroupDistinguishedName = GroupFoundDN
                            };

                            string MemberSID = null;
                            if (Properties["objectsid"] != null)
                            {
                                MemberSID = new System.Security.Principal.SecurityIdentifier(Properties["objectsid"][0] as byte[], 0).Value;
                            }
                            else
                            {
                                MemberSID = null;
                            }

                            string MemberDN = null;
                            try
                            {
                                MemberDN = Properties["distinguishedname"][0].ToString();
                                if (MemberDN.IsRegexMatch(@"ForeignSecurityPrincipals|S-1-5-21"))
                                {
                                    try
                                    {
                                        if (MemberSID.IsNullOrEmpty())
                                        {
                                            MemberSID = Properties["cn"][0].ToString();
                                        }
                                        ADNameArguments.Identity = new string[] { MemberSID };
                                        ADNameArguments.OutputType = ADSNameType.DomainSimple;
                                        var MemberSimpleName = Convert_ADName(ADNameArguments);

                                        if (MemberSimpleName != null && MemberSimpleName.Any())
                                        {
                                            MemberDomain = MemberSimpleName.First().Split('@')[1];
                                        }
                                        else
                                        {
                                            Logger.Write_Warning($@"[Get-DomainGroupMember] Error converting {MemberDN}");
                                            MemberDomain = null;
                                        }
                                    }
                                    catch
                                    {
                                        Logger.Write_Warning($@"[Get-DomainGroupMember] Error converting {MemberDN}");
                                        MemberDomain = null;
                                    }
                                }
                                else
                                {
                                    // extract the FQDN from the Distinguished Name
                                    MemberDomain = MemberDN.Substring(MemberDN.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                }
                            }
                            catch
                            {
                                MemberDN = null;
                                MemberDomain = null;
                            }
                            string MemberName = null;
                            if (Properties["samaccountname"] != null)
                            {
                                // forest users have the samAccountName set
                                MemberName = Properties["samaccountname"][0].ToString();
                            }
                            else
                            {
                                // external trust users have a SID, so convert it
                                try
                                {
                                    MemberName = ConvertFrom_SID(new Args_ConvertFrom_SID
                                    {
                                        ObjectSID = new string[] { Properties["cn"][0].ToString() },
                                        Domain = ADNameArguments.Domain,
                                        Server = ADNameArguments.Server,
                                        Credential = ADNameArguments.Credential
                                    }).First();
                                }
                                catch
                                {
                                    // if there's a problem contacting the domain to resolve the SID
                                    MemberName = Properties["cn"][0].ToString();
                                }
                            }

                            string MemberObjectClass = null;
                            if (Properties["objectclass"].RegexContains(@"computer"))
                            {
                                MemberObjectClass = @"computer";
                            }
                            else if (Properties["objectclass"].RegexContains(@"group"))
                            {
                                MemberObjectClass = @"group";
                            }
                            else if (Properties["objectclass"].RegexContains(@"user"))
                            {
                                MemberObjectClass = @"user";
                            }
                            else
                            {
                                MemberObjectClass = null;
                            }
                            GroupMember.MemberDomain = MemberDomain;
                            GroupMember.MemberName = MemberName;
                            GroupMember.MemberDistinguishedName = MemberDN;
                            GroupMember.MemberObjectClass = MemberObjectClass;
                            GroupMember.MemberSID = MemberSID;
                            GroupMembers.Add(GroupMember);

                            // if we're doing manual recursion
                            if (args.Recurse && MemberDN.IsNotNullOrEmpty() && MemberObjectClass.IsRegexMatch(@"group"))
                            {
                                Logger.Write_Verbose($@"[Get-DomainGroupMember] Manually recursing on group: {MemberDN}");
                                var GroupArguments = new Args_Get_DomainGroupMember()
                                {
                                    Domain = SearcherArguments.Domain,
                                    LDAPFilter = SearcherArguments.LDAPFilter,
                                    SearchBase = SearcherArguments.SearchBase,
                                    Server = SearcherArguments.Server,
                                    SearchScope = SearcherArguments.SearchScope,
                                    ResultPageSize = SearcherArguments.ResultPageSize,
                                    ServerTimeLimit = SearcherArguments.ServerTimeLimit,
                                    Tombstone = SearcherArguments.Tombstone,
                                    Credential = SearcherArguments.Credential,
                                    Identity = new string[] { MemberDN }
                                };
                                GroupMembers.AddRange(Get_DomainGroupMember(GroupArguments));
                            }
                        }
                    }
                }
                GroupSearcher.Dispose();
            }
            return GroupMembers;
        }

        public static IEnumerable<GroupMember> Get_NetGroupMember(Args_Get_DomainGroupMember args = null)
        {
            return Get_DomainGroupMember(args);
        }

        public static IEnumerable<ManagedSecurityGroup> Get_DomainManagedSecurityGroup(Args_Get_DomainManagedSecurityGroup args = null)
        {
            if (args == null) args = new Args_Get_DomainManagedSecurityGroup();

            var SearcherArguments = new Args_Get_DomainGroup
            {
                LDAPFilter = @"(&(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))",
                Properties = new[] { @"distinguishedName", @"managedBy", @"samaccounttype", @"samaccountname" },
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ObjectArguments = new Args_Get_DomainObject
            {
                LDAPFilter = @"(&(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))",
                Properties = new[] { @"distinguishedName", @"managedBy", @"samaccounttype", @"samaccountname" },
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            string TargetDomain = null;
            if (args.Domain.IsNotNullOrEmpty())
            {
                SearcherArguments.Domain = args.Domain;
                TargetDomain = args.Domain;
            }
            else
            {
                TargetDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            }

            var ManagedGroups = new List<ManagedSecurityGroup>();
            // go through the list of security groups on the domain and identify those who have a manager
            var groups = Get_DomainGroup(SearcherArguments);
            foreach (LDAPProperty group in groups)
            {
                ObjectArguments.Properties = new[] { @"distinguishedname", @"name", @"samaccounttype", @"samaccountname", @"objectsid" };
                ObjectArguments.Identity = new[] { group.managedby };
                SearcherArguments.LDAPFilter = null;

                // $SearcherArguments
                // retrieve the object that the managedBy DN refers to
                var GroupManager = Get_DomainObject(ObjectArguments).First() as LDAPProperty;
                // Write-Host "GroupManager: $GroupManager"
                var ManagedGroup = new ManagedSecurityGroup
                {
                    GroupName = group.samaccountname,
                    GroupDistinguishedName = group.distinguishedname,
                    ManagerName = GroupManager.samaccountname,
                    ManagerDistinguishedName = GroupManager.distinguishedname
                };

                // determine whether the manager is a user or a group
                if (GroupManager.samaccounttype == SamAccountType.GROUP_OBJECT)
                {
                    ManagedGroup.ManagerType = ManagerType.Group;
                }
                else if (GroupManager.samaccounttype == SamAccountType.USER_OBJECT)
                {
                    ManagedGroup.ManagerType = ManagerType.User;
                }

                ManagedGroup.ManagerCanWrite = "UNKNOWN";
                ManagedGroups.Add(ManagedGroup);
            }

            return ManagedGroups;
        }

        public static IEnumerable<ManagedSecurityGroup> Find_ManagedSecurityGroups(Args_Get_DomainManagedSecurityGroup args = null)
        {
            return Get_DomainManagedSecurityGroup(args);
        }

        public static IEnumerable<object> Get_DomainOU(Args_Get_DomainOU args = null)
        {
            if (args == null) args = new Args_Get_DomainOU();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var OUSearcher = Get_DomainSearcher(SearcherArguments);
            List<object> Outs = new List<object>();

            if (OUSearcher != null)
            {
                var IdentityFilter = "";
                var Filter = "";

                if (args.Identity != null)
                {
                    foreach (var item in args.Identity)
                    {
                        var IdentityInstance = item.Replace(@"(", @"\28").Replace(@")", @"\29");
                        if (IdentityInstance.IsRegexMatch(@"^OU=.*"))
                        {
                            IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                            if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                            {
                                //if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                // and rebuild the domain searcher
                                var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                Logger.Write_Verbose($@"[Get-DomainOU] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                OUSearcher = Get_DomainSearcher(SearcherArguments);
                                if (OUSearcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainOU] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                }
                            }
                        }
                        else
                        {
                            try
                            {
                                var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                                IdentityFilter += $@"(objectguid={GuidByteString})";
                            }
                            catch
                            {
                                IdentityFilter += $@"(name={IdentityInstance})";
                            }
                        }
                    }
                }
                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += $@"(|{IdentityFilter})";
                }

                if (args.GPLink.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainOU] Searching for OUs with {args.GPLink} set in the gpLink property");
                    Filter += $@"(gplink=*{args.GPLink}*)";
                }

                if (args.LDAPFilter.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainOU] Using additional LDAP filter: {args.LDAPFilter}");
                    Filter += $@"{args.LDAPFilter}";
                }

                OUSearcher.Filter = $@"(&(objectCategory=organizationalUnit){Filter})";
                Logger.Write_Verbose($@"[Get-DomainOU] Get-DomainOU filter string: {OUSearcher.Filter}");

                SearchResult[] Results = null;
                if (args.FindOne) { Results = new SearchResult[] { OUSearcher.FindOne() }; }
                else
                {
                    var items = OUSearcher.FindAll();
                    if (items != null)
                    {
                        Results = new SearchResult[items.Count];
                        items.CopyTo(Results, 0);
                        items.Dispose();
                    }
                }
                if (Results != null)
                {
                    foreach (var result in Results)
                    {
                        if (args.Raw)
                        {
                            // return raw result objects
                            Outs.Add(result);
                        }
                        else
                        {
                            var Out = Convert_LDAPProperty(result.Properties);
                            Outs.Add(Out);
                        }
                    }
                }
                OUSearcher.Dispose();
            }
            return Outs;
        }

        public static IEnumerable<object> Get_NetOU(Args_Get_DomainOU args = null)
        {
            return Get_DomainOU(args);
        }

        public static string Get_DomainSID(Args_Get_DomainSID args = null)
        {
            if (args == null) args = new Args_Get_DomainSID();

            var SearcherArguments = new Args_Get_DomainComputer
            {
                LDAPFilter = @"(userAccountControl:1.2.840.113556.1.4.803:=8192)",
                Domain = args.Domain,
                Server = args.Server,
                Credential = args.Credential,
                FindOne = true
            };

            var computer = Get_DomainComputer(SearcherArguments).First() as LDAPProperty;
            var DCSIDs = computer.objectsid;

            if (DCSIDs != null)
            {
                return DCSIDs[0]?.Substring(0, DCSIDs[0].LastIndexOf('-'));
            }
            else
            {
                Logger.Write_Verbose($@"[Get-DomainSID] Error extracting domain SID for '{args.Domain}'");
            }
            return null;
        }

        public static ForestEx Get_Forest(Args_Get_Forest args = null)
        {
            if (args == null) args = new Args_Get_Forest();

            var ForestObject = new ForestEx();
            if (args.Credential != null)
            {

                Logger.Write_Verbose(@"[Get-Forest] Using alternate credentials for Get-Forest");

                string TargetForest = null;
                if (args.Forest.IsNotNullOrEmpty())
                {
                    TargetForest = args.Forest;
                }
                else
                {
                    // if no domain is supplied, extract the logon domain from the PSCredential passed
                    TargetForest = args.Credential.Domain;
                    Logger.Write_Verbose(@"[Get-Forest] Extracted domain '$Forest' from -Credential");
                }

                var ForestContext = new System.DirectoryServices.ActiveDirectory.DirectoryContext(System.DirectoryServices.ActiveDirectory.DirectoryContextType.Forest, TargetForest, args.Credential.UserName, args.Credential.Password);

                try
                {
                    ForestObject.Forest = System.DirectoryServices.ActiveDirectory.Forest.GetForest(ForestContext);
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-Forest] The specified forest '{TargetForest}' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: {e}");
                }
            }
            else if (args.Forest.IsNotNullOrEmpty())
            {
                var ForestContext = new System.DirectoryServices.ActiveDirectory.DirectoryContext(System.DirectoryServices.ActiveDirectory.DirectoryContextType.Forest, args.Forest);
                try
                {
                    ForestObject.Forest = System.DirectoryServices.ActiveDirectory.Forest.GetForest(ForestContext);
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-Forest] The specified forest '{args.Forest}' does not exist, could not be contacted, or there isn't an existing trust: {e}");
                }
            }
            else
            {
                // otherwise use the current forest
                ForestObject.Forest = System.DirectoryServices.ActiveDirectory.Forest.GetCurrentForest();
            }

            if (ForestObject.Forest != null)
            {
                // get the SID of the forest root
                string ForestSid = null;
                if (args.Credential != null)
                {
                    ForestSid = (Get_DomainUser(new Args_Get_DomainUser { Identity = new[] { @"krbtgt" }, Domain = ForestObject.Forest.RootDomain.Name, Credential = args.Credential }).First() as LDAPProperty).objectsid?.First();
                }
                else
                {
                    ForestSid = (Get_DomainUser(new Args_Get_DomainUser { Identity = new[] { @"krbtgt" }, Domain = ForestObject.Forest.RootDomain.Name }).First() as LDAPProperty).objectsid?.First();
                }

                var Parts = ForestSid.Split('-');
                ForestSid = string.Join(@"-", Parts.Take(Parts.Length - 2 + 1));
                ForestObject.RootDomainSid = ForestSid;
                return ForestObject;
            }
            return null;
        }

        public static ForestEx Get_NetForest(Args_Get_Forest args = null)
        {
            return Get_Forest(args);
        }

        public static IEnumerable<IDomainTrust> Get_ForestTrust(Args_Get_Forest args = null)
        {
            if (args == null) args = new Args_Get_Forest();

            var FoundForest = Get_Forest(args);

            if (FoundForest != null)
            {
                var items = FoundForest.Forest.GetAllTrustRelationships();
                var ForestTrusts = new List<IDomainTrust>();
                foreach (TrustRelationshipInformation item in items)
                {
                    ForestTrusts.Add(new NetDomainTrust
                    {
                        SourceName = item.SourceName,
                        TargetName = item.TargetName,
                        TrustDirection = item.TrustDirection,
                        TrustType = item.TrustType
                    });
                }
                return ForestTrusts;
            }
            return null;
        }

        public static System.DirectoryServices.ActiveDirectory.TrustRelationshipInformationCollection Get_NetForestTrust(Args_Get_Forest args = null)
        {
            return Get_NetForestTrust(args);
        }

        public static IEnumerable<IDomainTrust> Get_DomainTrust(Args_Get_DomainTrust args = null)
        {
            if (args == null) args = new Args_Get_DomainTrust();

            var LdapSearcherArguments = new Args_Get_DomainSearcher
            {
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            Args_Get_DomainSID NetSearcherArguments = null;
            string SourceDomain = null;
            if (!args.API)
            {
                NetSearcherArguments = new Args_Get_DomainSID();
                if (args.Domain.IsNotNullOrEmpty() && args.Domain.Trim() != "")
                {
                    SourceDomain = args.Domain;
                }
                else
                {
                    if (args.Credential != null)
                    {
                        SourceDomain = Get_Domain(new Args_Get_Domain { Credential = args.Credential }).Name;
                    }
                    else
                    {
                        SourceDomain = Get_Domain().Name;
                    }
                }
            }
            else if (!args.NET)
            {
                if (args.Domain != null && args.Domain.Trim() != "")
                {
                    SourceDomain = args.Domain;
                }
                else
                {
                    SourceDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
                }
            }

            var DomainTrusts = new List<IDomainTrust>();
            if (!args.API && !args.NET)
            {
                // if we're searching for domain trusts through LDAP/ADSI
                var TrustSearcher = Get_DomainSearcher(LdapSearcherArguments);
                var SourceSID = Get_DomainSID(NetSearcherArguments);

                if (TrustSearcher != null)
                {
                    TrustSearcher.Filter = @"(objectClass=trustedDomain)";

                    SearchResult[] Results = null;
                    if (args.FindOne) { Results = new SearchResult[] { TrustSearcher.FindOne() }; }
                    else
                    {
                        var items = TrustSearcher.FindAll();
                        if (items != null)
                        {
                            Results = new SearchResult[items.Count];
                            items.CopyTo(Results, 0);
                        }
                    }
                    if (Results != null)
                    {
                        foreach (var result in Results)
                        {
                            var Props = result.Properties;
                            var DomainTrust = new LdapDomainTrust();

                            var TrustAttrib = (TrustAttribute)Props[@"trustattributes"][0];

                            var Direction = (TrustDirection)Props[@"trustdirection"][0];

                            var TrustType = (TrustType)Props[@"trusttype"][0];

                            var Distinguishedname = Props[@"distinguishedname"][0] as string;
                            var SourceNameIndex = Distinguishedname.IndexOf(@"DC=");
                            if (SourceNameIndex != 0)
                            {
                                SourceDomain = Distinguishedname.Substring(SourceNameIndex).Replace(@"DC=", @"").Replace(@",", @".");
                            }
                            else
                            {
                                SourceDomain = @"";
                            }

                            var TargetNameIndex = Distinguishedname.IndexOf(@",CN=System");
                            string TargetDomain = null;
                            if (SourceNameIndex != 0)
                            {
                                TargetDomain = Distinguishedname.Substring(3, TargetNameIndex - 3);
                            }
                            else
                            {
                                TargetDomain = @"";
                            }

                            var ObjectGuid = new Guid(Props[@"objectguid"][0] as byte[]);
                            var TargetSID = (new System.Security.Principal.SecurityIdentifier(Props[@"securityidentifier"][0] as byte[], 0)).Value;

                            DomainTrust = new LdapDomainTrust
                            {
                                SourceName = SourceDomain,
                                TargetName = Props[@"name"][0] as string,
                                TrustType = TrustType,
                                TrustAttributes = TrustAttrib,
                                TrustDirection = Direction,
                                WhenCreated = Props[@"whencreated"][0],
                                WhenChanged = Props[@"whenchanged"][0]
                            };
                            DomainTrusts.Add(DomainTrust);
                        }
                    }
                    TrustSearcher.Dispose();
                }
            }
            else if (args.API)
            {
                // if we're searching for domain trusts through Win32 API functions
                string TargetDC = null;
                if (args.Server.IsNotNullOrEmpty())
                {
                    TargetDC = args.Server;
                }
                else if (args.Domain != null && args.Domain.Trim() != @"")
                {
                    TargetDC = args.Domain;
                }
                else
                {
                    // see https://msdn.microsoft.com/en-us/library/ms675976(v=vs.85).aspx for default NULL behavior
                    TargetDC = null;
                }

                // arguments for DsEnumerateDomainTrusts
                var PtrInfo = IntPtr.Zero;

                // 63 = DS_DOMAIN_IN_FOREST + DS_DOMAIN_DIRECT_OUTBOUND + DS_DOMAIN_TREE_ROOT + DS_DOMAIN_PRIMARY + DS_DOMAIN_NATIVE_MODE + DS_DOMAIN_DIRECT_INBOUND
                uint Flags = 63;
                uint DomainCount = 0;

                // get the trust information from the target server
                var Result = NativeMethods.DsEnumerateDomainTrusts(TargetDC, Flags, out PtrInfo, out DomainCount);

                // Locate the offset of the initial intPtr
                var Offset = PtrInfo.ToInt64();

                // 0 = success
                if (Result == 0 && Offset > 0)
                {
                    // Work out how much to increment the pointer by finding out the size of the structure
                    var Increment = Marshal.SizeOf(typeof(NativeMethods.DS_DOMAIN_TRUSTS));

                    // parse all the result structures
                    for (var i = 0; i < DomainCount; i++)
                    {
                        // create a new int ptr at the given offset and cast the pointer as our result structure
                        var NewIntPtr = new IntPtr(Offset);
                        var Info = (NativeMethods.DS_DOMAIN_TRUSTS)Marshal.PtrToStructure(NewIntPtr, typeof(NativeMethods.DS_DOMAIN_TRUSTS));

                        Offset = NewIntPtr.ToInt64();
                        Offset += Increment;

                        var SidString = @"";
                        bool ret = NativeMethods.ConvertSidToStringSid(Info.DomainSid, out SidString);
                        var LastError = Marshal.GetLastWin32Error();

                        if (ret == false)
                        {
                            Logger.Write_Verbose($@"[Get-DomainTrust] Error: {new System.ComponentModel.Win32Exception(LastError).Message}");
                        }
                        else
                        {
                            var DomainTrust = new ApiDomainTrust
                            {
                                SourceName = SourceDomain,
                                TargetName = Info.DnsDomainName,
                                TargetNetbiosName = Info.NetbiosDomainName,
                                Flags = Info.Flags,
                                ParentIndex = Info.ParentIndex,
                                TrustType = (NativeMethods.DS_DOMAIN_TRUST_TYPE)Info.TrustType,
                                TrustAttributes = Info.TrustAttributes,
                                TargetSid = SidString,
                                TargetGuid = Info.DomainGuid
                            };
                            DomainTrusts.Add(DomainTrust);
                        }
                    }
                    // free up the result buffer
                    NativeMethods.NetApiBufferFree(PtrInfo);
                }
                else
                {
                    Logger.Write_Verbose($@"[Get-DomainTrust] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }
            else
            {
                // if we're searching for domain trusts through .NET methods
                var FoundDomain = Get_Domain(new Args_Get_Domain
                {
                    Domain = NetSearcherArguments.Domain,
                    Credential = NetSearcherArguments.Credential
                });
                if (FoundDomain != null)
                {
                    var items = FoundDomain.GetAllTrustRelationships();
                    foreach (TrustRelationshipInformation item in items)
                    {
                        DomainTrusts.Add(new NetDomainTrust
                        {
                            SourceName = item.SourceName,
                            TargetName = item.TargetName,
                            TrustDirection = item.TrustDirection,
                            TrustType = item.TrustType
                        });
                    }
                }
            }
            return DomainTrusts;
        }

        public static IEnumerable<IDomainTrust> Get_NetDomainTrust(Args_Get_DomainTrust args = null)
        {
            return Get_DomainTrust(args);
        }

        public static DomainCollection Get_ForestDomain(Args_Get_ForestDomain args = null)
        {
            if (args == null) args = new Args_Get_ForestDomain();

            var Arguments = new Args_Get_Forest
            {
                Forest = args.Forest,
                Credential = args.Credential
            };

            var ForestObject = Get_Forest(Arguments);
            if (ForestObject != null)
            {
                return ForestObject.Forest?.Domains;
            }
            return null;
        }

        public static DomainCollection Get_NetForestDomain(Args_Get_ForestDomain args = null)
        {
            return Get_ForestDomain(args);
        }

        public static IEnumerable<object> Get_DomainSite(Args_Get_DomainSite args = null)
        {
            if (args == null) args = new Args_Get_DomainSite();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                SearchBasePrefix = @"CN=Sites,CN=Configuration",
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var SiteSearcher = Get_DomainSearcher(SearcherArguments);
            var Sites = new List<object>();
            if (SiteSearcher != null)
            {
                var IdentityFilter = @"";
                var Filter = @"";
                if (args.Identity != null)
                {
                    foreach (var item in args.Identity)
                    {
                        var IdentityInstance = item.Replace(@"(", @"\28").Replace(@")", @"\29");
                        if (IdentityInstance.IsRegexMatch(@"^CN=.*"))
                        {
                            IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                            if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                            {
                                // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                //   and rebuild the domain searcher
                                var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                Logger.Write_Verbose($@"[Get-DomainSite] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                SiteSearcher = Get_DomainSearcher(SearcherArguments);
                                if (SiteSearcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainSite] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                }
                            }
                        }
                        else
                        {
                            try
                            {
                                var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                                IdentityFilter += $@"(objectguid={GuidByteString})";
                            }
                            catch
                            {
                                IdentityFilter += $@"(name={IdentityInstance})";
                            }
                        }
                    }
                }
                if (IdentityFilter != null && IdentityFilter.Trim() != @"")
                {
                    Filter += $@"(|{IdentityFilter})";
                }

                if (args.GPLink.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainSite] Searching for sites with {args.GPLink} set in the gpLink property");
                    Filter += $@"(gplink=*{args.GPLink}*)";
                }

                if (args.LDAPFilter.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainSite] Using additional LDAP filter: {args.LDAPFilter}");
                    Filter += $@"{args.LDAPFilter}";
                }

                SiteSearcher.Filter = $@"(&(objectCategory=site){Filter})";
                Logger.Write_Verbose($@"[Get-DomainSite] Get-DomainSite filter string: {SiteSearcher.Filter}");

                SearchResult[] Results = null;
                if (args.FindOne) { Results = new SearchResult[] { SiteSearcher.FindOne() }; }
                else
                {
                    var items = SiteSearcher.FindAll();
                    if (items != null)
                    {
                        Results = new SearchResult[items.Count];
                        items.CopyTo(Results, 0);
                    }
                }
                if (Results != null)
                {
                    foreach (var result in Results)
                    {
                        if (args.Raw)
                        {
                            // return raw result objects
                            Sites.Add(result);
                        }
                        else
                        {
                            var Site = Convert_LDAPProperty(result.Properties);
                            Sites.Add(Site);
                        }
                    }
                }
                SiteSearcher.Dispose();
            }
            return Sites;
        }

        public static IEnumerable<object> Get_NetSite(Args_Get_DomainSite args = null)
        {
            return Get_DomainSite(args);
        }

        public static IEnumerable<object> Get_DomainSubnet(Args_Get_DomainSubnet args = null)
        {
            if (args == null) args = new Args_Get_DomainSubnet();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                SearchBasePrefix = @"CN=Subnets,CN=Sites,CN=Configuration",
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var SubnetSearcher = Get_DomainSearcher(SearcherArguments);
            var Subnets = new List<object>();
            if (SubnetSearcher != null)
            {
                var IdentityFilter = @"";
                var Filter = @"";
                if (args.Identity != null)
                {
                    foreach (var item in args.Identity)
                    {
                        var IdentityInstance = item.Replace(@"(", @"\28").Replace(@")", @"\29");
                        if (IdentityInstance.IsRegexMatch(@"^CN=.*"))
                        {
                            IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                            if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                            {
                                // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                // and rebuild the domain searcher
                                var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                Logger.Write_Verbose($@"[Get-DomainSite] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                SubnetSearcher = Get_DomainSearcher(SearcherArguments);
                                if (SubnetSearcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainSubnet] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                }
                            }
                        }
                        else
                        {
                            try
                            {
                                var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                                IdentityFilter += $@"(objectguid={GuidByteString})";
                            }
                            catch
                            {
                                IdentityFilter += $@"(name={IdentityInstance})";
                            }
                        }
                    }
                }
                if (IdentityFilter != null && IdentityFilter.Trim() != @"")
                {
                    Filter += $@"(|{IdentityFilter})";
                }

                if (args.LDAPFilter.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainSubnet] Using additional LDAP filter: {args.LDAPFilter}");
                    Filter += $@"{args.LDAPFilter}";
                }

                SubnetSearcher.Filter = $@"(&(objectCategory=site){Filter})";
                Logger.Write_Verbose($@"[Get-DomainSubnet] Get-DomainSubnet filter string: {SubnetSearcher.Filter}");

                SearchResult[] Results = null;
                if (args.FindOne) { Results = new SearchResult[] { SubnetSearcher.FindOne() }; }
                else
                {
                    var items = SubnetSearcher.FindAll();
                    if (items != null)
                    {
                        Results = new SearchResult[items.Count];
                        items.CopyTo(Results, 0);
                    }
                }
                if (Results != null)
                {
                    foreach (var result in Results)
                    {
                        if (args.Raw)
                        {
                            // return raw result objects
                            if (args.SiteName.IsNotNullOrEmpty())
                            {
                                // have to do the filtering after the LDAP query as LDAP doesn't let you specify
                                // wildcards for 'siteobject' :(
                                if (result.Properties != null && (result.Properties[@"siteobject"][0] as string).IsLikeMatch($@"*{args.SiteName}*"))
                                {
                                    Subnets.Add(result);
                                }
                            }
                        }
                        else
                        {
                            var Subnet = Convert_LDAPProperty(result.Properties);
                            if (Subnet.siteobject.IsLikeMatch($@"*{args.SiteName}*"))
                            {
                                Subnets.Add(result);
                            }
                        }
                    }
                }
                SubnetSearcher.Dispose();
            }
            return Subnets;
        }

        public static IEnumerable<object> Get_NetSubnet(Args_Get_DomainSubnet args = null)
        {
            return Get_DomainSubnet(args);
        }

        public static IEnumerable<IDomainTrust> Get_DomainTrustMapping(Args_Get_DomainTrustMapping args = null)
        {
            if (args == null) args = new Args_Get_DomainTrustMapping();

            // keep track of domains seen so we don't hit infinite recursion
            var SeenDomains = new Dictionary<string, string>();

            // our domain status tracker
            var Domains = new System.Collections.Stack();

            var DomainTrustArguments = new Args_Get_DomainTrust
            {
                API = args.API,
                NET = args.NET,
                LDAPFilter = args.LDAPFilter,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            // get the current domain and push it onto the stack
            string CurrentDomain = null;
            if (args.Credential != null)
            {
                CurrentDomain = Get_Domain(new Args_Get_Domain { Credential = args.Credential }).Name;
            }
            else
            {
                CurrentDomain = Get_Domain().Name;
            }
            Domains.Push(CurrentDomain);

            var DomainTrustMappings = new List<IDomainTrust>();
            while (Domains.Count != 0)
            {

                string Domain = Domains.Pop() as string;

                // if we haven't seen this domain before
                if (Domain != null && Domain.Trim() != @"" && !SeenDomains.ContainsKey(Domain))
                {

                    Logger.Write_Verbose($@"[Get-DomainTrustMapping] Enumerating trusts for domain: '{Domain}'");

                    // mark it as seen in our list
                    SeenDomains.Add(Domain, "");

                    try
                    {
                        // get all the trusts for this domain
                        DomainTrustArguments.Domain = Domain;
                        var Trusts = Get_DomainTrust(DomainTrustArguments);

                        // get any forest trusts, if they exist
                        if (args.NET)
                        {
                            var ForestTrustArguments = new Args_Get_Forest
                            {
                                Forest = args.Forest,
                                Credential = args.Credential
                            };
                            Trusts.Union(Get_ForestTrust(ForestTrustArguments));
                        }

                        if (Trusts != null)
                        {
                            // enumerate each trust found
                            foreach (var Trust in Trusts)
                            {
                                if (Trust.SourceName.IsNotNullOrEmpty() && Trust.TargetName.IsNotNullOrEmpty())
                                {
                                    // make sure we process the target
                                    Domains.Push(Trust.TargetName);
                                    DomainTrustMappings.Add(Trust);
                                }
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[Get-DomainTrustMapping] Error: {e}");
                    }
                }
            }
            return DomainTrustMappings;
        }

        public static IEnumerable<IDomainTrust> Invoke_MapDomainTrust(Args_Get_DomainTrustMapping args = null)
        {
            return Get_DomainTrustMapping(args);
        }

        public static IEnumerable<GlobalCatalog> Get_ForestGlobalCatalog(Args_Get_ForestGlobalCatalog args = null)
        {
            if (args == null) args = new Args_Get_ForestGlobalCatalog();

            var Arguments = new Args_Get_Forest
            {
                Forest = args.Forest,
                Credential = args.Credential
            };

            var ForestObject = Get_Forest(Arguments);

            if (ForestObject != null)
            {
                var ForestGlobalCatalogs = new List<GlobalCatalog>();
                var items = ForestObject.Forest.FindAllGlobalCatalogs();
                foreach (GlobalCatalog item in items)
                {
                    ForestGlobalCatalogs.Add(item);
                }
            }
            return null;
        }

        public static IEnumerable<GlobalCatalog> Get_NetForestCatalog(Args_Get_ForestGlobalCatalog args = null)
        {
            return Get_ForestGlobalCatalog(args);
        }

        public static IEnumerable<IWinEvent> Get_DomainUserEvent(Args_Get_DomainUserEvent args = null)
        {
            if (args == null) args = new Args_Get_DomainUserEvent();

            // the XML filter we're passing to Get-WinEvent
            var XPathFilter = $@"
<QueryList>
    <Query Id=""0"" Path=""Security"">

        <!--Logon events-->
        <Select Path = ""Security"">
             *[
                 System[
                     Provider[
                         @Name='Microsoft-Windows-Security-Auditing'
                     ] 
                     and (Level=4 or Level=0) and (EventID=4624) 
                     and TimeCreated[
                         @SystemTime&gt;='{args.StartTime.ToUniversalTime().ToString("s")}' and @SystemTime&lt;='{args.EndTime.ToUniversalTime().ToString("s")}'
                    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
        </Select>

        <!-- Logon with explicit credential events -->
        <Select Path=""Security"">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
                        @SystemTime&gt;='{args.StartTime.ToUniversalTime().ToString("s")}' and @SystemTime&lt;='{args.EndTime.ToUniversalTime().ToString("s")}'
                    ]
                ]
            ]
        </Select>

        <Suppress Path=""Security"">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name='LogonType']='5' or Data[@Name='LogonType']='0')
                        or
                        Data[@Name='TargetUserName']='ANONYMOUS LOGON'
                        or
                        Data[@Name='TargetUserSID']='S-1-5-18'
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
";

            var Events = new List<IWinEvent>();
            foreach (var Computer in args.ComputerName)
            {
                EventLogQuery query = new EventLogQuery(@"Security", PathType.LogName, XPathFilter);
                EventLogReader reader = new EventLogReader(query);
                for (EventRecord Event = reader.ReadEvent(); null != Event; Event = reader.ReadEvent())
                {
                    if (args.ComputerName.Any(x => Event.MachineName.Equals(x, StringComparison.OrdinalIgnoreCase) || Event.MachineName.StartsWith(x, StringComparison.OrdinalIgnoreCase)))
                    {
                        var Properties = Event.Properties;
                        switch (Event.Id)
                        {
                            case 4624: // logon event
                                // skip computer logons, for now...
                                if (!Event.Properties[5].Value.ToString().EndsWith(@"$"))
                                {
                                    Events.Add(new LogonEvent
                                    {
                                        ComputerName = Computer,
                                        TimeCreated = Event.TimeCreated,
                                        EventId = Event.Id,
                                        SubjectUserSid = Properties[0].Value.ToString(),
                                        SubjectUserName = Properties[1].Value.ToString(),
                                        SubjectDomainName = Properties[2].Value.ToString(),
                                        SubjectLogonId = Properties[3].Value.ToString(),
                                        TargetUserSid = Properties[4].Value.ToString(),
                                        TargetUserName = Properties[5].Value.ToString(),
                                        TargetDomainName = Properties[6].Value.ToString(),
                                        TargetLogonId = Properties[7].Value.ToString(),
                                        LogonType = Properties[8].Value.ToString(),
                                        LogonProcessName = Properties[9].Value.ToString(),
                                        AuthenticationPackageName = Properties[10].Value.ToString(),
                                        WorkstationName = Properties[11].Value.ToString(),
                                        LogonGuid = Properties[12].Value.ToString(),
                                        TransmittedServices = Properties[13].Value.ToString(),
                                        LmPackageName = Properties[14].Value.ToString(),
                                        KeyLength = Properties[15].Value.ToString(),
                                        ProcessId = Properties[16].Value.ToString(),
                                        ProcessName = Properties[17].Value.ToString(),
                                        IpAddress = Properties[18].Value.ToString(),
                                        IpPort = Properties[19].Value.ToString(),
                                        ImpersonationLevel = Properties[20].Value.ToString(),
                                        RestrictedAdminMode = Properties[21].Value.ToString(),
                                        TargetOutboundUserName = Properties[22].Value.ToString(),
                                        TargetOutboundDomainName = Properties[23].Value.ToString(),
                                        VirtualAccount = Properties[24].Value.ToString(),
                                        TargetLinkedLogonId = Properties[25].Value.ToString(),
                                        ElevatedToken = Properties[26].Value.ToString()
                                    });
                                }
                                break;
                            case 4648: // logon with explicit credential
                                // skip computer logons, for now...
                                if (!Properties[5].Value.ToString().EndsWith(@"$") && Properties[11].Value.ToString().IsRegexMatch(@"taskhost\.exe"))
                                {
                                    Events.Add(new ExplicitCredentialLogonEvent
                                    {
                                        ComputerName = Computer,
                                        TimeCreated = Event.TimeCreated,
                                        EventId = Event.Id,
                                        SubjectUserSid = Properties[0].Value.ToString(),
                                        SubjectUserName = Properties[1].Value.ToString(),
                                        SubjectDomainName = Properties[2].Value.ToString(),
                                        SubjectLogonId = Properties[3].Value.ToString(),
                                        LogonGuid = Properties[4].Value.ToString(),
                                        TargetUserName = Properties[5].Value.ToString(),
                                        TargetDomainName = Properties[6].Value.ToString(),
                                        TargetLogonGuid = Properties[7].Value.ToString(),
                                        TargetServerName = Properties[8].Value.ToString(),
                                        TargetInfo = Properties[9].Value.ToString(),
                                        ProcessId = Properties[10].Value.ToString(),
                                        ProcessName = Properties[11].Value.ToString(),
                                        IpAddress = Properties[12].Value.ToString(),
                                        IpPort = Properties[13].Value.ToString()
                                    });
                                }
                                break;
                            default:
                                Logger.Write_Warning($@"No handler exists for event ID: {Event.Id}");
                                break;
                        }
                    }

                    if (Events.Count >= args.MaxEvents)
                        break;
                }
            }
            return Events;
        }

        public static IEnumerable<IWinEvent> Get_UserEvent(Args_Get_DomainUserEvent args = null)
        {
            return Get_DomainUserEvent(args);
        }

        public static Dictionary<string, string> Get_DomainGUIDMap(Args_Get_DomainGUIDMap args = null)
        {
            if (args == null) args = new Args_Get_DomainGUIDMap();

            var GUIDs = new Dictionary<string, string>
            {
                { @"00000000-0000-0000-0000-000000000000", @"All"}
            };

            var ForestArguments = new Args_Get_Forest()
            {
                Credential = args.Credential
            };

            string SchemaPath = null;
            try
            {
                SchemaPath = Get_Forest(ForestArguments).Forest.Schema.Name;
            }
            catch
            {
                throw new Exception(@"[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest");
            }
            if (SchemaPath.IsNullOrEmpty())
            {
                throw new Exception(@"[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest");
            }

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                SearchBase = SchemaPath,
                LDAPFilter = @"(schemaIDGUID=*)",
                Domain = args.Domain,
                Server = args.Server,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Credential = args.Credential
            };
            var SchemaSearcher = Get_DomainSearcher(SearcherArguments);

            if (SchemaSearcher != null)
            {
                try
                {
                    var Results = SchemaSearcher.FindAll();
                    if (Results != null)
                    {
                        foreach (SearchResult result in Results)
                        {
                            GUIDs[(new Guid(result.Properties["schemaidguid"][0] as byte[])).ToString()] = result.Properties["name"][0].ToString();
                        }
                        try { Results.Dispose(); }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-DomainGUIDMap] Error disposing of the Results object: {e}");
                        }
                    }
                    SchemaSearcher.Dispose();
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-DomainGUIDMap] Error in building GUID map: {e}");
                }
            }

            SearcherArguments.SearchBase = SchemaPath.Replace(@"Schema", @"Extended-Rights");
            SearcherArguments.LDAPFilter = @"(objectClass=controlAccessRight)";
            var RightsSearcher = Get_DomainSearcher(SearcherArguments);

            if (RightsSearcher != null)
            {
                try
                {
                    var Results = RightsSearcher.FindAll();
                    if (Results != null)
                    {
                        foreach (SearchResult result in Results)
                        {
                            GUIDs[(new Guid(result.Properties["rightsguid"][0] as byte[])).ToString()] = result.Properties["name"][0].ToString();
                        }
                        try { Results.Dispose(); }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-DomainGUIDMap] Error disposing of the Results object: {e}");
                        }
                    }
                    RightsSearcher.Dispose();
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-DomainGUIDMap] Error in building GUID map: {e}");
                }
            }
            return GUIDs;
        }

        public static Dictionary<string, string> Get_GUIDMap(Args_Get_DomainGUIDMap args = null)
        {
            return Get_DomainGUIDMap(args);
        }

        public static IEnumerable<ComputerIPAddress> Resolve_IPAddress(Args_Resolve_IPAddress args = null)
        {
            if (args == null) args = new Args_Resolve_IPAddress();

            var addresses = new List<ComputerIPAddress>();
            foreach (var Computer in args.ComputerName)
            {
                try
                {
                    foreach (var address in System.Net.Dns.GetHostEntry(Computer).AddressList)
                    {
                        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            var Out = new ComputerIPAddress
                            {
                                ComputerName = Computer,
                                IPAddress = address.ToString()
                            };
                            addresses.Add(Out);
                        }
                    }
                }
                catch
                {
                    Logger.Write_Verbose(@"[Resolve-IPAddress] Could not resolve $Computer to an IP Address.");
                }
            }
            return addresses;
        }

        public static IEnumerable<ComputerIPAddress> Get_IPAddress(Args_Resolve_IPAddress args = null)
        {
            return Resolve_IPAddress(args);
        }

        public static IEnumerable<string> ConvertTo_SID(Args_ConvertTo_SID args = null)
        {
            if (args == null) args = new Args_ConvertTo_SID();

            var DomainSearcherArguments = new Args_Get_DomainObject
            {
                Domain = args.Domain,
                Server = args.Server,
                Credential = args.Credential
            };

            var SIDs = new List<string>();
            foreach (var item in args.ObjectName)
            {
                var name = item.Replace(@"/", @"\");

                if (args.Credential != null)
                {
                    var DN = Convert_ADName(new Args_Convert_ADName
                    {
                        Identity = new[] { name },
                        OutputType = ADSNameType.DN,
                        Domain = DomainSearcherArguments.Domain,
                        Server = DomainSearcherArguments.Server,
                        Credential = DomainSearcherArguments.Credential
                    });


                    if (DN != null)
                    {
                        var UserDomain = DN.First().Substring(DN.First().IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                        var UserName = DN.First().Split(',')[0].Split('=')[1];

                        DomainSearcherArguments.Identity = new[] { UserName };
                        DomainSearcherArguments.Domain = UserDomain;
                        DomainSearcherArguments.Properties = new[] { @"objectsid" };
                        var obj = Get_DomainObject(DomainSearcherArguments);
                        foreach (LDAPProperty ldapProperty in obj)
                        {
                            SIDs.AddRange(ldapProperty.objectsid);
                        }
                    }
                }
                else
                {
                    try
                    {
                        if (name.Contains(@"\"))
                        {
                            args.Domain = name.Split('\\')[0];
                            name = name.Split('\\')[1];
                        }
                        else if (args.Domain.IsNullOrEmpty())
                        {
                            args.Domain = Get_Domain().Name;
                        }

                        var obj = new System.Security.Principal.NTAccount(args.Domain, name);
                        SIDs.Add(obj.Translate(typeof(System.Security.Principal.SecurityIdentifier)).Value);
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[ConvertTo-SID] Error converting {args.Domain}\{name} : {e}");
                    }
                }
            }
            return SIDs;
        }

        public static IntPtr Invoke_UserImpersonation(Args_Invoke_UserImpersonation args = null)
        {
            if (args == null) args = new Args_Invoke_UserImpersonation();

            if (System.Threading.Thread.CurrentThread.GetApartmentState() == System.Threading.ApartmentState.STA && !args.Quiet)
            {
                Logger.Write_Warning(@"[Invoke-UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work.");
            }

            IntPtr LogonTokenHandle;
            bool Result;
            if (args.TokenHandle != IntPtr.Zero)
            {
                LogonTokenHandle = args.TokenHandle;
            }
            else
            {
                LogonTokenHandle = IntPtr.Zero;
                var UserDomain = args.Credential.Domain;
                var UserName = args.Credential.UserName;
                Logger.Write_Warning($@"[Invoke-UserImpersonation] Executing LogonUser() with user: {UserDomain}\{UserName}");

                // LOGON32_LOGON_NEW_CREDENTIALS = 9, LOGON32_PROVIDER_WINNT50 = 3
                //   this is to simulate "runas.exe /netonly" functionality
                Result = NativeMethods.LogonUser(UserName, UserDomain, args.Credential.Password, LogonType.LOGON32_LOGON_NEW_CREDENTIALS, LogonProvider.LOGON32_PROVIDER_WINNT50, ref LogonTokenHandle);
                var LastError = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

                if (!Result)
                {
                    throw new Exception($@"[Invoke-UserImpersonation] LogonUser() Error: {new System.ComponentModel.Win32Exception(LastError).Message}");
                }
            }

            // actually impersonate the token from LogonUser()
            Result = NativeMethods.ImpersonateLoggedOnUser(LogonTokenHandle);

            if (!Result)
            {
                throw new Exception($@"[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)");
            }


            Logger.Write_Verbose(@"[Invoke-UserImpersonation] Alternate credentials successfully impersonated");
            return LogonTokenHandle;
        }


        public static void Invoke_RevertToSelf(IntPtr TokenHandle)
        {
            var Result = false;
            if (TokenHandle != IntPtr.Zero)
            {
                Logger.Write_Warning(@"[Invoke-RevertToSelf] Reverting token impersonation and closing LogonUser() token handle");
                Result = NativeMethods.CloseHandle(TokenHandle);
            }

            Result = NativeMethods.RevertToSelf();
            var LastError = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

            if (!Result)
            {
                throw new Exception($@"[Invoke-RevertToSelf] RevertToSelf() Error: {new System.ComponentModel.Win32Exception(LastError).Message}");
            }

            Logger.Write_Verbose(@"[Invoke-RevertToSelf] Token impersonation successfully reverted");
        }


        public static IEnumerable<SPNTicket> Get_DomainSPNTicket(Args_Get_DomainSPNTicket args = null)
        {
            if (args == null) args = new Args_Get_DomainSPNTicket();

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation { Credential = args.Credential });
            }

            IEnumerable<object> TargetObject;
            if (args.User != null)
            {
                TargetObject = new[] { args.User };
            }
            else
            {
                TargetObject = args.SPN;
            }

            var SPNTickets = new List<SPNTicket>();
            foreach (var item in TargetObject)
            {
                string UserSPN;
                string SamAccountName;
                string DistinguishedName;

                if (args.User != null)
                {
                    var obj = item as LDAPProperty;
                    UserSPN = obj.ServicePrincipalName;
                    SamAccountName = obj.samaccountname;
                    DistinguishedName = obj.distinguishedname;
                }
                else
                {
                    UserSPN = item as string;
                    SamAccountName = @"UNKNOWN";
                    DistinguishedName = @"UNKNOWN";
                }

                // if a user has multiple SPNs we only take the first one otherwise the service ticket request fails miserably :) -@st3r30byt3
                System.IdentityModel.Tokens.KerberosRequestorSecurityToken Ticket = null;
                try
                {
                    Ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(UserSPN);
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[Get-DomainSPNTicket] Error requesting ticket for SPN '{UserSPN}' from user '{DistinguishedName}' : {e}");
                }
                byte[] TicketByteStream = null;
                if (Ticket != null)
                {
                    TicketByteStream = Ticket.GetRequest();
                }
                if (TicketByteStream != null)
                {
                    var Out = new SPNTicket();

                    var TicketHexStream = System.BitConverter.ToString(TicketByteStream).Replace(@"-", @"");

                    // TicketHexStream == GSS-API Frame (see https://tools.ietf.org/html/rfc4121#section-4.1)
                    // No easy way to parse ASN1, so we'll try some janky regex to parse the embedded KRB_AP_REQ.Ticket object
                    var Matches = TicketHexStream.GetRegexGroups(@"a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)");

                    string Hash;
                    byte Etype = 0;
                    UInt32 CipherTextLen = 0;
                    string CipherText = null;
                    if (Matches != null && Matches.Count > 0)
                    {
                        Etype = Convert.ToByte(Matches[@"EtypeLen"].Value, 16);
                        CipherTextLen = Convert.ToUInt32(Matches[@"CipherTextLen"].Value, 16) - 4;
                        CipherText = Matches[@"DataToEnd"].Value.Substring(0, (int)(CipherTextLen * 2));
                        // Make sure the next field matches the beginning of the KRB_AP_REQ.Authenticator object
                        if (Matches[@"DataToEnd"].Value.Substring((int)(CipherTextLen * 2), 4) != @"A482")
                        {
                            Logger.Write_Warning($@"Error parsing ciphertext for the SPN  {Ticket.ServicePrincipalName}. Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq");
                            Hash = null;
                            Out.TicketByteHexStream = BitConverter.ToString(TicketByteStream).Replace(@"-", @"");
                        }
                        else
                        {
                            Hash = $@"{CipherText.Substring(0, 32)}${CipherText.Substring(32)}";
                            Out.TicketByteHexStream = null;
                        }
                    }
                    else
                    {
                        Logger.Write_Warning($@"Unable to parse ticket structure for the SPN  {Ticket.ServicePrincipalName}. Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq");
                        Hash = null;
                        Out.TicketByteHexStream = BitConverter.ToString(TicketByteStream).Replace(@"-", @"");
                    }
                    string HashFormat;
                    if (Hash.IsNotNullOrEmpty())
                    {
                        if (args.OutputFormat == SPNTicketFormat.John)
                        {
                            HashFormat = $@"$krb5tgs${Ticket.ServicePrincipalName}:{Hash}";
                        }
                        else
                        {
                            string UserDomain;
                            if (DistinguishedName != @"UNKNOWN")
                            {
                                UserDomain = DistinguishedName.Substring(DistinguishedName.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                            }
                            else
                            {
                                UserDomain = @"UNKNOWN";
                            }

                            // hashcat output format
                            HashFormat = $@"$krb5tgs${Etype}$*{SamAccountName}${UserDomain}${Ticket.ServicePrincipalName}*${Hash}";
                        }
                        Out.Hash = HashFormat;
                    }

                    Out.SamAccountName = SamAccountName;
                    Out.DistinguishedName = DistinguishedName;
                    Out.ServicePrincipalName = Ticket.ServicePrincipalName;

                    SPNTickets.Add(Out);
                }
            }
            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return SPNTickets;
        }

        public static IEnumerable<SPNTicket> Request_SPNTicket(Args_Get_DomainSPNTicket args = null)
        {
            return Get_DomainSPNTicket(args);
        }

        public static IEnumerable<ComputerSite> Get_NetComputerSiteName(Args_Get_NetComputerSiteName args = null)
        {
            if (args == null) args = new Args_Get_NetComputerSiteName();
            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation { Credential = args.Credential });
            }

            var ComputerSites = new List<ComputerSite>();
            foreach (var item in args.ComputerName)
            {
                string IPAddress;
                var Computer = item;
                //if we get an IP address, try to resolve the IP to a hostname
                if (Computer.IsRegexMatch(@"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"))
                {
                    IPAddress = Computer;
                    Computer = System.Net.Dns.GetHostEntry(Computer).HostName;
                }
                else
                {
                    IPAddress = Resolve_IPAddress(new Args_Resolve_IPAddress { ComputerName = new[] { Computer } }).First().IPAddress;
                }

                var PtrInfo = IntPtr.Zero;

                var Result = NativeMethods.DsGetSiteName(Computer, out PtrInfo);

                var ComputerSite = new ComputerSite
                {
                    ComputerName = Computer,
                    IPAddress = IPAddress
                };

                if (Result == 0)
                {
                    var Sitename = System.Runtime.InteropServices.Marshal.PtrToStringAuto(PtrInfo);
                    ComputerSite.SiteName = Sitename;
                }
                else
                {
                    Logger.Write_Verbose($@"[Get-NetComputerSiteName] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");

                    ComputerSite.SiteName = @"";
                }

                // free up the result buffer
                NativeMethods.NetApiBufferFree(PtrInfo);

                ComputerSites.Add(ComputerSite);
            }
            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return ComputerSites;
        }

        public static IEnumerable<ComputerSite> Get_SiteName(Args_Get_NetComputerSiteName args = null)
        {
            return Get_NetComputerSiteName(args);
        }

        public static IEnumerable<object> Get_DomainGPO(Args_Get_DomainGPO args = null)
        {
            if (args == null) args = new Args_Get_DomainGPO();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                Domain = args.Domain,
                Properties = args.Properties,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                SecurityMasks = args.SecurityMasks,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var GPOSearcher = Get_DomainSearcher(SearcherArguments);

            var GPOs = new List<object>();
            if (GPOSearcher != null)
            {
                if (args.ComputerIdentity != null || args.UserIdentity != null)
                {
                    var GPOAdsPaths = new List<string>();
                    string[] OldProperties = null;
                    if (SearcherArguments.Properties != null)
                    {
                        OldProperties = SearcherArguments.Properties;
                    }
                    SearcherArguments.Properties = new[] { @"distinguishedname", @"dnshostname" };
                    string TargetComputerName = null;
                    string ObjectDN = null;

                    if (args.ComputerIdentity.IsNotNullOrEmpty())
                    {
                        var Computer = Get_DomainComputer(new Args_Get_DomainComputer(SearcherArguments)
                        {
                            Identity = new[] { args.ComputerIdentity },
                            FindOne = true
                        }).First() as LDAPProperty;
                        if (Computer == null)
                        {
                            Logger.Write_Verbose($@"[Get-DomainGPO] Computer '{args.ComputerIdentity}' not found!");
                        }
                        ObjectDN = Computer.distinguishedname;
                        TargetComputerName = Computer.dnshostname;
                    }
                    else
                    {
                        var User = Get_DomainUser(new Args_Get_DomainUser(SearcherArguments)
                        {
                            Identity = new[] { args.UserIdentity },
                            FindOne = true
                        }) as LDAPProperty;
                        if (User == null)
                        {
                            Logger.Write_Verbose($@"[Get-DomainGPO] User '{args.UserIdentity}' not found!");
                        }
                        ObjectDN = User.distinguishedname;
                    }

                    // extract all OUs the target user/computer is a part of
                    var ObjectOUs = new List<string>();
                    foreach (var item in ObjectDN.Split(','))
                    {
                        if (item.StartsWith(@"OU="))
                        {
                            ObjectOUs.Add(ObjectDN.Substring(ObjectDN.IndexOf($@"{item},")));
                        }
                    }
                    Logger.Write_Verbose($@"[Get-DomainGPO] object OUs: {ObjectOUs}");

                    if (ObjectOUs != null)
                    {
                        // find all the GPOs linked to the user/computer's OUs
                        SearcherArguments.Properties = null;
                        var InheritanceDisabled = false;
                        foreach (var ObjectOU in ObjectOUs)
                        {
                            var ous = Get_DomainOU(new Args_Get_DomainOU(SearcherArguments)
                            {
                                Identity = new[] { ObjectOU }
                            });
                            foreach (LDAPProperty ou in ous)
                            {
                                // extract any GPO links for this particular OU the computer is a part of
                                if (ou.gplink.IsNotNullOrEmpty())
                                {
                                    foreach (var item in ou.gplink.Split(new[] { @"][" }, StringSplitOptions.None))
                                    {
                                        if (item.StartsWith(@"LDAP"))
                                        {
                                            var Parts = item.Split(';');
                                            var GpoDN = Parts[0];
                                            var Enforced = Parts[1];

                                            if (InheritanceDisabled)
                                            {
                                                // if inheritance has already been disabled and this GPO is set as "enforced"
                                                // then add it, otherwise ignore it
                                                if (Enforced == @"2")
                                                {
                                                    GPOAdsPaths.Add(GpoDN);
                                                }
                                            }
                                            else
                                            {
                                                // inheritance not marked as disabled yet
                                                GPOAdsPaths.Add(GpoDN);
                                            }
                                        }
                                    }
                                }

                                //if this OU has GPO inheritence disabled, break so additional OUs aren't processed
                                if (ou.gpoptions == 1)
                                {
                                    InheritanceDisabled = true;
                                }
                            }
                        }
                    }

                    if (TargetComputerName.IsNotNullOrEmpty())
                    {
                        // find all the GPOs linked to the computer's site
                        var ComputerSite = Get_NetComputerSiteName(new Args_Get_NetComputerSiteName { ComputerName = new[] { TargetComputerName } }).First().SiteName;
                        if (ComputerSite.IsNotNullOrEmpty() && !ComputerSite.IsLikeMatch(@"Error*"))
                        {
                            var sites = Get_DomainSite(new Args_Get_DomainSite(SearcherArguments)
                            {
                                Identity = new[] { ComputerSite }
                            });
                            foreach (LDAPProperty site in sites)
                            {
                                if (site.gplink.IsNotNullOrEmpty())
                                {
                                    // extract any GPO links for this particular site the computer is a part of
                                    foreach (var item in site.gplink.Split(new[] { @"][" }, StringSplitOptions.None))
                                    {
                                        if (item.StartsWith(@"LDAP"))
                                        {
                                            GPOAdsPaths.Add(item.Split(';')[0]);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // find any GPOs linked to the user/computer's domain
                    var ObjectDomainDN = ObjectDN.Substring(ObjectDN.IndexOf(@"DC="));
                    SearcherArguments.Properties = null;
                    SearcherArguments.LDAPFilter = $@"(objectclass=domain)(distinguishedname={ObjectDomainDN})";
                    var objs = Get_DomainObject(new Args_Get_DomainObject(SearcherArguments));
                    foreach (LDAPProperty obj in objs)
                    {
                        if (obj.gplink.IsNotNullOrEmpty())
                        {
                            // extract any GPO links for this particular domain the computer is a part of
                            foreach (var item in obj.gplink.Split(new[] { @"][" }, StringSplitOptions.None))
                            {
                                if (item.StartsWith(@"LDAP"))
                                {
                                    GPOAdsPaths.Add(item.Split(';')[0]);
                                }
                            }
                        }
                    }
                    Logger.Write_Verbose($@"[Get-DomainGPO] GPOAdsPaths: {GPOAdsPaths}");

                    // restore the old properites to return, if set
                    if (OldProperties != null) { SearcherArguments.Properties = OldProperties; }
                    else { SearcherArguments.Properties = null; }

                    foreach (var path in GPOAdsPaths.Where(x => x != null && x != ""))
                    {
                        // use the gplink as an ADS path to enumerate all GPOs for the computer
                        SearcherArguments.SearchBase = path;
                        SearcherArguments.LDAPFilter = @"(objectCategory=groupPolicyContainer)";
                        objs = Get_DomainObject(new Args_Get_DomainObject(SearcherArguments));
                        foreach (LDAPProperty obj in objs)
                        {
                            GPOs.Add(new GPO(obj));
                        }
                    }
                }
                else
                {
                    var IdentityFilter = @"";
                    var Filter = @"";
                    if (args.Identity != null)
                    {
                        foreach (var item in args.Identity)
                        {
                            var IdentityInstance = item.Replace(@"(", @"\28").Replace(@")", @"\29");
                            if (IdentityInstance.IsRegexMatch(@"LDAP://|^CN=.*"))
                            {
                                IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                                if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                                {
                                    // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                    // and rebuild the domain searcher
                                    var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                    Logger.Write_Verbose($@"[Get-DomainGPO] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                    SearcherArguments.Domain = IdentityDomain;
                                    GPOSearcher = Get_DomainSearcher(SearcherArguments);
                                    if (GPOSearcher == null)
                                    {
                                        Logger.Write_Warning($@"[Get-DomainGPO] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                    }
                                }
                            }
                            else if (IdentityInstance.IsRegexMatch(@"{.*}"))
                            {
                                IdentityFilter += $@"(name={IdentityInstance})";
                            }
                            else
                            {
                                try
                                {
                                    var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                                    IdentityFilter += $@"(objectguid={GuidByteString})";
                                }
                                catch
                                {
                                    IdentityFilter += $@"(displayname={IdentityInstance})";
                                }
                            }
                        }
                    }

                    if (IdentityFilter != null && IdentityFilter.Trim() != @"")
                    {
                        Filter += $@"(|{IdentityFilter})";
                    }

                    if (args.LDAPFilter.IsNotNullOrEmpty())
                    {
                        Logger.Write_Verbose($@"[Get-DomainGPO] Using additional LDAP filter: {args.LDAPFilter}");
                        Filter += $@"{args.LDAPFilter}";
                    }

                    GPOSearcher.Filter = $@"(&(objectCategory=groupPolicyContainer){Filter})";
                    Logger.Write_Verbose($@"[Get-DomainGPO] filter string: {GPOSearcher.Filter}");

                    SearchResult[] Results = null;
                    if (args.FindOne) { Results = new SearchResult[] { GPOSearcher.FindOne() }; }
                    else
                    {
                        var items = GPOSearcher.FindAll();
                        if (items != null)
                        {
                            Results = new SearchResult[items.Count];
                            items.CopyTo(Results, 0);
                        }
                    }
                    if (Results != null)
                    {
                        foreach (var result in Results)
                        {
                            if (args.Raw)
                            {
                                // return raw result objects
                                GPOs.Add(result);
                            }
                            else
                            {
                                GPO GPO;
                                if (args.SearchBase.IsNotNullOrEmpty() && args.SearchBase.IsRegexMatch(@"^GC://"))
                                {
                                    GPO = new GPO(Convert_LDAPProperty(result.Properties));
                                    try
                                    {
                                        var GPODN = GPO.distinguishedname;
                                        var GPODomain = GPODN.Substring(GPODN.IndexOf(@"DC=")).Replace(@"DC=", @"").Replace(@",", @".");
                                        var gpcfilesyspath = $@"\\{GPODomain}\SysVol\{GPODomain}\Policies\{GPO.cn}";
                                        GPO.gpcfilesyspath = gpcfilesyspath;
                                    }
                                    catch
                                    {
                                        Logger.Write_Verbose($@"[Get-DomainGPO] Error calculating gpcfilesyspath for: {GPO.distinguishedname}");
                                    }
                                }
                                else
                                {
                                    GPO = new GPO(Convert_LDAPProperty(result.Properties));
                                }
                                GPOs.Add(GPO);
                            }
                        }
                    }
                }
                GPOSearcher.Dispose();
            }
            return GPOs;
        }

        public static IEnumerable<object> Get_NetGPO(Args_Get_DomainGPO args = null)
        {
            return Get_DomainGPO(args);
        }

        public static void Set_DomainObject(Args_Set_DomainObject args = null)
        {
            var SearcherArguments = new Args_Get_DomainObject
            {
                Identity = args.Identity,
                Raw = true,
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            // splat the appropriate arguments to Get-DomainObject
            var RawObject = Get_DomainObject(SearcherArguments);

            foreach (SearchResult obj in RawObject)
            {
                var Entry = obj.GetDirectoryEntry();

                if (args.Set != null)
                {
                    try
                    {
                        foreach (var set in args.Set)
                        {
                            Logger.Write_Verbose($@"[Set-DomainObject] Setting '{set.Key}' to '{set.Value}' for object '{obj.Properties[@"samaccountname"][0]}'");

                            Entry.InvokeSet(set.Key, new[] { set.Value });
                        }
                        Entry.CommitChanges();
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Warning($@"[Set-DomainObject] Error setting/replacing properties for object '{obj.Properties[@"samaccountname"][0]}' : {e}");
                    }
                }
                if (args.XOR != null)
                {
                    try
                    {
                        foreach (var xor in args.XOR)
                        {
                            var PropertyName = xor.Key;
                            var PropertyXorValue = (int)xor.Value;
                            Logger.Write_Verbose($@"[Set-DomainObject] XORing '{PropertyName}' with '{PropertyXorValue}' for object '{obj.Properties[@"samaccountname"][0]}'");
                            var TypeName = Entry.Properties[PropertyName][0].GetType();

                            // UAC value references- https://support.microsoft.com/en-us/kb/305144
                            var PropertyValue = (int)Entry.Properties[PropertyName][0] ^ PropertyXorValue;
                            Entry.Properties[PropertyName][0] = PropertyValue;
                        }
                        Entry.CommitChanges();
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Warning($@"[Set-DomainObject] Error XOR'ing properties for object '{obj.Properties[@"samaccountname"][0]}' : {e}");
                    }
                }
                if (args.Clear != null)
                {
                    try
                    {
                        foreach (var clear in args.Clear)
                        {
                            var PropertyName = clear;
                            Logger.Write_Verbose($@"[Set-DomainObject] Clearing '{PropertyName}' for object '{obj.Properties[@"samaccountname"][0]}'");
                            Entry.Properties[PropertyName].Clear();
                        }
                        Entry.CommitChanges();
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Warning($@"[Set-DomainObject] Error clearing properties for object '{obj.Properties[@"samaccountname"][0]}' : {e}");
                    }
                }
            }
        }

        public static void Set_ADObject(Args_Set_DomainObject args = null)
        {
            Set_DomainObject(args);
        }

        public static void Add_RemoteConnection(Args_Add_RemoteConnection args = null)
        {
            if (args == null) args = new Args_Add_RemoteConnection();

            var NetResourceInstance = Activator.CreateInstance(typeof(NetResource)) as NetResource;
            NetResourceInstance.ResourceType = NativeMethods.ResourceType.Disk;

            var Paths = new List<string>();
            if (args.ComputerName != null)
            {
                foreach (var item in args.ComputerName)
                {
                    var TargetComputerName = item;
                    TargetComputerName = TargetComputerName.Trim('\\');
                    Paths.Add($@"\\{TargetComputerName}\IPC$");
                }
            }
            else
            {
                Paths.AddRange(args.Path);
            }

            foreach (var TargetPath in Paths)
            {
                NetResourceInstance.RemoteName = TargetPath;
                Logger.Write_Verbose($@"[Add-RemoteConnection] Attempting to mount: {TargetPath}");

                // https://msdn.microsoft.com/en-us/library/windows/desktop/aa385413(v=vs.85).aspx
                //   CONNECT_TEMPORARY = 4
                var Result = NativeMethods.WNetAddConnection2(NetResourceInstance, args.Credential.Password, args.Credential.UserName, 4);

                if (Result == 0)
                {
                    Logger.Write_Verbose($@"{TargetPath} successfully mounted");
                }
                else
                {
                    throw new Exception($@"[Add-RemoteConnection] error mounting {TargetPath} : {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }
        }

        public static void Remove_RemoteConnection(Args_Remove_RemoteConnection args = null)
        {
            if (args == null) args = new Args_Remove_RemoteConnection();

            var Paths = new List<string>();
            if (args.ComputerName != null)
            {
                foreach (var item in args.ComputerName)
                {
                    var TargetComputerName = item;
                    TargetComputerName = TargetComputerName.Trim('\\');
                    Paths.Add($@"\\{TargetComputerName}\IPC$");
                }
            }
            else
            {
                Paths.AddRange(args.Path);
            }

            foreach (var TargetPath in Paths)
            {
                Logger.Write_Verbose($@"[Remove-RemoteConnection] Attempting to unmount: {TargetPath}");
                var Result = NativeMethods.WNetCancelConnection2(TargetPath, 0, true);

                if (Result == 0)
                {
                    Logger.Write_Verbose($@"{TargetPath} successfully ummounted");
                }
                else
                {
                    throw new Exception($@"[Add-RemoteConnection] error mounting {TargetPath} : {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }
        }

        public static IEnumerable<Dictionary<string, Dictionary<string, object>>> Get_IniContent(Args_Get_IniContent args = null)
        {
            if (args == null) args = new Args_Get_IniContent();

            var MappedComputers = new Dictionary<string, bool>();

            var IniObjects = new List<Dictionary<string, Dictionary<string, object>>>();

            foreach (var TargetPath in args.Path)
            {
                if (TargetPath.IsRegexMatch(@"\\\\.*\\.*") && args.Credential != null)
                {
                    var HostComputer = new System.Uri(TargetPath).Host;
                    if (!MappedComputers[HostComputer])
                    {
                        // map IPC$ to this computer if it's not already
                        Add_RemoteConnection(new Args_Add_RemoteConnection { ComputerName = new[] { HostComputer }, Credential = args.Credential });
                        MappedComputers[HostComputer] = true;
                    }
                }

                if (System.IO.File.Exists(TargetPath))
                {
                    var IniObject = new Dictionary<string, Dictionary<string, object>>();
                    var content = System.IO.File.ReadAllLines(TargetPath);
                    var CommentCount = 0;
                    var Section = "";
                    foreach (var line in content)
                    {
                        if (line.IsRegexMatch(@"^\[(.+)\]"))
                        {
                            Section = line.GetRegexGroups(@"^\[(.+)\]")[1].Value.Trim();
                            IniObject[Section] = new Dictionary<string, object>();
                            CommentCount = 0;
                        }
                        else if (line.IsRegexMatch(@"^(;.*)$"))
                        {
                            var Value = line.GetRegexGroups(@"^(;.*)$")[1].Value.Trim();
                            CommentCount = CommentCount + 1;
                            var Name = @"Comment" + CommentCount;
                            IniObject[Section][Name] = Value;
                        }
                        else if (line.IsRegexMatch(@"(.+?)\s*=(.*)"))
                        {
                            var matches = line.GetRegexGroups(@"^(;.*)$");
                            var Name = matches[1].Value;
                            var Value = matches[2].Value;
                            Name = Name.Trim();
                            var Values = Value.Split(',').Select(x => x.Trim());

                            // if ($Values -isnot [System.Array]) { $Values = @($Values) }

                            IniObject[Section][Name] = Values;
                        }
                    }
                    IniObjects.Add(IniObject);
                }
            }

            // remove the IPC$ mappings
            foreach (var key in MappedComputers.Keys)
            {
                Remove_RemoteConnection(new Args_Remove_RemoteConnection { ComputerName = new[] { key } });
            }

            return IniObjects;
        }

        public static IEnumerable<GptTmpl> Get_GptTmpl(Args_Get_GptTmpl args = null)
        {
            if (args == null) args = new Args_Get_GptTmpl();
            var MappedPaths = new Dictionary<string, bool>();

            var GptTmpls = new List<GptTmpl>();
            try
            {
                if (args.GptTmplPath.IsRegexMatch(@"\\\\.*\\.*") && args.Credential != null)
                {
                    var SysVolPath = $@"\\{new System.Uri(args.GptTmplPath).Host}\SYSVOL";
                    if (!MappedPaths[SysVolPath])
                    {
                        // map IPC$ to this computer if it's not already
                        Add_RemoteConnection(new Args_Add_RemoteConnection { Path = new[] { SysVolPath }, Credential = args.Credential });
                        MappedPaths[SysVolPath] = true;
                    }
                }

                var TargetGptTmplPath = args.GptTmplPath;
                if (TargetGptTmplPath.EndsWith(@".inf"))
                {
                    TargetGptTmplPath += @"\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf";
                }

                Logger.Write_Verbose($@"[Get-GptTmpl] Parsing GptTmplPath: {TargetGptTmplPath}");

                var Contents = Get_IniContent(new Args_Get_IniContent { Path = new[] { TargetGptTmplPath } });
                if (Contents != null)
                {
                    GptTmpls.Add(new GptTmpl(Contents.FirstOrDefault()) { Path = TargetGptTmplPath });
                }
            }
            catch (Exception e)
            {
                Logger.Write_Verbose($@"[Get-GptTmpl] Error parsing $TargetGptTmplPath : {e}");
            }
            // remove the SYSVOL mappings
            foreach (var key in MappedPaths.Keys)
            {
                Remove_RemoteConnection(new Args_Remove_RemoteConnection { Path = new[] { key } });
            }

            return GptTmpls;
        }


        public static IEnumerable<GroupsXML> Get_GroupsXML(Args_Get_GroupsXML args = null)
        {
            if (args == null) args = new Args_Get_GroupsXML();
            var MappedPaths = new Dictionary<string, bool>();
            var GroupsXMLs = new List<GroupsXML>();

            try
            {
                if (args.GroupsXMLPath.IsRegexMatch(@"\\\\.*\\.*") && args.Credential != null)
                {
                    var SysVolPath = $@"\\{new System.Uri(args.GroupsXMLPath).Host}\SYSVOL";
                    if (!MappedPaths[SysVolPath])
                    {
                        // map IPC$ to this computer if it's not already
                        Add_RemoteConnection(new Args_Add_RemoteConnection { Path = new[] { SysVolPath }, Credential = args.Credential });
                        MappedPaths[SysVolPath] = true;
                    }
                }

                XmlDocument GroupsXMLcontent = new XmlDocument();
                GroupsXMLcontent.Load(args.GroupsXMLPath);

                // process all group properties in the XML
                var nodes = GroupsXMLcontent.SelectNodes(@"/Groups/Group");
                foreach (XmlNode node in nodes)
                {
                    var GroupName = node["groupName"].InnerText;

                    // extract the localgroup sid for memberof
                    var GroupSID = node[@"groupSid"].InnerText;
                    if (GroupSID.IsNotNullOrEmpty())
                    {
                        if (GroupName.IsRegexMatch(@"Administrators"))
                        {
                            GroupSID = @"S-1-5-32-544";
                        }
                        else if (GroupName.IsRegexMatch(@"Remote Desktop"))
                        {
                            GroupSID = @"S-1-5-32-555";
                        }
                        else if (GroupName.IsRegexMatch(@"Guests"))
                        {
                            GroupSID = @"S-1-5-32-546";
                        }
                        else
                        {
                            if (args.Credential != null)
                            {
                                GroupSID = ConvertTo_SID(new Args_ConvertTo_SID { ObjectName = new[] { GroupName }, Credential = args.Credential }).FirstOrDefault();
                            }
                            else
                            {
                                GroupSID = ConvertTo_SID(new Args_ConvertTo_SID { ObjectName = new[] { GroupName } }).FirstOrDefault();
                            }
                        }
                    }

                    // extract out members added to this group
                    var Members = new List<string>();
                    foreach (XmlNode member in node["members"].SelectNodes("//Member"))
                    {
                        if (member["action"].InnerText.IsRegexMatch("ADD"))
                        {
                            if (member["sid"] != null) { Members.Add(member["sid"].InnerText); }
                            else { Members.Add(member["name"].InnerText); }
                        }

                        if (Members != null)
                        {
                            // extract out any/all filters...I hate you GPP
                            var Filters = new List<Filter>();

                            if (node.Attributes != null)
                            {
                                foreach (XmlAttribute filter in node.Attributes)
                                {
                                    Filters.Add(new Filter { Type = filter.LocalName, Value = filter.Name });
                                }
                            }
                            else
                            {
                                Filters = null;
                            }

                            var GroupsXML = new GroupsXML
                            {
                                GPOPath = args.GroupsXMLPath,
                                Filters = Filters,
                                GroupName = GroupName,
                                GroupSID = GroupSID,
                                GroupMemberOf = null,
                                GroupMembers = Members
                            };
                            GroupsXMLs.Add(GroupsXML);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Logger.Write_Verbose($@"[Get-GroupsXML] Error parsing {args.GroupsXMLPath} : {e}");
            }
            // remove the SYSVOL mappings
            foreach (var key in MappedPaths.Keys)
            {
                Remove_RemoteConnection(new Args_Remove_RemoteConnection { Path = new[] { key } });
            }
            return GroupsXMLs;
        }

        public static IEnumerable<Returns.DomainPolicyData> Get_DomainPolicyData(Args_Get_DomainPolicyData args = null)
        {
            var SearcherArguments = new Args_Get_DomainGPO
            {
                Server = args.Server,
                ServerTimeLimit = args.ServerTimeLimit,
                Credential = args.Credential
            };

            if (args.Domain.IsNotNullOrEmpty())
            {
                SearcherArguments.Domain = args.Domain;
            }

            if (args.Policy == "All")
            {
                SearcherArguments.Identity = new[] { @"*" };
            }
            else if (args.Policy == @"Domain")
            {
                SearcherArguments.Identity = new[] { @"{31B2F340-016D-11D2-945F-00C04FB984F9}" };
            }
            else if (args.Policy == @"DomainController" || args.Policy == @"DC")
            {
                SearcherArguments.Identity = new[] { @"{6AC1786C-016F-11D2-945F-00C04FB984F9}" };
            }
            else
            {
                SearcherArguments.Identity = new[] { args.Policy };
            }

            var DomainPolicyData = new List<DomainPolicyData>();

            var GPOResults = Get_DomainGPO(SearcherArguments);

            foreach (GPO GPO in GPOResults)
            {
                // grab the GptTmpl.inf file and parse it
                var GptTmplPath = GPO.gpcfilesyspath + @"\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf";

                var ParseArgs = new Args_Get_GptTmpl
                {
                    GptTmplPath = GptTmplPath
                };
                if (args.Credential != null) { ParseArgs.Credential = args.Credential; }

                // parse the GptTmpl.inf
                IEnumerable<GptTmpl> gpts = Get_GptTmpl(ParseArgs);
                foreach (var gpt in gpts)
                {
                    DomainPolicyData.Add(new Returns.DomainPolicyData(gpt)
                    {
                        GPOName = GPO.name,
                        GPODisplayName = GPO.displayname
                    });
                }
            }
            return DomainPolicyData;
        }

        public static IEnumerable<Returns.DomainPolicyData> Get_DomainPolicy(Args_Get_DomainPolicyData args = null)
        {
            return Get_DomainPolicyData(args);
        }

        public static IEnumerable<GPOGroup> Get_DomainGPOLocalGroup(Args_Get_DomainGPOLocalGroup args = null)
        {
            if (args == null) args = new Args_Get_DomainGPOLocalGroup();

            var SearcherArguments = new Args_Get_DomainGPO
            {
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var ConvertArguments = new Args_ConvertFrom_SID
            {
                Domain = args.Domain,
                Server = args.Server,
                Credential = args.Credential
            };

            var SplitOption = System.StringSplitOptions.RemoveEmptyEntries;

            SearcherArguments.Identity = args.Identity;

            var GPOGroups = new List<GPOGroup>();
            var gpos = Get_DomainGPO(SearcherArguments);
            foreach (GPO gpo in gpos)
            {
                var GPODisplayName = gpo.displayname;
                var GPOName = gpo.name;
                var GPOPath = gpo.gpcfilesyspath;

                var ParseArgs = new Args_Get_GptTmpl
                {
                    GptTmplPath = $@"{GPOPath}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf",
                };
                if (args.Credential != null) { ParseArgs.Credential = args.Credential; }

                // first parse the 'Restricted Groups' file (GptTmpl.inf) if it exists
                IEnumerable<GptTmpl> gpts = Get_GptTmpl(ParseArgs);

                var Inf = gpts.FirstOrDefault();

                if (Inf != null && Inf["psbase"].Keys.Contains("Group Membership"))
                {
                    var Memberships = new Dictionary<string, IDictionary<string, IEnumerable<string>>>();

                    // parse the members/memberof fields for each entry
                    foreach (var Membership in Inf["Group Membership"])
                    {
                        var Group_Relation = Membership.Key.Split(new[] { "__" }, SplitOption);
                        var Group = Group_Relation[0].Trim();
                        var Relation = Group_Relation[1].Trim();
                        //# extract out ALL members
                        var MembershipValue = (Membership.Value as Dictionary<string, object>).Select(x => (x.Value as string).Trim());

                        if (args.ResolveMembersToSIDs)
                        {
                            // if the resulting member is username and not a SID, attempt to resolve it
                            var GroupMembers = new List<string>();
                            foreach (var Member in MembershipValue)
                            {
                                if (Member != null && Member.Trim() != "")
                                {
                                    if (!Member.IsRegexMatch("^S-1-.*"))
                                    {
                                        var ConvertToArguments = new Args_ConvertTo_SID { ObjectName = new[] { Member } };
                                        if (args.Domain.IsNotNullOrEmpty()) { ConvertToArguments.Domain = args.Domain; }
                                        var MemberSID = ConvertTo_SID(ConvertToArguments).FirstOrDefault();

                                        if (MemberSID.IsNotNullOrEmpty())
                                        {
                                            GroupMembers.Add(MemberSID);
                                        }
                                        else
                                        {
                                            GroupMembers.Add(Member);
                                        }
                                    }
                                    else
                                    {
                                        GroupMembers.Add(Member);
                                    }
                                }
                            }
                            MembershipValue = GroupMembers;
                        }

                        if (Memberships[Group] == null)
                        {
                            Memberships[Group] = new Dictionary<string, IEnumerable<string>>();
                        }
                        Memberships[Group].Add(Relation, MembershipValue);
                    }

                    foreach (var Membership in Memberships)
                    {
                        string GroupName = null;
                        string GroupSID = null;
                        if (Membership.Key.IsNotNullOrEmpty() && Membership.Key.IsRegexMatch(@"^\*"))
                        {
                            // if the SID is already resolved (i.e. begins with *) try to resolve SID to a name
                            GroupSID = Membership.Key.Trim('*');
                            if (GroupSID != null && GroupSID.Trim() != "")
                            {
                                ConvertArguments.ObjectSID = new[] { GroupSID };
                                GroupName = ConvertFrom_SID(ConvertArguments).FirstOrDefault();
                            }
                            else
                            {
                                GroupName = null;
                            }
                        }
                        else
                        {
                            GroupName = Membership.Key;

                            if (GroupName != null && GroupName.Trim() != "")
                            {
                                if (GroupName.IsRegexMatch("Administrators"))
                                {
                                    GroupSID = "S-1-5-32-544";
                                }
                                else if (GroupName.IsRegexMatch("Remote Desktop"))
                                {
                                    GroupSID = "S-1-5-32-555";
                                }
                                else if (GroupName.IsRegexMatch("Guests"))
                                {
                                    GroupSID = "S-1-5-32-546";
                                }
                                else if (GroupName.Trim() != "")
                                {
                                    var ConvertToArguments = new Args_ConvertTo_SID { ObjectName = new[] { GroupName } };
                                    if (args.Domain.IsNotNullOrEmpty()) { ConvertToArguments.Domain = args.Domain; }
                                    GroupSID = ConvertTo_SID(ConvertToArguments).FirstOrDefault();
                                }
                                else
                                {
                                    GroupSID = null;
                                }
                            }
                        }

                        var GPOGroup = new GPOGroup
                        {
                            GPODisplayName = GPODisplayName,
                            GPOName = GPOName,
                            GPOPath = GPOPath,
                            GPOType = "RestrictedGroups",
                            Filters = null,
                            GroupName = GroupName,
                            GroupSID = GroupSID,
                            GroupMemberOf = Membership.Value["Memberof"],
                            GroupMembers = Membership.Value["Members"]
                        };
                        GPOGroups.Add(GPOGroup);
                    }
                }

                // now try to the parse group policy preferences file (Groups.xml) if it exists
                var ParseArgs1 = new Args_Get_GroupsXML
                {
                    GroupsXMLPath = $@"{GPOPath}\MACHINE\Preferences\Groups\Groups.xml"
                };

                var groups = Get_GroupsXML(ParseArgs1);
                foreach (var group in groups)
                {
                    if (args.ResolveMembersToSIDs)
                    {
                        var GroupMembers = new List<string>();
                        foreach (var Member in group.GroupMembers)
                        {
                            if (Member != null && Member.Trim() != "")
                            {
                                if (!Member.IsRegexMatch("^S-1-.*"))
                                {

                                    // if the resulting member is username and not a SID, attempt to resolve it
                                    var MemberSID = ConvertTo_SID(new Args_ConvertTo_SID { Domain = args.Domain, ObjectName = new[] { Member } }).FirstOrDefault();

                                    if (MemberSID.IsNotNullOrEmpty())
                                    {
                                        GroupMembers.Add(MemberSID);
                                    }
                                    else
                                    {
                                        GroupMembers.Add(Member);
                                    }
                                }
                                else
                                {
                                    GroupMembers.Add(Member);
                                }
                            }
                        }
                        group.GroupMembers = GroupMembers;
                    }
                    var GPOGroup = new GPOGroup
                    {
                        GPODisplayName = GPODisplayName,
                        GPOName = GPOName,
                        GPOType = "GroupPolicyPreferences",
                        Filters = group.Filters,
                        GPOPath = group.GPOPath,
                        GroupMemberOf = group.GroupMemberOf,
                        GroupMembers = group.GroupMembers,
                        GroupName = group.GroupName,
                        GroupSID = group.GroupSID
                    };
                    GPOGroups.Add(GPOGroup);
                }
            }
            return GPOGroups;
        }

        public static IEnumerable<GPOGroup> Get_NetGPOGroup(Args_Get_DomainGPOLocalGroup args = null)
        {
            return Get_DomainGPOLocalGroup(args);
        }

        public static IEnumerable<GPOLocalGroupMapping> Get_DomainGPOUserLocalGroupMapping(Args_Get_DomainGPOUserLocalGroupMapping args = null)
        {
            if (args == null) args = new Args_Get_DomainGPOUserLocalGroupMapping();

            var CommonArguments = new Args_Get_DomainObject
            {
                Domain = args.Domain,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var TargetSIDs = new List<string>();
            IEnumerable<string> TargetObjectSID = null;

            if (args.Identity != null)
            {
                var sids = Get_DomainObject(new Args_Get_DomainObject(CommonArguments) { Identity = new[] { args.Identity } }).Select(x => (x as LDAPProperty).objectsid);
                foreach (var sid in sids)
                {
                    TargetSIDs.AddRange(sid);
                }
                TargetObjectSID = TargetSIDs;
                if (TargetSIDs != null)
                {
                    throw new Exception($@"[Get-DomainGPOUserLocalGroupMapping] Unable to retrieve SID for identity '{args.Identity}'");
                }
            }
            else
            {
                // no filtering/match all
                TargetSIDs.Clear();
                TargetSIDs.Add("*");
            }

            string TargetLocalSID = null;
            if (args.LocalGroup.ToString().IsRegexMatch("S-1-5"))
            {
                TargetLocalSID = args.LocalGroup.ToString();
            }
            else if (args.LocalGroup.ToString().IsRegexMatch("Admin"))
            {
                TargetLocalSID = "S-1-5-32-544";
            }
            else
            {
                // RDP
                TargetLocalSID = "S-1-5-32-555";
            }

            if (TargetSIDs[0] != "*")
            {
                foreach (var TargetSid in TargetSIDs)
                {
                    Logger.Write_Verbose($@"[Get-DomainGPOUserLocalGroupMapping] Enumerating nested group memberships for: '{TargetSid}'");
                    var sids = Get_DomainGroup(new Args_Get_DomainGroup(CommonArguments) { Properties = new[] { "objectsid" }, MemberIdentity = new[] { TargetSid } }).Select(x => (x as LDAPProperty).objectsid);
                    foreach (var sid in sids)
                    {
                        TargetSIDs.AddRange(sid);
                    }
                }
            }

            Logger.Write_Verbose($@"[Get-DomainGPOUserLocalGroupMapping] Target localgroup SID: {TargetLocalSID}");
            Logger.Write_Verbose($@"[Get-DomainGPOUserLocalGroupMapping] Effective target domain SIDs: {TargetSIDs}");

            var GPOgroupsTmp = Get_DomainGPOLocalGroup(new Args_Get_DomainGPOLocalGroup(CommonArguments) { ResolveMembersToSIDs = true });
            var GPOgroups = new List<GPOGroup>();
            foreach (var GPOgroup in GPOgroupsTmp)
            {
                // if the locally set group is what we're looking for, check the GroupMembers ('members') for our target SID
                if (GPOgroup.GroupSID.IsRegexMatch(TargetLocalSID))
                {
                    foreach (var member in GPOgroup.GroupMembers)
                    {
                        if ((TargetSIDs[0] == "*") || (TargetSIDs.Contains(member)))
                        {
                            GPOgroups.Add(GPOgroup);
                        }
                    }
                }
                // if the group is a 'memberof' the group we're looking for, check GroupSID against the targt SIDs
                if ((GPOgroup.GroupMemberOf.Contains(TargetLocalSID)))
                {
                    if ((TargetSIDs[0] == "*") || (TargetSIDs.Contains(GPOgroup.GroupSID)))
                    {
                        GPOgroups.Add(GPOgroup);
                    }
                }
            }
            GPOgroups = GPOgroups.GroupBy(x => x.GPOName).Select(x => x.Single()).OrderBy(x => x.GPOName).ToList();
            var GPOLocalGroupMappings = new List<GPOLocalGroupMapping>();
            foreach (var group in GPOgroups)
            {
                var GPOName = group.GPODisplayName;
                var GPOGuid = group.GPOName;
                var GPOPath = group.GPOPath;
                var GPOType = group.GPOType;
                IEnumerable<string> GPOMembers = null;
                if (group.GroupMembers != null)
                {
                    GPOMembers = group.GroupMembers;
                }
                else
                {
                    GPOMembers = new[] { group.GroupSID };
                }

                var Filters = group.Filters;

                IEnumerable<string> TargetObjectSIDs = null;
                if (TargetSIDs[0] == "*")
                {
                    // if the * wildcard was used, set the targets to all GPO members so everything it output
                    TargetObjectSIDs = GPOMembers;
                }
                else
                {
                    TargetObjectSIDs = TargetObjectSID;
                }

                // find any OUs that have this GPO linked through gpLink
                var ous = Get_DomainOU(new Args_Get_DomainOU(CommonArguments) { Raw = true, Properties = new[] { "name", "distinguishedname" }, GPLink = GPOGuid });
                foreach (LDAPProperty ou in ous)
                {
                    IEnumerable<string> OUComputers = null;
                    if (Filters != null)
                    {
                        OUComputers = Get_DomainComputer(new Args_Get_DomainComputer(CommonArguments) { Properties = new[] { "dnshostname", "distinguishedname" }, SearchBase = ou.path })
                            .Where(x => (x as LDAPProperty).distinguishedname.IsRegexMatch(Filters.FirstOrDefault().Value))
                            .Select(x => (x as LDAPProperty).dnshostname);
                    }
                    else
                    {
                        OUComputers = Get_DomainComputer(new Args_Get_DomainComputer(CommonArguments) { Properties = new[] { "dnshostname" }, SearchBase = ou.path })
                            .Where(x => (x as LDAPProperty).distinguishedname.IsRegexMatch(Filters.FirstOrDefault().Value))
                            .Select(x => (x as LDAPProperty).dnshostname);
                    }

                    if (OUComputers != null)
                    {
                        foreach (var TargetSid in TargetObjectSIDs)
                        {
                            var Object = Get_DomainObject(new Args_Get_DomainObject(CommonArguments) { Identity = new[] { TargetSid }, Properties = new[] { "samaccounttype", "samaccountname", "distinguishedname", "objectsid" } }).FirstOrDefault() as LDAPProperty;

                            var IsGroup = new List<SamAccountType> { SamAccountType.GROUP_OBJECT, SamAccountType.NON_SECURITY_GROUP_OBJECT, SamAccountType.ALIAS_OBJECT, SamAccountType.NON_SECURITY_ALIAS_OBJECT }
                                .Contains(Object.samaccounttype.Value);

                            var GPOLocalGroupMapping = new GPOLocalGroupMapping
                            {
                                ObjectName = Object.samaccountname,
                                ObjectDN = Object.distinguishedname,
                                ObjectSID = Object.objectsid,
                                Domain = args.Domain,
                                IsGroup = IsGroup,
                                GPODisplayName = GPOName,
                                GPOGuid = GPOGuid,
                                GPOPath = GPOPath,
                                GPOType = GPOType,
                                ContainerName = ou.distinguishedname,
                                ComputerName = OUComputers
                            };
                            GPOLocalGroupMappings.Add(GPOLocalGroupMapping);
                        }
                    }
                }

                // find any sites that have this GPO linked through gpLink
                var sites = Get_DomainSite(new Args_Get_DomainSite(CommonArguments) { Properties = new[] { "siteobjectbl", "distinguishedname" }, GPLink = GPOGuid });
                foreach (LDAPProperty site in sites)
                {
                    foreach (var TargetSid in TargetObjectSIDs)
                    {
                        var Object = Get_DomainObject(new Args_Get_DomainObject(CommonArguments) { Identity = new[] { TargetSid }, Properties = new[] { "samaccounttype", "samaccountname", "distinguishedname", "objectsid" } }).FirstOrDefault() as LDAPProperty;

                        var IsGroup = new List<SamAccountType> { SamAccountType.GROUP_OBJECT, SamAccountType.NON_SECURITY_GROUP_OBJECT, SamAccountType.ALIAS_OBJECT, SamAccountType.NON_SECURITY_ALIAS_OBJECT }
                            .Contains(Object.samaccounttype.Value);

                        var GPOLocalGroupMapping = new GPOLocalGroupMapping
                        {
                            ObjectName = Object.samaccountname,
                            ObjectDN = Object.distinguishedname,
                            ObjectSID = Object.objectsid,
                            Domain = args.Domain,
                            IsGroup = IsGroup,
                            GPODisplayName = GPOName,
                            GPOGuid = GPOGuid,
                            GPOPath = GPOPath,
                            GPOType = GPOType,
                            ContainerName = site.distinguishedname,
                            ComputerName = new[] { site.siteobjectbl }
                        };
                        GPOLocalGroupMappings.Add(GPOLocalGroupMapping);
                    }
                }
            }

            return GPOLocalGroupMappings;
        }

        public static IEnumerable<GPOLocalGroupMapping> Find_GPOLocation(Args_Get_DomainGPOUserLocalGroupMapping args = null)
        {
            return Get_DomainGPOUserLocalGroupMapping(args);
        }

        public static IEnumerable<GPOComputerLocalGroupMember> Get_DomainGPOComputerLocalGroupMapping(Args_Get_DomainGPOComputerLocalGroupMapping args = null)
        {
            if (args == null) args = new Args_Get_DomainGPOComputerLocalGroupMapping();

            var CommonArguments = new Args_Get_DomainObject
            {
                Domain = args.Domain,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var GPOComputerLocalGroupMembers = new List<GPOComputerLocalGroupMember>();
            if (args.ComputerIdentity.IsNotNullOrEmpty())
            {
                var Computers = Get_DomainComputer(new Args_Get_DomainComputer(CommonArguments) { Identity = new[] { args.ComputerIdentity }, Properties = new[] { "distinguishedname", "dnshostname" } });

                if (Computers == null)
                {
                    throw new Exception($@"[Get-DomainGPOComputerLocalGroupMapping] Computer {args.ComputerIdentity} not found. Try a fully qualified host name.");
                }

                foreach (LDAPProperty Computer in Computers)
                {

                    var GPOGuids = new List<string>();

                    // extract any GPOs linked to this computer's OU through gpLink
                    var DN = Computer.distinguishedname;
                    var OUIndex = DN.IndexOf("OU=");
                    string OUName = null;
                    if (OUIndex > 0)
                    {
                        OUName = DN.Substring(OUIndex);
                    }
                    if (OUName.IsNotNullOrEmpty())
                    {
                        var ous = Get_DomainOU(new Args_Get_DomainOU(CommonArguments) { SearchBase = OUName, LDAPFilter = "(gplink=*)" });
                        foreach (LDAPProperty ou in ous)
                        {
                            var matches = ou.gplink.GetRegexGroups(@"(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}");
                            foreach (var match in matches)
                            {
                                GPOGuids.Add(match.Value);
                            }
                        }
                    }

                    // extract any GPOs linked to this computer's site through gpLink
                    Logger.Write_Verbose($@"Enumerating the sitename for: {Computer.dnshostname}");
                    var ComputerSite = Get_NetComputerSiteName(new Args_Get_NetComputerSiteName { ComputerName = new[] { Computer.dnshostname } }).FirstOrDefault().SiteName;
                    if (ComputerSite.IsNotNullOrEmpty() && !ComputerSite.IsRegexMatch("Error"))
                    {
                        var ous = Get_DomainSite(new Args_Get_DomainSite(CommonArguments) { Identity = new[] { ComputerSite }, LDAPFilter = "(gplink=*)" });
                        foreach (LDAPProperty ou in ous)
                        {
                            var matches = ou.gplink.GetRegexGroups(@"(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}");
                            foreach (var match in matches)
                            {
                                GPOGuids.Add(match.Value);
                            }
                        }
                    }

                    // process any GPO local group settings from the GPO GUID set
                    var groups = Get_DomainGPOLocalGroup(new Args_Get_DomainGPOLocalGroup(CommonArguments) { Identity = GPOGuids.ToArray() }).GroupBy(x => x.GPOName).Select(x => x.Single()).OrderBy(x => x.GPOName);
                    foreach (var group in groups)
                    {
                        var GPOGroup = group;

                        IEnumerable<string> GPOMembers = null;
                        if (GPOGroup.GroupMembers != null)
                        {
                            GPOMembers = GPOGroup.GroupMembers;
                        }
                        else
                        {
                            GPOMembers = new[] { GPOGroup.GroupSID };
                        }

                        foreach (var member in GPOMembers)
                        {
                            var Object = Get_DomainObject(new Args_Get_DomainObject(CommonArguments) { Identity = new[] { member } }).FirstOrDefault() as LDAPProperty;
                            var IsGroup = new List<SamAccountType> { SamAccountType.GROUP_OBJECT, SamAccountType.NON_SECURITY_GROUP_OBJECT, SamAccountType.ALIAS_OBJECT, SamAccountType.NON_SECURITY_ALIAS_OBJECT }
                                        .Contains(Object.samaccounttype.Value);

                            var GPOComputerLocalGroupMember = new GPOComputerLocalGroupMember
                            {
                                ComputerName = new[] { Computer.dnshostname },
                                ObjectName = Object.samaccountname,
                                ObjectDN = Object.distinguishedname,
                                ObjectSID = new[] { member },
                                IsGroup = IsGroup,
                                GPODisplayName = GPOGroup.GPODisplayName,
                                GPOGuid = GPOGroup.GPOName,
                                GPOPath = GPOGroup.GPOPath,
                                GPOType = GPOGroup.GPOType
                            };
                            GPOComputerLocalGroupMembers.Add(GPOComputerLocalGroupMember);
                        }
                    }
                }
            }
            return GPOComputerLocalGroupMembers;
        }

        public static IEnumerable<GPOComputerLocalGroupMember> Find_GPOComputerAdmin(Args_Get_DomainGPOComputerLocalGroupMapping args = null)
        {
            return Get_DomainGPOComputerLocalGroupMapping(args);
        }

        public static IEnumerable<ACL> Get_DomainObjectAcl(Args_Get_DomainObjectAcl args = null)
        {
            if (args == null) args = new Args_Get_DomainObjectAcl();

            var SearcherArguments = new Args_Get_DomainSearcher
            {
                Properties = new[] { "samaccountname", "ntsecuritydescriptor", "distinguishedname", "objectsid" },
                SecurityMasks = args.Sacl ? SecurityMasks.Sacl : SecurityMasks.Dacl,
                Domain = args.Domain,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var Searcher = Get_DomainSearcher(SearcherArguments);

            var DomainGUIDMapArguments = new Args_Get_DomainGUIDMap
            {
                Domain = args.Domain,
                Server = args.Server,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Credential = args.Credential
            };

            // get a GUID -> name mapping
            IDictionary<string, string> GUIDs = null;
            if (args.ResolveGUIDs)
            {
                GUIDs = Get_DomainGUIDMap(DomainGUIDMapArguments);
            }

            var ACLs = new List<ACL>();
            if (Searcher != null)
            {
                var IdentityFilter = "";
                var Filter = "";
                if (args.Identity != null)
                {
                    foreach (var item in args.Identity)
                    {
                        var IdentityInstance = item.Replace(@"(", @"\28").Replace(@")", @"\29");
                        if (IdentityInstance.IsRegexMatch(@"^S-1-.*"))
                        {
                            IdentityFilter += $@"(objectsid={IdentityInstance})";
                        }
                        else if (IdentityInstance.IsRegexMatch(@"^(CN|OU|DC)=.*"))
                        {
                            IdentityFilter += $@"(distinguishedname={IdentityInstance})";
                            if (args.Domain.IsNullOrEmpty() && args.SearchBase.IsNullOrEmpty())
                            {
                                // if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                                // and rebuild the domain searcher
                                var IdentityDomain = IdentityInstance.Substring(IdentityInstance.IndexOf("DC=")).Replace("DC=", "").Replace(",", ".");
                                Logger.Write_Verbose($@"[Get-DomainObjectAcl] Extracted domain '{IdentityDomain}' from '{IdentityInstance}'");
                                SearcherArguments.Domain = IdentityDomain;
                                Searcher = Get_DomainSearcher(SearcherArguments);
                                if (Searcher == null)
                                {
                                    Logger.Write_Warning($@"[Get-DomainObjectAcl] Unable to retrieve domain searcher for '{IdentityDomain}'");
                                }
                            }
                        }
                        else if (IdentityInstance.IsRegexMatch(@"^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$"))
                        {
                            var GuidByteString = string.Join(string.Empty, Guid.Parse(IdentityInstance).ToByteArray().Select(x => x.ToString(@"\X2")));
                            IdentityFilter += $@"(objectguid={GuidByteString})";
                        }
                        else if (IdentityInstance.Contains('.'))
                        {
                            IdentityFilter += $@"(|(samAccountName={IdentityInstance})(name={IdentityInstance})(dnshostname={IdentityInstance}))";
                        }
                        else
                        {
                            IdentityFilter += $@"(|(samAccountName={IdentityInstance})(name={IdentityInstance})(displayname={IdentityInstance}))";
                        }
                    }
                }
                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += $@"(|{IdentityFilter})";
                }

                if (args.LDAPFilter.IsNotNullOrEmpty())
                {
                    Logger.Write_Verbose($@"[Get-DomainObjectAcl] Using additional LDAP filter: {args.LDAPFilter}");
                    Filter += $@"{args.LDAPFilter}";
                }

                if (Filter.IsNotNullOrEmpty())
                {
                    Searcher.Filter = $@"(&{Filter})";
                }
                Logger.Write_Verbose($@"[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: {Searcher.Filter}");

                var Results = Searcher.FindAll();
                foreach (SearchResult result in Results)
                {
                    var Object = result.Properties;

                    string ObjectSid = null;
                    if (Object["objectsid"] != null && Object["objectsid"].Count > 0 && Object["objectsid"][0] != null)
                    {
                        ObjectSid = new System.Security.Principal.SecurityIdentifier(Object["objectsid"][0] as byte[], 0).Value;
                    }
                    else
                    {
                        ObjectSid = null;
                    }

                    try
                    {
                        var rsd = new System.Security.AccessControl.RawSecurityDescriptor(Object["ntsecuritydescriptor"][0] as byte[], 0);
                        var rawAcl = args.Sacl ? rsd.SystemAcl : rsd.DiscretionaryAcl;
                        foreach (var ace in rawAcl)
                        {
                            var acl = new ACL { Ace = ace };
                            bool Continue = false;
                            if (args.RightsFilter != null)
                            {
                                string GuidFilter = null;
                                switch (args.RightsFilter.Value)
                                {
                                    case Rights.ResetPassword:
                                        GuidFilter = "00299570-246d-11d0-a768-00aa006e0529";
                                        break;
                                    case Rights.WriteMembers:
                                        GuidFilter = "bf9679c0-0de6-11d0-a285-00aa003049e2";
                                        break;
                                    default:
                                        GuidFilter = "00000000-0000-0000-0000-000000000000";
                                        break;
                                }
                                if (ace is System.Security.AccessControl.ObjectAccessRule)
                                {
                                    if (string.Compare(((object)ace as System.Security.AccessControl.ObjectAccessRule).ObjectType.ToString(), GuidFilter, StringComparison.OrdinalIgnoreCase) == 0)
                                    {
                                        acl.ObjectDN = Object["distinguishedname"][0] as string;
                                        acl.ObjectSID = ObjectSid;
                                        Continue = true;
                                    }
                                }
                            }
                            else
                            {
                                acl.ObjectDN = Object["distinguishedname"][0] as string;
                                acl.ObjectSID = ObjectSid;
                                Continue = true;
                            }
                            if (Continue)
                            {
                                if (ace is System.Security.AccessControl.KnownAce)
                                    acl.ActiveDirectoryRights = (System.DirectoryServices.ActiveDirectoryRights)(ace as System.Security.AccessControl.KnownAce).AccessMask;
                                if (GUIDs != null)
                                {
                                    // if we're resolving GUIDs, map them them to the resolved hash table
                                    if (ace is ObjectAce)
                                    {
                                        try { (acl.Ace as ObjectAce).ObjectAceType = new Guid(GUIDs[(ace as ObjectAce).ObjectAceType.ToString()]); }
                                        catch { }
                                        try { (acl.Ace as ObjectAce).InheritedObjectAceType = new Guid(GUIDs[(ace as ObjectAce).InheritedObjectAceType.ToString()]); }
                                        catch { }
                                    }
                                    else if (ace is ObjectAccessRule)
                                    {
                                        /*try { (acl.Ace as ObjectAccessRule).ObjectType = new Guid(GUIDs[(ace as ObjectAccessRule).ObjectType.ToString()]); }
                                        catch { }
                                        try { (acl.Ace as ObjectAccessRule).InheritedObjectType = new Guid(GUIDs[(ace as ObjectAccessRule).InheritedObjectType.ToString()]); }
                                        catch { }*/
                                    }
                                }

                                ACLs.Add(acl);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[Get-DomainObjectAcl] Error: {e}");
                    }
                }
            }
            return ACLs;
        }

        public static IEnumerable<ACL> Get_ObjectAcl(Args_Get_DomainObjectAcl args = null)
        {
            return Get_DomainObjectAcl(args);
        }

        public static void Add_DomainObjectAcl(Args_Add_DomainObjectAcl args = null)
        {
            if (args == null) args = new Args_Add_DomainObjectAcl();

            var TargetSearcherArguments = new Args_Get_DomainObject
            {
                Properties = new[] { "distinguishedname" },
                Raw = true,
                Domain = args.TargetDomain,
                LDAPFilter = args.TargetLDAPFilter,
                SearchBase = args.TargetSearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var PrincipalSearcherArguments = new Args_Get_DomainObject
            {
                Identity = args.PrincipalIdentity,
                Properties = new[] { "distinguishedname", "objectsid" },
                Domain = args.PrincipalDomain,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var Principals = Get_DomainObject(PrincipalSearcherArguments);
            if (Principals == null)
            {
                throw new Exception($@"Unable to resolve principal: {args.PrincipalIdentity}");
            }

            TargetSearcherArguments.Identity = args.TargetIdentity;
            var Targets = Get_DomainObject(TargetSearcherArguments);

            foreach (SearchResult TargetObject in Targets)
            {
                var InheritanceType = System.DirectoryServices.ActiveDirectorySecurityInheritance.None;
                var ControlType = System.Security.AccessControl.AccessControlType.Allow;
                var ACEs = new List<System.DirectoryServices.ActiveDirectoryAccessRule>();

                var GUIDs = new List<string>();
                if (args.RightsGUID != null)
                {
                    GUIDs.Add(args.RightsGUID.ToString());
                }
                else
                {
                    switch (args.Rights)
                    {
                        // ResetPassword doesn't need to know the user's current password
                        case Rights.ResetPassword:
                            GUIDs.Add("00299570-246d-11d0-a768-00aa006e0529");
                            break;
                        // allows for the modification of group membership
                        case Rights.WriteMembers:
                            GUIDs.Add("bf9679c0 -0de6-11d0-a285-00aa003049e2");
                            break;
                        // 'DS-Replication-Get-Changes' = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                        // 'DS-Replication-Get-Changes-All' = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                        // 'DS-Replication-Get-Changes-In-Filtered-Set' = 89e95b76-444d-4c62-991a-0facbeda640c
                        // when applied to a domain's ACL, allows for the use of DCSync
                        case Rights.DCSync:
                            GUIDs.Add("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
                            GUIDs.Add("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
                            GUIDs.Add("89e95b76-444d-4c62-991a-0facbeda640c");
                            break;
                    }
                }

                foreach (LDAPProperty PrincipalObject in Principals)
                {
                    Logger.Write_Verbose($@"[Add-DomainObjectAcl] Granting principal {PrincipalObject.distinguishedname} '{args.Rights}' on {TargetObject.Properties["distinguishedname"][0]}");

                    try
                    {
                        var Identity = new System.Security.Principal.SecurityIdentifier(PrincipalObject.objectsid[0]);

                        if (GUIDs != null)
                        {
                            foreach (var GUID in GUIDs)
                            {
                                var NewGUID = new Guid(GUID);
                                var ADRights = System.DirectoryServices.ActiveDirectoryRights.ExtendedRight;
                                ACEs.Add(new System.DirectoryServices.ActiveDirectoryAccessRule(Identity, ADRights, ControlType, NewGUID, InheritanceType));
                            }
                        }
                        else
                        {
                            // deault to GenericAll rights
                            var ADRights = System.DirectoryServices.ActiveDirectoryRights.GenericAll;
                            ACEs.Add(new System.DirectoryServices.ActiveDirectoryAccessRule(Identity, ADRights, ControlType, InheritanceType));
                        }

                        // add all the new ACEs to the specified object directory entry
                        foreach (var ACE in ACEs)
                        {
                            Logger.Write_Verbose($@"[Add-DomainObjectAcl] Granting principal {PrincipalObject.distinguishedname} rights GUID '{ACE.ObjectType}' on {TargetObject.Properties["distinguishedname"][0]}");
                            var TargetEntry = TargetObject.GetDirectoryEntry();
                            TargetEntry.Options.SecurityMasks = SecurityMasks.Dacl;
                            TargetEntry.ObjectSecurity.AddAccessRule(ACE);
                            TargetEntry.CommitChanges();
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[Add-DomainObjectAcl] Error granting principal {PrincipalObject.distinguishedname} '{args.Rights}' on {TargetObject.Properties["distinguishedname"][0]}: {e}");
                    }
                }
            }
        }

        public static void Add_ObjectAcl(Args_Add_DomainObjectAcl args = null)
        {
            Add_DomainObjectAcl(args);
        }

        public static void Remove_DomainObjectAcl(Args_Remove_DomainObjectAcl args = null)
        {
            if (args == null) args = new Args_Remove_DomainObjectAcl();

            var TargetSearcherArguments = new Args_Get_DomainObject
            {
                Properties = new[] { "distinguishedname" },
                Raw = true,
                Domain = args.TargetDomain,
                LDAPFilter = args.TargetLDAPFilter,
                SearchBase = args.TargetSearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var PrincipalSearcherArguments = new Args_Get_DomainObject
            {
                Identity = args.PrincipalIdentity,
                Properties = new[] { "distinguishedname", "objectsid" },
                Domain = args.PrincipalDomain,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var Principals = Get_DomainObject(PrincipalSearcherArguments);
            if (Principals == null)
            {
                throw new Exception($@"Unable to resolve principal: {args.PrincipalIdentity}");
            }

            TargetSearcherArguments.Identity = args.TargetIdentity;
            var Targets = Get_DomainObject(TargetSearcherArguments);

            foreach (SearchResult TargetObject in Targets)
            {
                var InheritanceType = System.DirectoryServices.ActiveDirectorySecurityInheritance.None;
                var ControlType = System.Security.AccessControl.AccessControlType.Allow;
                var ACEs = new List<System.DirectoryServices.ActiveDirectoryAccessRule>();

                var GUIDs = new List<string>();
                if (args.RightsGUID != null)
                {
                    GUIDs.Add(args.RightsGUID.ToString());
                }
                else
                {
                    switch (args.Rights)
                    {
                        // ResetPassword doesn't need to know the user's current password
                        case Rights.ResetPassword:
                            GUIDs.Add("00299570-246d-11d0-a768-00aa006e0529");
                            break;
                        // allows for the modification of group membership
                        case Rights.WriteMembers:
                            GUIDs.Add("bf9679c0 -0de6-11d0-a285-00aa003049e2");
                            break;
                        // 'DS-Replication-Get-Changes' = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                        // 'DS-Replication-Get-Changes-All' = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                        // 'DS-Replication-Get-Changes-In-Filtered-Set' = 89e95b76-444d-4c62-991a-0facbeda640c
                        // when applied to a domain's ACL, allows for the use of DCSync
                        case Rights.DCSync:
                            GUIDs.Add("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
                            GUIDs.Add("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
                            GUIDs.Add("89e95b76-444d-4c62-991a-0facbeda640c");
                            break;
                    }
                }

                foreach (LDAPProperty PrincipalObject in Principals)
                {
                    Logger.Write_Verbose($@"[Remove-DomainObjectAcl] Removing principal {PrincipalObject.distinguishedname} '{args.Rights}' from {TargetObject.Properties["distinguishedname"][0]}");

                    try
                    {
                        var Identity = new System.Security.Principal.SecurityIdentifier(PrincipalObject.objectsid[0]);

                        if (GUIDs != null)
                        {
                            foreach (var GUID in GUIDs)
                            {
                                var NewGUID = new Guid(GUID);
                                var ADRights = System.DirectoryServices.ActiveDirectoryRights.ExtendedRight;
                                ACEs.Add(new System.DirectoryServices.ActiveDirectoryAccessRule(Identity, ADRights, ControlType, NewGUID, InheritanceType));
                            }
                        }
                        else
                        {
                            // deault to GenericAll rights
                            var ADRights = System.DirectoryServices.ActiveDirectoryRights.GenericAll;
                            ACEs.Add(new System.DirectoryServices.ActiveDirectoryAccessRule(Identity, ADRights, ControlType, InheritanceType));
                        }

                        // remove all the specified ACEs from the specified object directory entry
                        foreach (var ACE in ACEs)
                        {
                            Logger.Write_Verbose($@"[Remove-DomainObjectAcl] Removing principal {PrincipalObject.distinguishedname} rights GUID '{ACE.ObjectType}' from {TargetObject.Properties["distinguishedname"][0]}");
                            var TargetEntry = TargetObject.GetDirectoryEntry();
                            TargetEntry.Options.SecurityMasks = SecurityMasks.Dacl;
                            TargetEntry.ObjectSecurity.RemoveAccessRule(ACE);
                            TargetEntry.CommitChanges();
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[Remove-DomainObjectAcl] Error removing principal {PrincipalObject.distinguishedname} '{args.Rights}' from {TargetObject.Properties["distinguishedname"][0]}: {e}");
                    }
                }
            }
        }

        public static IEnumerable<RegLoggedOnUser> Get_RegLoggedOn(Args_Get_RegLoggedOn args = null)
        {
            if (args == null) args = new Args_Get_RegLoggedOn();

            IntPtr LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation { Credential = args.Credential });
            }

            var RegLoggedOnUsers = new List<RegLoggedOnUser>();
            foreach (var Computer in args.ComputerName)
            {
                try
                {
                    // retrieve HKU remote registry values
                    var Reg = Microsoft.Win32.RegistryKey.OpenRemoteBaseKey(Microsoft.Win32.RegistryHive.Users, $@"{Computer}");

                    // sort out bogus sid's like _class
                    var subkeys = Reg.GetSubKeyNames()?.Where(x => x.IsRegexMatch(@"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"));

                    foreach (var subkey in subkeys)
                    {
                        var UserName = ConvertFrom_SID(new Args_ConvertFrom_SID { ObjectSID = new[] { subkey } }).FirstOrDefault();
                        string UserDomain;

                        if (UserName != null)
                        {
                            UserName = UserName.Split('@')[0];
                            UserDomain = UserName.Split('@')[1];
                        }
                        else
                        {
                            UserName = subkey;
                            UserDomain = null;
                        }

                        var RegLoggedOnUser = new RegLoggedOnUser
                        {
                            ComputerName = $@"{Computer}",
                            UserDomain = UserDomain,
                            UserName = UserName,
                            UserSID = subkey
                        };
                        RegLoggedOnUsers.Add(RegLoggedOnUser);
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-RegLoggedOn] Error opening remote registry on '{Computer}' : {e}");
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }

            return RegLoggedOnUsers;
        }

        public static IEnumerable<RegLoggedOnUser> Get_LoggedOnLocal(Args_Get_RegLoggedOn args = null)
        {
            return Get_RegLoggedOn(args);
        }

        public static IEnumerable<RDPSessionInfo> Get_NetRDPSession(Args_Get_NetRDPSession args = null)
        {
            if (args == null) args = new Args_Get_NetRDPSession();

            IntPtr LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation { Credential = args.Credential });
            }

            var RDPSessions = new List<RDPSessionInfo>();
            foreach (var Computer in args.ComputerName)
            {

                // open up a handle to the Remote Desktop Session host
                var Handle = NativeMethods.WTSOpenServerEx(Computer);

                // if we get a non-zero handle back, everything was successful
                if (Handle != IntPtr.Zero)
                {
                    // arguments for WTSEnumerateSessionsEx
                    var ppSessionInfo = IntPtr.Zero;
                    UInt32 pCount = 0;

                    // get information on all current sessions
                    UInt32 level = 1;
                    var Result = NativeMethods.WTSEnumerateSessionsEx(Handle, ref level, 0, ref ppSessionInfo, ref pCount);
                    var LastError = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

                    // locate the offset of the initial intPtr
                    var Offset = ppSessionInfo.ToInt64();

                    if ((Result != 0) && (Offset > 0))
                    {

                        // work out how much to increment the pointer by finding out the size of the structure
                        var Increment = Marshal.SizeOf(typeof(NativeMethods.WTS_SESSION_INFO_1));

                        // parse all the result structures
                        for (var i = 0; (i < pCount); i++)
                        {

                            // create a new int ptr at the given offset and cast the pointer as our result structure
                            var NewIntPtr = new IntPtr(Offset);
                            var Info = (NativeMethods.WTS_SESSION_INFO_1)Marshal.PtrToStructure(NewIntPtr, typeof(NativeMethods.WTS_SESSION_INFO_1));

                            var RDPSession = new RDPSessionInfo();

                            if (Info.pHostName != null)
                            {
                                RDPSession.ComputerName = Info.pHostName;
                            }
                            else
                            {
                                // if no hostname returned, use the specified hostname
                                RDPSession.ComputerName = Computer;
                            }

                            RDPSession.SessionName = Info.pSessionName;

                            if ((Info.pDomainName == null) || (Info.pDomainName == ""))
                            {
                                // if a domain isn't returned just use the username
                                RDPSession.UserName = Info.pUserName;
                            }
                            else
                            {
                                RDPSession.UserName = $@"{Info.pDomainName}\{Info.pUserName}";
                            }

                            RDPSession.ID = Info.SessionId;
                            RDPSession.State = Info.State;

                            var ppBuffer = IntPtr.Zero;
                            uint pBytesReturned = 0;

                            // query for the source client IP with WTSQuerySessionInformation
                            // https://msdn.microsoft.com/en-us/library/aa383861(v=vs.85).aspx
                            var Result2 = NativeMethods.WTSQuerySessionInformation(Handle, Info.SessionId, NativeMethods.WTS_INFO_CLASS.WTSClientAddress, out ppBuffer, out pBytesReturned);
                            var LastError2 = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

                            if (Result2 == false)
                            {
                                Logger.Write_Verbose($@"[Get-NetRDPSession] Error: {new System.ComponentModel.Win32Exception((int)LastError2).Message}");
                            }
                            else
                            {
                                var Offset2 = ppBuffer.ToInt64();
                                var NewIntPtr2 = new IntPtr(Offset2);
                                var Info2 = (NativeMethods.WTS_CLIENT_ADDRESS)Marshal.PtrToStructure(NewIntPtr2, typeof(NativeMethods.WTS_CLIENT_ADDRESS));

                                string SourceIP;
                                if (Info2.Address[2] != 0)
                                {
                                    SourceIP = $@"{Info2.Address[2]}.{Info2.Address[3]}.{Info2.Address[4]}.{Info2.Address[5]}";
                                }
                                else
                                {
                                    SourceIP = null;
                                }

                                RDPSession.SourceIP = SourceIP;
                                RDPSessions.Add(RDPSession);

                                // free up the memory buffer
                                NativeMethods.WTSFreeMemory(ppBuffer);

                                Offset += Increment;
                            }
                        }
                        // free up the memory result buffer
                        NativeMethods.WTSFreeMemoryEx(WTS_TYPE_CLASS.WTSTypeSessionInfoLevel1, ppSessionInfo, pCount);
                    }
                    else
                    {
                        Logger.Write_Verbose($@"[Get-NetRDPSession] Error: {new System.ComponentModel.Win32Exception((int)LastError).Message}");
                    }
                    // close off the service handle
                    NativeMethods.WTSCloseServer(Handle);
                }
                else
                {
                    Logger.Write_Verbose($@"[Get-NetRDPSession] Error opening the Remote Desktop Session Host (RD Session Host) server for: {Computer}");
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }

            return RDPSessions;
        }

        public static IEnumerable<AdminAccess> Test_AdminAccess(Args_Test_AdminAccess args = null)
        {
            if (args == null) args = new Args_Test_AdminAccess();

            IntPtr LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation { Credential = args.Credential });
            }

            var IsAdmins = new List<AdminAccess>();
            foreach (var Computer in args.ComputerName)
            {
                // 0xF003F - SC_MANAGER_ALL_ACCESS
                // http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
                var Handle = NativeMethods.OpenSCManagerW($@"\\{Computer}", "ServicesActive", 0xF003F);
                var LastError = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

                var IsAdmin = new AdminAccess
                {
                    ComputerName = Computer
                };

                // if we get a non-zero handle back, everything was successful
                if (Handle != IntPtr.Zero)
                {
                    NativeMethods.CloseServiceHandle(Handle);
                    IsAdmin.IsAdmin = true;
                }
                else
                {
                    Logger.Write_Verbose($@"[Test-AdminAccess] Error: {new System.ComponentModel.Win32Exception((int)LastError).Message}");
                    IsAdmin.IsAdmin = false;
                }
                IsAdmins.Add(IsAdmin);
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }

            return IsAdmins;
        }

        public static IEnumerable<AdminAccess> Invoke_CheckLocalAdminAccess(Args_Test_AdminAccess args = null)
        {
            return Test_AdminAccess(args);
        }

        public static IEnumerable<UserProcess> Get_WMIProcess(Args_Get_WMIProcess args = null)
        {
            if (args == null) args = new Args_Get_WMIProcess();

            var UserProcesses = new List<UserProcess>();
            foreach (var Computer in args.ComputerName)
            {
                try
                {
                    var cls = WmiWrapper.GetClass($@"\\{Computer}\ROOT\CIMV2", "Win32_process", args.Credential);
                    var procs = WmiWrapper.GetInstances(cls);
                    foreach (var proc in procs)
                    {
                        var owner = WmiWrapper.CallMethod(proc, "GetOwner");
                        var UserProcess = new UserProcess
                        {
                            ComputerName = Computer,
                            ProcessName = proc.Properties["Caption"].Value.ToString(),
                            ProcessID = proc.Properties["ProcessId"].Value.ToString(),
                            Domain = $@"{owner["Domain"]}",
                            User = $@"{owner["User"]}",
                        };
                        UserProcesses.Add(UserProcess);
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-WMIProcess] Error enumerating remote processes on '{Computer}', access likely denied: {e}");
                }
            }
            return UserProcesses;
        }

        public static IEnumerable<UserProcess> Get_NetProcess(Args_Get_WMIProcess args = null)
        {
            return Get_WMIProcess(args);
        }

        public static IEnumerable<ProxySettings> Get_WMIRegProxy(Args_Get_WMIRegProxy args = null)
        {
            if (args == null) args = new Args_Get_WMIRegProxy();

            var ProxySettings = new List<ProxySettings>();
            foreach (var Computer in args.ComputerName)
            {
                try
                {
                    var RegProvider = WmiWrapper.GetClass($@"\\{Computer}\ROOT\DEFAULT", "StdRegProv", args.Credential);
                    var Key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";

                    // HKEY_CURRENT_USER
                    var HKCU = 2147483649;
                    var outParams = WmiWrapper.CallMethod(RegProvider, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKCU }, { "sSubKeyName", Key }, { "sValueName", "ProxyServer" } }) as System.Management.ManagementBaseObject;
                    var ProxyServer = outParams["sValue"] as string;
                    outParams = WmiWrapper.CallMethod(RegProvider, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKCU }, { "sSubKeyName", Key }, { "sValueName", "AutoConfigURL" } }) as System.Management.ManagementBaseObject;
                    var AutoConfigURL = outParams["sValue"] as string;

                    var Wpad = "";
                    if (AutoConfigURL != null && AutoConfigURL != "")
                    {
                        try
                        {
                            Wpad = (new System.Net.WebClient()).DownloadString(AutoConfigURL);
                        }
                        catch
                        {
                            Logger.Write_Warning($@"[Get-WMIRegProxy] Error connecting to AutoConfigURL : {AutoConfigURL}");
                        }
                    }

                    if (ProxyServer != null || AutoConfigURL != null)
                    {
                        var Out = new ProxySettings
                        {
                            ComputerName = Computer,
                            ProxyServer = ProxyServer,
                            AutoConfigURL = AutoConfigURL,
                            Wpad = Wpad
                        };
                        ProxySettings.Add(Out);
                    }
                    else
                    {
                        Logger.Write_Warning($@"[Get-WMIRegProxy] No proxy settings found for {Computer}");
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[Get-WMIRegProxy] Error enumerating proxy settings for {Computer} : {e}");
                }
            }

            return ProxySettings;
        }

        public static IEnumerable<ProxySettings> Get_Proxy(Args_Get_WMIRegProxy args = null)
        {
            return Get_WMIRegProxy(args);
        }

        public static IEnumerable<LastLoggedOnUser> Get_WMIRegLastLoggedOn(Args_Get_WMIRegLastLoggedOn args = null)
        {
            if (args == null) args = new Args_Get_WMIRegLastLoggedOn();

            var LastLoggedOnUsers = new List<LastLoggedOnUser>();
            foreach (var Computer in args.ComputerName)
            {
                // HKEY_LOCAL_MACHINE
                var HKLM = 2147483650;

                // try to open up the remote registry key to grab the last logged on user
                try
                {
                    var Reg = WmiWrapper.GetClass($@"\\{Computer}\ROOT\DEFAULT", "StdRegProv", args.Credential);
                    var Key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI";

                    var Value = "LastLoggedOnUser";
                    var outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKLM }, { "sSubKeyName", Key }, { "sValueName", Value } }) as System.Management.ManagementBaseObject;
                    var LastUser = outParams["sValue"] as string;

                    var LastLoggedOn = new LastLoggedOnUser
                    {
                        ComputerName = Computer,
                        LastLoggedOn = LastUser
                    };
                    LastLoggedOnUsers.Add(LastLoggedOn);
                }
                catch
                {
                    Logger.Write_Warning("[Get-WMIRegLastLoggedOn] Error opening remote registry on $Computer. Remote registry likely not enabled.");
                }
            }
            return LastLoggedOnUsers;
        }

        public static IEnumerable<LastLoggedOnUser> Get_LastLoggedOn(Args_Get_WMIRegLastLoggedOn args = null)
        {
            return Get_WMIRegLastLoggedOn(args);
        }

        public static IEnumerable<CachedRDPConnection> Get_WMIRegCachedRDPConnection(Args_Get_WMIRegCachedRDPConnection args = null)
        {
            if (args == null) args = new Args_Get_WMIRegCachedRDPConnection();

            var FoundConnections = new List<CachedRDPConnection>();
            foreach (var Computer in args.ComputerName)
            {
                // HKEY_USERS
                var HKU = 2147483651;

                try
                {
                    var Reg = WmiWrapper.GetClass($@"\\{Computer}\ROOT\DEFAULT", "StdRegProv", args.Credential);

                    // extract out the SIDs of domain users in this hive
                    var outParams = WmiWrapper.CallMethod(Reg, "EnumKey", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", "" } }) as System.Management.ManagementBaseObject;
                    var names = outParams["sNames"] as IEnumerable<string>;
                    if (names == null) continue;

                    var UserSIDs = names.Where(x => x.IsRegexMatch($@"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"));

                    foreach (var UserSID in UserSIDs)
                    {
                        try
                        {
                            var UserName = ConvertFrom_SID(new Args_ConvertFrom_SID { ObjectSID = new[] { UserSID }, Credential = args.Credential }).FirstOrDefault();

                            // pull out all the cached RDP connections
                            outParams = WmiWrapper.CallMethod(Reg, "EnumValues", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Software\Microsoft\Terminal Server Client\Default" } }) as System.Management.ManagementBaseObject;
                            var ConnectionKeys = outParams["sNames"] as IEnumerable<string>;

                            if (ConnectionKeys != null)
                            {
                                foreach (var Connection in ConnectionKeys)
                                {
                                    // make sure this key is a cached connection
                                    if (Connection.IsRegexMatch(@"MRU.*"))
                                    {
                                        outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Software\Microsoft\Terminal Server Client\Default" }, { "sValueName", Connection } }) as System.Management.ManagementBaseObject;
                                        var TargetServer = outParams["sValue"] as string;

                                        var FoundConnection = new CachedRDPConnection
                                        {
                                            ComputerName = Computer,
                                            UserName = UserName,
                                            UserSID = UserSID,
                                            TargetServer = TargetServer,
                                            UsernameHint = null
                                        };
                                        FoundConnections.Add(FoundConnection);
                                    }
                                }
                            }

                            // pull out all the cached server info with username hints
                            outParams = WmiWrapper.CallMethod(Reg, "EnumKey", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Software\Microsoft\Terminal Server Client\Servers" } }) as System.Management.ManagementBaseObject;
                            var ServerKeys = outParams["sNames"] as IEnumerable<string>;

                            if (ServerKeys != null)
                            {
                                foreach (var Server in ServerKeys)
                                {
                                    outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Software\Microsoft\Terminal Server Client\Servers\{Server}" }, { "sValueName", "UsernameHint" } }) as System.Management.ManagementBaseObject;
                                    var UsernameHint = outParams["sValue"] as string;

                                    var FoundConnection = new CachedRDPConnection
                                    {
                                        ComputerName = Computer,
                                        UserName = UserName,
                                        UserSID = UserSID,
                                        TargetServer = Server,
                                        UsernameHint = UsernameHint
                                    };
                                    FoundConnections.Add(FoundConnection);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-WMIRegCachedRDPConnection] Error: {e}");
                        }
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[Get-WMIRegCachedRDPConnection] Error accessing {Computer}, likely insufficient permissions or firewall rules on host: {e}");
                }
            }
            return FoundConnections;
        }

        public static IEnumerable<CachedRDPConnection> Get_CachedRDPConnection(Args_Get_WMIRegCachedRDPConnection args = null)
        {
            return Get_WMIRegCachedRDPConnection(args);
        }

        public static IEnumerable<RegMountedDrive> Get_WMIRegMountedDrive(Args_Get_WMIRegMountedDrive args = null)
        {
            if (args == null) args = new Args_Get_WMIRegMountedDrive();

            var MountedDrives = new List<RegMountedDrive>();
            foreach (var Computer in args.ComputerName)
            {
                // HKEY_USERS
                var HKU = 2147483651;
                try
                {
                    var Reg = WmiWrapper.GetClass($@"\\{Computer}\ROOT\DEFAULT", "StdRegProv", args.Credential);

                    // extract out the SIDs of domain users in this hive
                    var outParams = WmiWrapper.CallMethod(Reg, "EnumKey", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", "" } }) as System.Management.ManagementBaseObject;
                    var names = outParams["sNames"] as IEnumerable<string>;
                    if (names == null) continue;

                    var UserSIDs = names.Where(x => x.IsRegexMatch($@"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"));

                    foreach (var UserSID in UserSIDs)
                    {
                        try
                        {
                            var UserName = ConvertFrom_SID(new Args_ConvertFrom_SID { ObjectSID = new[] { UserSID }, Credential = args.Credential }).FirstOrDefault();
                            outParams = WmiWrapper.CallMethod(Reg, "EnumKey", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Network" } }) as System.Management.ManagementBaseObject;
                            var DriveLetters = outParams["sNames"] as IEnumerable<string>;
                            if (DriveLetters == null) continue;

                            foreach (var DriveLetter in DriveLetters)
                            {
                                outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Network\{DriveLetter}" }, { "sValueName", "ProviderName" } }) as System.Management.ManagementBaseObject;
                                var ProviderName = outParams["sValue"] as string;
                                outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Network\{DriveLetter}" }, { "sValueName", "RemotePath" } }) as System.Management.ManagementBaseObject;
                                var RemotePath = outParams["sValue"] as string;
                                outParams = WmiWrapper.CallMethod(Reg, "GetStringValue", new Dictionary<string, object> { { "hDefKey", HKU }, { "sSubKeyName", $@"{UserSID}\Network\{DriveLetter}" }, { "sValueName", "UserName" } }) as System.Management.ManagementBaseObject;
                                var DriveUserName = outParams["sValue"] as string;
                                if (UserName == null) { UserName = ""; }

                                if (RemotePath != null && (RemotePath != ""))
                                {
                                    var MountedDrive = new RegMountedDrive
                                    {
                                        ComputerName = Computer,
                                        UserName = UserName,
                                        UserSID = UserSID,
                                        DriveLetter = DriveLetter,
                                        ProviderName = ProviderName,
                                        RemotePath = RemotePath,
                                        DriveUserName = DriveUserName
                                    };
                                    MountedDrives.Add(MountedDrive);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Logger.Write_Verbose($@"[Get-WMIRegMountedDrive] Error: {e}");
                        }
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[Get-WMIRegMountedDrive] Error accessing {Computer}, likely insufficient permissions or firewall rules on host: {e}");
                }
            }
            return MountedDrives;
        }

        public static IEnumerable<RegMountedDrive> Get_RegistryMountedDrive(Args_Get_WMIRegMountedDrive args = null)
        {
            return Get_WMIRegMountedDrive(args);
        }

        public static IEnumerable<ACL> Find_InterestingDomainAcl(Args_Find_InterestingDomainAcl args = null)
        {
            if (args == null) args = new Args_Find_InterestingDomainAcl();

            var ACLArguments = new Args_Get_DomainObjectAcl
            {
                ResolveGUIDs = args.ResolveGUIDs,
                RightsFilter = args.RightsFilter,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ObjectSearcherArguments = new Args_Get_DomainObject
            {
                Properties = new[] { "samaccountname", "objectclass" },
                Raw = true,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var ADNameArguments = new Args_Convert_ADName
            {
                Server = args.Server,
                Credential = args.Credential
            };

            // ongoing list of built-up SIDs
            var ResolvedSIDs = new Dictionary<string, ResolvedSID>();

            if (args.Domain != null)
            {
                ACLArguments.Domain = args.Domain;
                ADNameArguments.Domain = args.Domain;
            }

            var InterestingACLs = new List<ACL>();
            var acls = Get_DomainObjectAcl(ACLArguments);
            foreach (var acl in acls)
            {
                if ((acl.ActiveDirectoryRights.ToString().IsRegexMatch(@"GenericAll|Write|Create|Delete")) || ((acl.ActiveDirectoryRights == ActiveDirectoryRights.ExtendedRight) && (acl.Ace is QualifiedAce) && (acl.Ace as QualifiedAce).AceQualifier == AceQualifier.AccessAllowed))
                {
                    // only process SIDs > 1000
                    var ace = acl.Ace as QualifiedAce;
                    if (ace != null && ace.SecurityIdentifier.Value.IsRegexMatch(@"^S-1-5-.*-[1-9]\d{3,}$"))
                    {
                        if (ResolvedSIDs.ContainsKey(ace.SecurityIdentifier.Value) && ResolvedSIDs[ace.SecurityIdentifier.Value] != null)
                        {
                            var ResolvedSID = ResolvedSIDs[(acl.Ace as KnownAce).SecurityIdentifier.Value];
                            var InterestingACL = new ACL
                            {
                                ObjectDN = acl.ObjectDN,
                                Ace = ace,
                                ActiveDirectoryRights = acl.ActiveDirectoryRights,
                                IdentityReferenceName = ResolvedSID.IdentityReferenceName,
                                IdentityReferenceDomain = ResolvedSID.IdentityReferenceDomain,
                                IdentityReferenceDN = ResolvedSID.IdentityReferenceDN,
                                IdentityReferenceClass = ResolvedSID.IdentityReferenceClass
                            };
                            InterestingACLs.Add(InterestingACL);
                        }
                        else
                        {
                            ADNameArguments.Identity = new string[] { ace.SecurityIdentifier.Value };
                            ADNameArguments.OutputType = ADSNameType.DN;
                            var IdentityReferenceDN = Convert_ADName(ADNameArguments)?.FirstOrDefault();
                            // "IdentityReferenceDN: $IdentityReferenceDN"

                            if (IdentityReferenceDN != null)
                            {
                                var IdentityReferenceDomain = IdentityReferenceDN.Substring(IdentityReferenceDN.IndexOf("DC=")).Replace(@"DC=", "").Replace(",", ".");
                                // "IdentityReferenceDomain: $IdentityReferenceDomain"
                                ObjectSearcherArguments.Domain = IdentityReferenceDomain;
                                ObjectSearcherArguments.Identity = new[] { IdentityReferenceDN };
                                // "IdentityReferenceDN: $IdentityReferenceDN"
                                var Object = Get_DomainObject(ObjectSearcherArguments)?.FirstOrDefault() as SearchResult;

                                if (Object != null)
                                {
                                    var IdentityReferenceName = Object.Properties["samaccountname"][0].ToString();
                                    string IdentityReferenceClass;
                                    if (Object.Properties["objectclass"][0].ToString().IsRegexMatch(@"computer"))
                                    {
                                        IdentityReferenceClass = "computer";
                                    }
                                    else if (Object.Properties["objectclass"][0].ToString().IsRegexMatch(@"group"))
                                    {
                                        IdentityReferenceClass = "group";
                                    }
                                    else if (Object.Properties["objectclass"][0].ToString().IsRegexMatch(@"user"))
                                    {
                                        IdentityReferenceClass = "user";
                                    }
                                    else
                                    {
                                        IdentityReferenceClass = null;
                                    }

                                    // save so we don't look up more than once
                                    ResolvedSIDs[ace.SecurityIdentifier.Value] = new ResolvedSID
                                    {
                                        IdentityReferenceName = IdentityReferenceName,
                                        IdentityReferenceDomain = IdentityReferenceDomain,
                                        IdentityReferenceDN = IdentityReferenceDN,
                                        IdentityReferenceClass = IdentityReferenceClass
                                    };

                                    var InterestingACL = new ACL
                                    {
                                        ObjectDN = acl.ObjectDN,
                                        Ace = ace,
                                        ActiveDirectoryRights = acl.ActiveDirectoryRights,
                                        IdentityReferenceName = IdentityReferenceName,
                                        IdentityReferenceDomain = IdentityReferenceDomain,
                                        IdentityReferenceDN = IdentityReferenceDN,
                                        IdentityReferenceClass = IdentityReferenceClass
                                    };
                                    InterestingACLs.Add(InterestingACL);
                                }
                            }
                            else
                            {
                                Logger.Write_Warning($@"[Find-InterestingDomainAcl] Unable to convert SID '{ace.SecurityIdentifier.Value}' to a distinguishedname with Convert-ADName");
                            }
                        }
                    }
                }
            }

            return InterestingACLs;
        }

        public static IEnumerable<ACL> Invoke_ACLScanner(Args_Find_InterestingDomainAcl args = null)
        {
            return Find_InterestingDomainAcl(args);
        }

        public static IEnumerable<ShareInfo> Get_NetShare(Args_Get_NetShare args = null)
        {
            if (args == null) args = new Args_Get_NetShare();

            var shareInfos = new List<ShareInfo>();

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    Credential = args.Credential
                });
            }
            foreach (var Computer in args.ComputerName)
            {
                // arguments for NetShareEnum
                var QueryLevel = 1;
                var PtrInfo = IntPtr.Zero;
                var EntriesRead = 0;
                var TotalRead = 0;
                var ResumeHandle = 0;

                // get the raw share information
                var Result = NativeMethods.NetShareEnum(Computer, QueryLevel, ref PtrInfo, MAX_PREFERRED_LENGTH, ref EntriesRead, ref TotalRead, ref ResumeHandle);

                // locate the offset of the initial intPtr
                var Offset = PtrInfo.ToInt64();

                // 0 = success
                if ((Result == 0) && (Offset > 0))
                {
                    // work out how much to increment the pointer by finding out the size of the structure
                    var Increment = Marshal.SizeOf(typeof(SHARE_INFO_1));

                    // parse all the result structures
                    for (var i = 0; (i < EntriesRead); i++)
                    {
                        // create a new int ptr at the given offset and cast the pointer as our result structure
                        var NewIntPtr = new System.IntPtr(Offset);
                        var Info = (SHARE_INFO_1)Marshal.PtrToStructure(NewIntPtr, typeof(SHARE_INFO_1));

                        // return all the sections of the structure - have to do it this way for V2
                        shareInfos.Add(new ShareInfo
                        {
                            Name = Info.shi1_netname,
                            Type = Info.shi1_type,
                            Remark = Info.shi1_remark,
                            ComputerName = Computer
                        });
                        Offset = NewIntPtr.ToInt64();
                        Offset += Increment;
                    }

                    // free up the result buffer
                    NativeMethods.NetApiBufferFree(PtrInfo);
                }
                else
                {
                    Logger.Write_Verbose($@"[Get-NetShare] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return shareInfos;
        }

        public static IEnumerable<LoggedOnUserInfo> Get_NetLoggedon(Args_Get_NetLoggedon args = null)
        {
            if (args == null) args = new Args_Get_NetLoggedon();

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    Credential = args.Credential
                });
            }

            var LoggedOns = new List<LoggedOnUserInfo>();

            foreach (var Computer in args.ComputerName)
            {
                // declare the reference variables
                var QueryLevel = 1;
                var PtrInfo = IntPtr.Zero;
                var EntriesRead = 0;
                var TotalRead = 0;
                var ResumeHandle = 0;

                // get logged on user information
                var Result = NativeMethods.NetWkstaUserEnum(Computer, QueryLevel, out PtrInfo, -1, out EntriesRead, out TotalRead, ref ResumeHandle);

                // locate the offset of the initial intPtr
                var Offset = PtrInfo.ToInt64();

                // 0 = success
                if ((Result == 0) && (Offset > 0))
                {
                    // work out how much to increment the pointer by finding out the size of the structure
                    var Increment = Marshal.SizeOf(typeof(WKSTA_USER_INFO_1));

                    // parse all the result structures
                    for (var i = 0; (i < EntriesRead); i++)
                    {
                        // create a new int ptr at the given offset and cast the pointer as our result structure
                        var NewIntPtr = new System.IntPtr(Offset);
                        var Info = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(NewIntPtr, typeof(WKSTA_USER_INFO_1));

                        // return all the sections of the structure - have to do it this way for V2
                        LoggedOns.Add(new LoggedOnUserInfo
                        {
                            UserName = Info.wkui1_username,
                            LogonDomain = Info.wkui1_logon_domain,
                            AuthDomains = Info.wkui1_oth_domains,
                            LogonServer = Info.wkui1_logon_server,
                            ComputerName = Computer
                        });
                        Offset = NewIntPtr.ToInt64();
                        Offset += Increment;
                    }

                    // free up the result buffer
                    NativeMethods.NetApiBufferFree(PtrInfo);
                }
                else
                {
                    Logger.Write_Verbose($@"[Get-NetLoggedon] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return LoggedOns;
        }

        // LocalGroupAPI or LocalGroupWinNT
        public static IEnumerable<object> Get_NetLocalGroup(Args_Get_NetLocalGroup args = null)
        {
            if (args == null) args = new Args_Get_NetLocalGroup();

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    Credential = args.Credential
                });
            }

            var LocalGroups = new List<object>();

            foreach (var Computer in args.ComputerName)
            {
                if (args.Method == MethodType.API)
                {
                    // if we're using the Netapi32 NetLocalGroupEnum API call to get the local group information
                    // arguments for NetLocalGroupEnum
                    var QueryLevel = 1;
                    var PtrInfo = IntPtr.Zero;
                    var EntriesRead = 0;
                    var TotalRead = 0;
                    var ResumeHandle = 0;

                    // get the local user information
                    var Result = NativeMethods.NetLocalGroupEnum(Computer, QueryLevel, out PtrInfo, MAX_PREFERRED_LENGTH, out EntriesRead, out TotalRead, ref ResumeHandle);

                    // locate the offset of the initial intPtr
                    var Offset = PtrInfo.ToInt64();

                    // 0 = success
                    if ((Result == 0) && (Offset > 0))
                    {
                        // Work out how much to increment the pointer by finding out the size of the structure
                        var Increment = Marshal.SizeOf(typeof(LOCALGROUP_INFO_1));

                        // parse all the result structures
                        for (var i = 0; (i < EntriesRead); i++)
                        {
                            // create a new int ptr at the given offset and cast the pointer as our result structure
                            var NewIntPtr = new System.IntPtr(Offset);
                            var Info = (LOCALGROUP_INFO_1)Marshal.PtrToStructure(NewIntPtr, typeof(LOCALGROUP_INFO_1));

                            LocalGroups.Add(new LocalGroupAPI
                            {
                                ComputerName = Computer,
                                GroupName = Info.lgrpi1_name,
                                Comment = Info.lgrpi1_comment
                            });
                            Offset = NewIntPtr.ToInt64();
                            Offset += Increment;
                        }
                        // free up the result buffer
                        NativeMethods.NetApiBufferFree(PtrInfo);
                    }
                    else
                    {
                        Logger.Write_Verbose($@"[Get-NetLocalGroup] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                    }
                }
                else
                {
                    // otherwise we're using the WinNT service provider
                    var ComputerProvider = new System.DirectoryServices.DirectoryEntry($@"WinNT://{Computer},computer");
                    foreach (System.DirectoryServices.DirectoryEntry LocalGroup in ComputerProvider.Children)
                    {
                        if (LocalGroup.SchemaClassName.Equals("group", StringComparison.OrdinalIgnoreCase))
                        {
                            var Group = new LocalGroupWinNT
                            {
                                ComputerName = Computer,
                                GroupName = LocalGroup.Name,
                                SID = new System.Security.Principal.SecurityIdentifier((byte[])LocalGroup.InvokeGet("objectsid"), 0).Value,
                                Comment = LocalGroup.InvokeGet("Description").ToString()
                            };
                            LocalGroups.Add(Group);
                        }
                    }
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return LocalGroups;
        }

        public static IEnumerable<object> Get_NetLocalGroupMember(Args_Get_NetLocalGroupMember args = null)
        {
            if (args == null) args = new Args_Get_NetLocalGroupMember();

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    Credential = args.Credential
                });
            }

            var LocalGroupMembers = new List<object>();

            foreach (var Computer in args.ComputerName)
            {
                if (args.Method == MethodType.API)
                {
                    // if we're using the Netapi32 NetLocalGroupGetMembers API call to get the local group information
                    // arguments for NetLocalGroupGetMembers
                    var QueryLevel = 2;
                    var PtrInfo = IntPtr.Zero;
                    var EntriesRead = 0;
                    var TotalRead = 0;
                    var ResumeHandle = IntPtr.Zero;

                    // get the local user information
                    var Result = NativeMethods.NetLocalGroupGetMembers(Computer, args.GroupName, QueryLevel, out PtrInfo, -1, out EntriesRead, out TotalRead, ResumeHandle);

                    // locate the offset of the initial intPtr
                    var Offset = PtrInfo.ToInt64();

                    var Members = new List<object>();

                    // 0 = success
                    if ((Result == 0) && (Offset > 0))
                    {
                        // Work out how much to increment the pointer by finding out the size of the structure
                        var Increment = Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_2));

                        // parse all the result structures
                        for (var i = 0; (i < EntriesRead); i++)
                        {
                            // create a new int ptr at the given offset and cast the pointer as our result structure
                            var NewIntPtr = new System.IntPtr(Offset);
                            var Info = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(NewIntPtr, typeof(LOCALGROUP_MEMBERS_INFO_2));

                            Offset = NewIntPtr.ToInt64();
                            Offset += Increment;

                            var SidString = "";
                            var Result2 = NativeMethods.ConvertSidToStringSid(Info.lgrmi2_sid, out SidString);
                            var LastError = System.Runtime.InteropServices.Marshal.GetLastWin32Error();

                            if (!Result2)
                            {
                                Logger.Write_Verbose($@"[Get-NetLocalGroupMember] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                            }
                            else
                            {
                                var Member = new LocalGroupMemberAPI
                                {
                                    ComputerName = Computer,
                                    GroupName = args.GroupName,
                                    MemberName = Info.lgrmi2_domainandname,
                                    SID = SidString,
                                    IsGroup = Info.lgrmi2_sidusage == SID_NAME_USE.SidTypeGroup
                                };
                                Members.Add(Member);
                            }
                        }

                        // free up the result buffer
                        NativeMethods.NetApiBufferFree(PtrInfo);

                        // try to extract out the machine SID by using the -500 account as a reference
                        var MachineSid = (Members.FirstOrDefault(x => (x as LocalGroupMemberAPI).SID.IsRegexMatch(".*-500") || (x as LocalGroupMemberAPI).SID.IsRegexMatch(".*-501")) as LocalGroupMemberAPI).SID;
                        if (MachineSid != null)
                        {
                            MachineSid = MachineSid.Substring(0, MachineSid.LastIndexOf('-'));

                            foreach (LocalGroupMemberAPI member in Members)
                            {
                                if (member.SID.IsRegexMatch(MachineSid))
                                {
                                    member.IsDomain = "false";
                                }
                                else
                                {
                                    member.IsDomain = "true";
                                }
                            }
                        }
                        else
                        {
                            foreach (LocalGroupMemberAPI member in Members)
                            {
                                if (!member.SID.IsRegexMatch("S-1-5-21"))
                                {
                                    member.IsDomain = "false";
                                }
                                else
                                {
                                    member.IsDomain = "UNKNOWN";
                                }
                            }
                        }
                        LocalGroupMembers.AddRange(Members);
                    }
                    else
                    {
                        Logger.Write_Verbose($@"[Get-NetLocalGroupMember] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                    }
                }
                else
                {
                    // otherwise we're using the WinNT service provider
                    try
                    {
                        var GroupProvider = new System.DirectoryServices.DirectoryEntry($@"WinNT://{Computer}/{args.GroupName},group");
                        IEnumerable Members = (IEnumerable)GroupProvider.Invoke("Members");
                        foreach (var obj in Members)
                        {
                            var LocalUser = new System.DirectoryServices.DirectoryEntry(obj);
                            var Member = new LocalGroupMemberWinNT
                            {
                                ComputerName = Computer,
                                GroupName = args.GroupName
                            };

                            var AdsPath = LocalUser.InvokeGet("AdsPath").ToString().Replace("WinNT://", "");
                            var IsGroup = LocalUser.SchemaClassName.IsLikeMatch("group");

                            bool MemberIsDomain;
                            string Name;
                            if (Regex.Matches(AdsPath, "/").Count == 1)
                            {
                                // DOMAIN\user
                                MemberIsDomain = true;
                                Name = AdsPath.Replace(@"/", @"\");
                            }
                            else
                            {
                                // DOMAIN\machine\user
                                MemberIsDomain = false;
                                Name = AdsPath.Substring(AdsPath.IndexOf('/') + 1).Replace(@"/", @"\");
                            }

                            Member.AccountName = Name;
                            Member.SID = new System.Security.Principal.SecurityIdentifier((byte[])LocalUser.InvokeGet("ObjectSID"), 0).Value;
                            Member.IsGroup = IsGroup;
                            Member.IsDomain = MemberIsDomain;

                            LocalGroupMembers.Add(Member);
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Verbose($@"[Get-NetLocalGroupMember] Error for {Computer} : {e}");
                    }
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return LocalGroupMembers;
        }

        private static string Convert_FileRight(uint FSR)
        {
            // From Ansgar Wiechers at http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
            var AccessMask = new Dictionary<UInt32, string> {
                { 0x80000000, "GenericRead" },
                { 0x40000000, "GenericWrite" },
                { 0x20000000, "GenericExecute" },
                { 0x10000000, "GenericAll" },
                { 0x02000000, "MaximumAllowed" },
                { 0x01000000, "AccessSystemSecurity" },
                { 0x00100000, "Synchronize" },
                { 0x00080000, "WriteOwner" },
                { 0x00040000, "WriteDAC" },
                { 0x00020000, "ReadControl" },
                { 0x00010000, "Delete" },
                { 0x00000100, "WriteAttributes" },
                { 0x00000080, "ReadAttributes" },
                { 0x00000040, "DeleteChild" },
                { 0x00000020, "Execute/Traverse" },
                { 0x00000010, "WriteExtendedAttributes" },
                { 0x00000008, "ReadExtendedAttributes" },
                { 0x00000004, "AppendData/AddSubdirectory" },
                { 0x00000002, "WriteData/AddFile" },
                { 0x00000001, "ReadData/ListDirectory" }
            };

            var SimplePermissions = new Dictionary<UInt32, string> {
                { 0x1f01ff, "FullControl" },
                { 0x0301bf, "Modify" },
                { 0x0200a9, "ReadAndExecute" },
                { 0x02019f, "ReadAndWrite" },
                { 0x020089, "Read" },
                { 0x000116, "Write" }
            };

            var Permissions = new List<string>();

            // get simple permission
            foreach (var key in SimplePermissions.Keys)
            {
                if ((FSR & key) == key)
                {
                    Permissions.Add(SimplePermissions[key]);
                    FSR = FSR & ~key;
                }
            }

            // get remaining extended permissions
            foreach (var key in AccessMask.Keys)
            {
                if ((FSR & key) != 0)
                    Permissions.Add(AccessMask[key]);
            }

            return string.Join(",", Permissions);
        }

        public static IEnumerable<SessionInfo> Get_NetSession(Args_Get_NetSession args = null)
        {
            if (args == null) args = new Args_Get_NetSession();

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    Credential = args.Credential
                });
            }

            var SessionInfos = new List<SessionInfo>();
            foreach (var Computer in args.ComputerName)
            {
                // arguments for NetSessionEnum
                var QueryLevel = 10;
                var PtrInfo = IntPtr.Zero;
                var EntriesRead = 0;
                var TotalRead = 0;
                var ResumeHandle = 0;
                var UserName = string.Empty;

                // get session information
                var Result = NativeMethods.NetSessionEnum(Computer, string.Empty, UserName, QueryLevel, out PtrInfo, -1, ref EntriesRead, ref TotalRead, ref ResumeHandle);

                // locate the offset of the initial intPtr
                var Offset = PtrInfo.ToInt64();

                // 0 = success
                if ((Result == 0) && (Offset > 0))
                {
                    // work out how much to increment the pointer by finding out the size of the structure
                    var Increment = Marshal.SizeOf(typeof(SESSION_INFO_10));

                    // parse all the result structures
                    for (var i = 0; (i < EntriesRead); i++)
                    {
                        // create a new int ptr at the given offset and cast the pointer as our result structure
                        var NewIntPtr = new System.IntPtr(Offset);
                        var Info = (SESSION_INFO_10)Marshal.PtrToStructure(NewIntPtr, typeof(SESSION_INFO_10));

                        // return all the sections of the structure - have to do it this way for V2
                        var Session = new SessionInfo
                        {
                            ComputerName = Computer,
                            CName = Info.sesi10_cname,
                            UserName = Info.sesi10_username,
                            Time = Info.sesi502_time,
                            IdleTime = Info.sesi502_idle_time
                        };
                        Offset = NewIntPtr.ToInt64();
                        Offset += Increment;
                        SessionInfos.Add(Session);
                    }

                    // free up the result buffer
                    NativeMethods.NetApiBufferFree(PtrInfo);
                }
                else
                {
                    Logger.Write_Verbose($@"[Get-NetSession] Error: {new System.ComponentModel.Win32Exception((int)Result).Message}");
                }
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return SessionInfos;
        }

        public static IEnumerable<FileACL> Get_PathAcl(Args_Get_PathAcl args = null)
        {
            if (args == null) args = new Args_Get_PathAcl();

            var ConvertArguments = new Args_ConvertFrom_SID
            {
                Credential = args.Credential
            };
            var MappedComputers = new Dictionary<string, bool>();

            var FileACLs = new List<FileACL>();
            foreach (var TargetPath in args.Path)
            {
                try
                {
                    if (TargetPath.IsRegexMatch(@"\\\\.*\\.*") && args.Credential != null)
                    {
                        var HostComputer = new System.Uri(TargetPath).Host;
                        if (!MappedComputers[HostComputer])
                        {
                            // map IPC$ to this computer if it's not already
                            Add_RemoteConnection(new Args_Add_RemoteConnection { ComputerName = new string[] { HostComputer }, Credential = args.Credential });
                            MappedComputers[HostComputer] = true;
                        }
                    }

                    FileSystemSecurity ACL;
                    var attr = File.GetAttributes(TargetPath);
                    if (attr.HasFlag(FileAttributes.Directory))
                        ACL = Directory.GetAccessControl(TargetPath);
                    else
                        ACL = File.GetAccessControl(TargetPath);

                    var arc = ACL.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                    foreach (FileSystemAccessRule ar in arc)
                    {
                        var SID = ar.IdentityReference.Value;
                        ConvertArguments.ObjectSID = new string[] { SID };
                        var Name = ConvertFrom_SID(ConvertArguments);

                        var Out = new FileACL
                        {
                            Path = TargetPath,
                            FileSystemRights = Convert_FileRight((uint)ar.FileSystemRights),
                            IdentityReference = Name,
                            IdentitySID = SID,
                            AccessControlType = ar.AccessControlType
                        };
                        FileACLs.Add(Out);
                    }
                }
                catch (Exception e)
                {
                    Logger.Write_Verbose($@"[Get-PathAcl] error: {e}");
                }
            }

            // remove the IPC$ mappings
            Remove_RemoteConnection(new Args_Remove_RemoteConnection { ComputerName = MappedComputers.Keys.ToArray() });
            return FileACLs;
        }

        public static System.Collections.Specialized.OrderedDictionary ConvertFrom_UACValue(Args_ConvertFrom_UACValue args = null)
        {
            if (args == null) args = new Args_ConvertFrom_UACValue();

            // values from https://support.microsoft.com/en-us/kb/305144
            var UACValues = new System.Collections.Specialized.OrderedDictionary();
            UACValues.Add("SCRIPT", 1);
            UACValues.Add("ACCOUNTDISABLE", 2);
            UACValues.Add("HOMEDIR_REQUIRED", 8);
            UACValues.Add("LOCKOUT", 16);
            UACValues.Add("PASSWD_NOTREQD", 32);
            UACValues.Add("PASSWD_CANT_CHANGE", 64);
            UACValues.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128);
            UACValues.Add("TEMP_DUPLICATE_ACCOUNT", 256);
            UACValues.Add("NORMAL_ACCOUNT", 512);
            UACValues.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048);
            UACValues.Add("WORKSTATION_TRUST_ACCOUNT", 4096);
            UACValues.Add("SERVER_TRUST_ACCOUNT", 8192);
            UACValues.Add("DONT_EXPIRE_PASSWORD", 65536);
            UACValues.Add("MNS_LOGON_ACCOUNT", 131072);
            UACValues.Add("SMARTCARD_REQUIRED", 262144);
            UACValues.Add("TRUSTED_FOR_DELEGATION", 524288);
            UACValues.Add("NOT_DELEGATED", 1048576);
            UACValues.Add("USE_DES_KEY_ONLY", 2097152);
            UACValues.Add("DONT_REQ_PREAUTH", 4194304);
            UACValues.Add("PASSWORD_EXPIRED", 8388608);
            UACValues.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216);
            UACValues.Add("PARTIAL_SECRETS_ACCOUNT", 67108864);

            var ResultUACValues = new System.Collections.Specialized.OrderedDictionary();

            if (args.ShowAll)
            {
                foreach (DictionaryEntry UACValue in UACValues)
                {
                    if ((args.Value & (int)UACValue.Value) == (int)UACValue.Value)
                    {
                        ResultUACValues.Add(UACValue.Key, $"{UACValue.Value}+");
                    }
                    else
                    {
                        ResultUACValues.Add(UACValue.Key, $"{UACValue.Value}");
                    }
                }
            }
            else
            {
                foreach (DictionaryEntry UACValue in UACValues)
                {
                    if ((args.Value & (int)UACValue.Value) == (int)UACValue.Value)
                    {
                        ResultUACValues.Add(UACValue.Key, $"{UACValue.Value}");
                    }
                }
            }
            return ResultUACValues;
        }

        public static PrincipalContextEx Get_PrincipalContext(Args_Get_PrincipalContext args = null)
        {
            if (args == null) args = new Args_Get_PrincipalContext();

            try
            {
                var ConnectTarget = string.Empty;
                var ObjectIdentity = string.Empty;
                System.DirectoryServices.AccountManagement.PrincipalContext Context = null;
                if (!string.IsNullOrEmpty(args.Domain) || args.Identity.IsRegexMatch(@".+\\.+"))
                {
                    if (args.Identity.IsRegexMatch(@".+\\.+"))
                    {
                        // DOMAIN\groupname
                        var ConvertedIdentity = Convert_ADName(new Args_Convert_ADName { Identity = new[] { args.Identity } }).FirstOrDefault();
                        if (ConvertedIdentity != null)
                        {
                            ConnectTarget = ConvertedIdentity.Substring(0, ConvertedIdentity.IndexOf('/'));
                            ObjectIdentity = args.Identity.Split('\\')[1];
                            Logger.Write_Verbose($@"[Get-PrincipalContext] Binding to domain '{ConnectTarget}'");
                        }
                    }
                    else
                    {
                        ObjectIdentity = args.Identity;
                        Logger.Write_Verbose($@"[Get-PrincipalContext] Binding to domain '{args.Domain}'");
                        ConnectTarget = args.Domain;
                    }

                    if (args.Credential != null)
                    {
                        Logger.Write_Verbose($@"[Get-PrincipalContext] Using alternate credentials");
                        Context = new System.DirectoryServices.AccountManagement.PrincipalContext(System.DirectoryServices.AccountManagement.ContextType.Domain, ConnectTarget, args.Credential.UserName, args.Credential.Password);
                    }
                    else
                    {
                        Context = new System.DirectoryServices.AccountManagement.PrincipalContext(System.DirectoryServices.AccountManagement.ContextType.Domain, ConnectTarget);
                    }
                }
                else
                {
                    if (args.Credential != null)
                    {
                        Logger.Write_Verbose($@"[Get-PrincipalContext] Using alternate credentials");
                        var DomainName = Get_Domain().Name;
                        Context = new System.DirectoryServices.AccountManagement.PrincipalContext(System.DirectoryServices.AccountManagement.ContextType.Domain, DomainName, args.Credential.UserName, args.Credential.Password);
                    }
                    else
                    {
                        Context = new System.DirectoryServices.AccountManagement.PrincipalContext(System.DirectoryServices.AccountManagement.ContextType.Domain);
                    }
                    ObjectIdentity = args.Identity;
                }

                return new PrincipalContextEx
                {
                    Context = Context,
                    Identity = ObjectIdentity
                };
            }
            catch (Exception e)
            {
                Logger.Write_Warning($@"[Get-PrincipalContext] Error creating binding for object ('{args.Identity}') context : {e}");
            }

            return null;
        }

        public static System.DirectoryServices.AccountManagement.GroupPrincipal New_DomainGroup(Args_New_DomainGroup args = null)
        {
            if (args == null) args = new Args_New_DomainGroup();

            var ContextArguments = new Args_Get_PrincipalContext
            {
                Identity = args.SamAccountName,
                Domain = args.Domain,
                Credential = args.Credential
            };
            var Context = Get_PrincipalContext(ContextArguments);

            if (Context != null)
            {
                var Group = new System.DirectoryServices.AccountManagement.GroupPrincipal(Context.Context);

                // set all the appropriate group parameters
                Group.SamAccountName = Context.Identity;

                if (!string.IsNullOrEmpty(args.Name))
                {
                    Group.Name = args.Name;
                }
                else
                {
                    Group.Name = Context.Identity;
                }
                if (!string.IsNullOrEmpty(args.DisplayName))
                {
                    Group.DisplayName = args.DisplayName;
                }
                else
                {
                    Group.DisplayName = Context.Identity;
                }

                if (!string.IsNullOrEmpty(args.Description))
                {
                    Group.Description = args.Description;
                }

                Logger.Write_Verbose($@"[New-DomainGroup] Attempting to create group '{args.SamAccountName}'");
                try
                {
                    Group.Save();
                    Logger.Write_Verbose($@"[New-DomainGroup] Group '{args.SamAccountName}' successfully created");
                    return Group;
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[New-DomainGroup] Error creating group '{args.SamAccountName}' : {e}");
                }
            }

            return null;
        }

        public static System.DirectoryServices.AccountManagement.UserPrincipal New_DomainUser(Args_New_DomainUser args = null)
        {
            if (args == null) args = new Args_New_DomainUser();

            var ContextArguments = new Args_Get_PrincipalContext
            {
                Identity = args.SamAccountName,
                Domain = args.Domain,
                Credential = args.Credential
            };
            var Context = Get_PrincipalContext(ContextArguments);

            if (Context != null)
            {
                var User = new System.DirectoryServices.AccountManagement.UserPrincipal(Context.Context);

                // set all the appropriate user parameters
                User.SamAccountName = Context.Identity;
                var TempCred = new System.Net.NetworkCredential("a", args.AccountPassword);
                User.SetPassword(TempCred.Password);
                User.Enabled = true;
                User.PasswordNotRequired = false;

                if (!string.IsNullOrEmpty(args.Name))
                {
                    User.Name = args.Name;
                }
                else
                {
                    User.Name = Context.Identity;
                }
                if (!string.IsNullOrEmpty(args.DisplayName))
                {
                    User.DisplayName = args.DisplayName;
                }
                else
                {
                    User.DisplayName = Context.Identity;
                }

                if (!string.IsNullOrEmpty(args.Description))
                {
                    User.Description = args.Description;
                }

                Logger.Write_Verbose($@"[New-DomainUser] Attempting to create user '{args.SamAccountName}'");
                try
                {
                    User.Save();
                    Logger.Write_Verbose($@"[New-DomainUser] User '{args.SamAccountName}' successfully created");
                    return User;
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[New-DomainUser] Error creating user '{args.SamAccountName}' : {e}");
                }
            }

            return null;
        }

        public static void Add_DomainGroupMember(Args_Add_DomainGroupMember args = null)
        {
            if (args == null) args = new Args_Add_DomainGroupMember();

            var ContextArguments = new Args_Get_PrincipalContext
            {
                Identity = args.Identity,
                Domain = args.Domain,
                Credential = args.Credential
            };
            var GroupContext = Get_PrincipalContext(ContextArguments);

            System.DirectoryServices.AccountManagement.GroupPrincipal Group = null;
            if (GroupContext != null)
            {
                try
                {
                    Group = System.DirectoryServices.AccountManagement.GroupPrincipal.FindByIdentity(GroupContext.Context, GroupContext.Identity);
                }
                catch (Exception e)
                {
                    Logger.Write_Warning($@"[Add-DomainGroupMember] Error finding the group identity '{args.Identity}' : {e}");
                }
            }

            if (Group != null)
            {
                PrincipalContextEx UserContext = null;
                var UserIdentity = string.Empty;
                foreach (var Member in args.Members)
                {
                    if (Member.IsRegexMatch(@".+\\.+"))
                    {
                        ContextArguments.Identity = Member;
                        UserContext = Get_PrincipalContext(ContextArguments);
                        if (UserContext != null)
                        {
                            UserIdentity = UserContext.Identity;
                        }
                    }
                    else
                    {
                        UserContext = GroupContext;
                        UserIdentity = Member;
                    }
                    Logger.Write_Verbose($@"[Add-DomainGroupMember] Adding member '{Member}' to group '{args.Identity}'");
                    Group.Members.Add(System.DirectoryServices.AccountManagement.Principal.FindByIdentity(UserContext.Context, UserIdentity));
                    Group.Save();
                }
            }
        }

        public static void Set_DomainUserPassword(Args_Set_DomainUserPassword args = null)
        {
            if (args == null) args = new Args_Set_DomainUserPassword();

            var ContextArguments = new Args_Get_PrincipalContext
            {
                Identity = args.Identity,
                Domain = args.Domain,
                Credential = args.Credential
            };
            var Context = Get_PrincipalContext(ContextArguments);

            System.DirectoryServices.AccountManagement.UserPrincipal User = null;
            if (Context != null)
            {
                User = System.DirectoryServices.AccountManagement.UserPrincipal.FindByIdentity(Context.Context, args.Identity);

                if (User != null)
                {
                    Logger.Write_Verbose($@"[Set-DomainUserPassword] Attempting to set the password for user '{args.Identity}'");
                    try
                    {
                        var TempCred = new System.Net.NetworkCredential("a", args.AccountPassword);
                        User.SetPassword(TempCred.Password);
                        User.Save();
                        Logger.Write_Verbose($@"[Set-DomainUserPassword] Password for user '{args.Identity}' successfully reset");
                    }
                    catch (Exception e)
                    {
                        Logger.Write_Warning($@"[Set-DomainUserPassword] Error setting password for user '{args.Identity}' : {e}");
                    }
                }
                else
                {
                    Logger.Write_Warning($@"[Set-DomainUserPassword] Unable to find user '{args.Identity}'");
                }
            }
        }

        public static IEnumerable<SPNTicket> Invoke_Kerberoast(Args_Invoke_Kerberoast args = null)
        {
            if (args == null) args = new Args_Invoke_Kerberoast();

            var UserSearcherArguments = new Args_Get_DomainUser
            {
                SPN = true,
                Properties = new[] { "samaccountname", "distinguishedname", "serviceprincipalname" },
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    Credential = args.Credential
                });
            }

            if (args.Identity != null) { UserSearcherArguments.Identity = args.Identity; }
            var users = Get_DomainUser(UserSearcherArguments) as IEnumerable<LDAPProperty>;
            IEnumerable<SPNTicket> ret = null;
            if (users != null)
            {
                users.Where(x => x.samaccountname != "krbtgt");
                ret = Get_DomainSPNTicket();
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }

            return ret;
        }

        private static string ToCsv<T>(string separator, IEnumerable<T> objectlist)
        {
            Type t = typeof(T);
            FieldInfo[] fields = t.GetFields();

            string header = String.Join(separator, fields.Select(f => f.Name).ToArray());

            StringBuilder csvdata = new StringBuilder();
            csvdata.AppendLine(header);

            foreach (var o in objectlist)
                csvdata.AppendLine(ToCsvFields(separator, fields, o));

            return csvdata.ToString();
        }

        private static string ToCsvFields(string separator, FieldInfo[] fields, object o)
        {
            StringBuilder linie = new StringBuilder();

            foreach (var f in fields)
            {
                if (linie.Length > 0)
                    linie.Append(separator);

                var x = f.GetValue(o);

                if (x != null)
                    linie.Append(x.ToString());
            }

            return linie.ToString();
        }

        public static void Export_PowerViewCSV(Args_Export_PowerViewCSV args = null)
        {
            if (args == null) args = new Args_Export_PowerViewCSV();

            var OutputPath = Path.GetFullPath(args.Path);
            var Exists = File.Exists(OutputPath);

            // mutex so threaded code doesn't stomp on the output file
            var Mutex = new System.Threading.Mutex(false, "CSVMutex");
            Mutex.WaitOne();

            FileMode FileMode;
            if (args.Append)
            {
                FileMode = System.IO.FileMode.Append;
            }
            else
            {
                FileMode = System.IO.FileMode.Create;
                Exists = false;
            }

            var CSVStream = new FileStream(OutputPath, FileMode, System.IO.FileAccess.Write, FileShare.Read);
            var CSVWriter = new System.IO.StreamWriter(CSVStream);
            CSVWriter.AutoFlush = true;

            var csv = ToCsv<object>(args.Delimiter.ToString(), args.InputObject);

            CSVWriter.Write(csv);

            Mutex.ReleaseMutex();
            CSVWriter.Dispose();
            CSVStream.Dispose();
        }
        
        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<string> _Find_LocalAdminAccess(string[] ComputerName, IntPtr TokenHandle)
        {
            var LogonToken = IntPtr.Zero;
            if (TokenHandle != IntPtr.Zero)
            {
                // impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    TokenHandle = TokenHandle,
                    Quiet = true
                });
            }

            var TargetComputers = new List<string>();
            foreach (var TargetComputer in ComputerName)
            {
                var Up = TestConnection.Ping(TargetComputer, 1);
                if (Up) {
                    // check if the current user has local admin access to this server
                    var Access = Test_AdminAccess(new Args_Test_AdminAccess { ComputerName = new[] { TargetComputer } }).FirstOrDefault();
                    if (Access != null && Access.IsAdmin) {
                        TargetComputers.Add(TargetComputer);
                    }
                }
            }

            if (TokenHandle != IntPtr.Zero) {
                Invoke_RevertToSelf(LogonToken);
            }
            return TargetComputers;
        }

        public static IEnumerable<string> Find_LocalAdminAccess(Args_Find_LocalAdminAccess args = null)
        {
            if (args == null) args = new Args_Find_LocalAdminAccess();

            var ComputerSearcherArguments = new Args_Get_DomainComputer
            {
                Properties = new[] { "dnshostname" },
                Domain = args.ComputerDomain,
                LDAPFilter = args.ComputerLDAPFilter,
                SearchBase = args.ComputerSearchBase,
                //Unconstrained = args.Unconstrained,
                OperatingSystem = args.OperatingSystem,
                ServicePack = args.ServicePack,
                SiteName = args.SiteName,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            string[] TargetComputers;
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                Logger.Write_Verbose($@"[Find-LocalAdminAccess] Querying computers in the domain");
                TargetComputers = Get_DomainComputer(ComputerSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
            }
            if (TargetComputers == null || TargetComputers.Length == 0)
            {
                throw new Exception("[Find-LocalAdminAccess] No hosts found to enumerate");
            }
            Logger.Write_Verbose($@"[Find-LocalAdminAccess] TargetComputers length: {TargetComputers.Length}");

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                if (args.Delay != 0/* || args.StopOnSuccess*/)
                {
                    LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential
                    });
                }
                else
                {
                    LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential,
                        Quiet = true
                    });
                }
            }

            var rets = new List<string>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0/* || args.StopOnSuccess*/)
            {
                Logger.Write_Verbose($@"[Find-LocalAdminAccess] Total number of hosts: {TargetComputers.Count()}");
                Logger.Write_Verbose($@"[Find-LocalAdminAccess] Delay: {args.Delay}, Jitter: {args.Jitter}");
                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-LocalAdminAccess] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var ret = _Find_LocalAdminAccess(new[] { TargetComputer }, LogonToken);
                    if (ret != null)
                        rets.AddRange(ret);
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-LocalAdminAccess] Using threading with threads: {args.Threads}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                    TargetComputers,
                    TargetComputer =>
                    {
                        var ret = _Find_LocalAdminAccess(new[] { TargetComputer }, LogonToken);
                        lock (rets)
                        {
                            if (ret != null)
                                rets.AddRange(ret);
                        }
                    });
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return rets;
        }

        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<object> _Find_DomainLocalGroupMember(string[] ComputerName, string GroupName, MethodType Method, IntPtr TokenHandle)
        {
            // Add check if user defaults to/selects "Administrators"
            if (GroupName == "Administrators") {
                var AdminSecurityIdentifier = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                GroupName = AdminSecurityIdentifier.Translate(typeof(System.Security.Principal.NTAccount)).Value.Split('\\').LastOrDefault();
            }

            var LogonToken = IntPtr.Zero;
            if (TokenHandle != IntPtr.Zero)
            {
                // impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    TokenHandle = TokenHandle,
                    Quiet = true
                });
            }

            var Members = new List<object>();
            foreach (var TargetComputer in ComputerName)
            {
                var Up = TestConnection.Ping(TargetComputer, 1);
                if (Up)
                {
                    var NetLocalGroupMemberArguments = new Args_Get_NetLocalGroupMember
                    {
                        ComputerName = new[] { TargetComputer },
                        Method = Method,
                        GroupName = GroupName
                    };
                    var ret = Get_NetLocalGroupMember(NetLocalGroupMemberArguments);
                    if (ret != null)
                        Members.AddRange(ret);
                }
            }

            if (TokenHandle != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return Members;
        }

        public static IEnumerable<object> Find_DomainLocalGroupMember(Args_Find_DomainLocalGroupMember args = null)
        {
            if (args == null) args = new Args_Find_DomainLocalGroupMember();

            var ComputerSearcherArguments = new Args_Get_DomainComputer
            {
                Properties = new[] { "dnshostname" },
                Domain = args.ComputerDomain,
                LDAPFilter = args.ComputerLDAPFilter,
                SearchBase = args.ComputerSearchBase,
                //Unconstrained = args.Unconstrained,
                OperatingSystem = args.OperatingSystem,
                ServicePack = args.ServicePack,
                SiteName = args.SiteName,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            string[] TargetComputers;
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] Querying computers in the domain");
                TargetComputers = Get_DomainComputer(ComputerSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
            }

            if (TargetComputers == null || TargetComputers.Length == 0)
            {
                throw new Exception("[Find-DomainLocalGroupMember] No hosts found to enumerate");
            }
            Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] TargetComputers length: {TargetComputers.Length}");

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                if (args.Delay != 0/* || args.StopOnSuccess*/)
                {
                    LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential
                    });
                }
                else
                {
                    LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential,
                        Quiet = true
                    });
                }
            }

            var rets = new List<object>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0/* || args.StopOnSuccess*/)
            {
                Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] Total number of hosts: {TargetComputers.Count()}");
                Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] Delay: {args.Delay}, Jitter: {args.Jitter}");
                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var ret = _Find_DomainLocalGroupMember(new[] { TargetComputer }, args.GroupName, args.Method, LogonToken);
                    if (ret != null)
                        rets.AddRange(ret);
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainLocalGroupMember] Using threading with threads: {args.Threads}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                        TargetComputers,
                        TargetComputer =>
                        {
                            var ret = _Find_DomainLocalGroupMember(new[] { TargetComputer }, args.GroupName, args.Method, LogonToken);
                            lock (rets)
                            {
                                if (ret != null)
                                    rets.AddRange(ret);
                            }
                        });
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return rets;
        }

        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<ShareInfo> _Find_DomainShare(string[] ComputerName, bool CheckShareAccess, IntPtr TokenHandle)
        {
            var LogonToken = IntPtr.Zero;
            if (TokenHandle != IntPtr.Zero)
            {
                // impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    TokenHandle = TokenHandle,
                    Quiet = true
                });
            }

            var DomainShares = new List<ShareInfo>();
            foreach (var TargetComputer in ComputerName)
            {
                var Up = TestConnection.Ping(TargetComputer, 1);
                if (Up)
                {
                    // get the shares for this host and check what we find
                    var Shares = Get_NetShare(new Args_Get_NetShare
                    {
                        ComputerName = new[] { TargetComputer }
                    });

                    foreach (var Share in Shares)
                    {
                        var ShareName = Share.Name;
                        // $Remark = $Share.Remark
                        var Path = @"\\" + TargetComputer + @"\" + ShareName;

                        if ((!string.IsNullOrEmpty(ShareName)) && (ShareName.Trim() != ""))
                        {
                            // see if we want to check access to this share
                            if (CheckShareAccess)
                            {
                                // check if the user has access to this path
                                try
                                {
                                    Directory.GetFiles(Path);
                                    DomainShares.Add(Share);
                                }
                                catch (Exception e)
                                {
                                    Logger.Write_Verbose($@"Error accessing share path {Path} : {e}");
                                }
                            }
                            else
                            {
                                DomainShares.Add(Share);
                            }
                        }
                    }
                }
            }

            if (TokenHandle != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return DomainShares;
        }

        public static IEnumerable<ShareInfo> Find_DomainShare(Args_Find_DomainShare args = null)
        {
            if (args == null) args = new Args_Find_DomainShare();

            var ComputerSearcherArguments = new Args_Get_DomainComputer
            {
                Properties = new[] { "dnshostname" },
                Domain = args.ComputerDomain,
                LDAPFilter = args.ComputerLDAPFilter,
                SearchBase = args.ComputerSearchBase,
                //Unconstrained = args.Unconstrained,
                OperatingSystem = args.OperatingSystem,
                ServicePack = args.ServicePack,
                SiteName = args.SiteName,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            string[] TargetComputers;
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainShare] Querying computers in the domain");
                TargetComputers = Get_DomainComputer(ComputerSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
            }

            if (TargetComputers == null || TargetComputers.Length == 0)
            {
                throw new Exception("[Find-DomainShare] No hosts found to enumerate");
            }
            Logger.Write_Verbose($@"[Find-DomainShare] TargetComputers length: {TargetComputers.Length}");

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                if (args.Delay != 0/* || args.StopOnSuccess*/)
                {
                    LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential
                    });
                }
                else
                {
                    LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential,
                        Quiet = true
                    });
                }
            }

            var rets = new List<ShareInfo>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0/* || args.StopOnSuccess*/)
            {
                Logger.Write_Verbose($@"[Find-DomainShare] Total number of hosts: {TargetComputers.Count()}");
                Logger.Write_Verbose($@"[Find-DomainShare] Delay: {args.Delay}, Jitter: {args.Jitter}");

                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-DomainShare] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var ret = _Find_DomainShare(new[] { TargetComputer }, args.CheckShareAccess, LogonToken);
                    if (ret != null)
                        rets.AddRange(ret);
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainShare] Using threading with threads: {args.Threads}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                            TargetComputers,
                            TargetComputer =>
                            {
                                var ret = _Find_DomainShare(new[] { TargetComputer }, args.CheckShareAccess, LogonToken);
                                lock (rets)
                                {
                                    if (ret != null)
                                        rets.AddRange(ret);
                                }
                            });
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return rets;
        }

        private static IEnumerable<IWinEvent> _Find_DomainUserEvent(string[] ComputerName, DateTime StartTime, DateTime EndTime, int MaxEvents, string[] TargetUsers, Dictionary<string, string> Filter, System.Net.NetworkCredential Credential)
        {
            var Events = new List<IWinEvent>();
            foreach (var TargetComputer in ComputerName)
            {
                var Up = TestConnection.Ping(TargetComputer, 1);
                if (Up)
                {
                    var DomainUserEventArgs = new Args_Get_DomainUserEvent
                    {
                        ComputerName = new[] { TargetComputer },
                        StartTime = StartTime,
                        EndTime = EndTime,
                        MaxEvents = MaxEvents,
                        Credential = Credential
                    };
                    if (Filter != null || TargetUsers != null)
                    {
                        if (TargetUsers != null)
                        {
                            Get_DomainUserEvent(DomainUserEventArgs).Where(x => TargetUsers.Contains((x is LogonEvent) ? (x as LogonEvent).TargetUserName : (x as ExplicitCredentialLogonEvent).TargetUserName));
                        }
                        else
                        {
                            var Operator = "or";
                            foreach (var key in Filter.Keys)
                            {
                                if ((key == "Op") || (key == "Operator") || (key == "Operation"))
                                {
                                    if ((Filter[key].IsRegexMatch("&")) || (Filter[key] == "and"))
                                    {
                                        Operator = "and";
                                    }
                                }
                            }
                            var Keys = Filter.Keys.Where(x => (x != "Op") && (x != "Operator") && (x != "Operation"));
                            var events = Get_DomainUserEvent(DomainUserEventArgs);
                            foreach (var evt in events)
                            {
                                if (Operator == "or")
                                {
                                    foreach (var Key in Keys)
                                    {
                                        if (evt.GetPropValue<string>(Key).IsRegexMatch(Filter[Key]))
                                        {
                                            Events.Add(evt);
                                        }
                                    }
                                }
                                else
                                {
                                    // and all clauses
                                    foreach (var Key in Keys)
                                    {
                                        if (!evt.GetPropValue<string>(Key).IsRegexMatch(Filter[Key]))
                                        {
                                            break;
                                        }
                                        Events.Add(evt);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        Get_DomainUserEvent(DomainUserEventArgs);
                    }
                }
            }

            return Events;
        }

        // the host enumeration block we're using to enumerate all servers
        public static IEnumerable<object> Find_DomainUserEvent(Args_Find_DomainUserEvent args = null)
        {
            if (args == null) args = new Args_Find_DomainUserEvent();

            var UserSearcherArguments = new Args_Get_DomainUser
            {
                Properties = new[] { "samaccountname" },
                Identity = args.UserIdentity,
                Domain = args.UserDomain,
                LDAPFilter = args.UserLDAPFilter,
                SearchBase = args.UserSearchBase,
                AdminCount = args.UserAdminCount,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            string[] TargetUsers = null;
            if (args.UserIdentity != null || !string.IsNullOrEmpty(args.UserLDAPFilter) || !string.IsNullOrEmpty(args.UserSearchBase) || args.UserAdminCount)
            {
                TargetUsers = Get_DomainUser(UserSearcherArguments).Select(x => (x as LDAPProperty).samaccountname).ToArray();
            }
            else if (args.UserGroupIdentity != null || (args.Filter == null))
            {
                // otherwise we're querying a specific group
                var GroupSearcherArguments = new Args_Get_DomainGroupMember
                {
                    Identity = args.UserGroupIdentity,
                    Recurse = true,
                    Domain = args.UserDomain,
                    SearchBase = args.UserSearchBase,
                    Server = args.Server,
                    SearchScope = args.SearchScope,
                    ResultPageSize = args.ResultPageSize,
                    ServerTimeLimit = args.ServerTimeLimit,
                    Tombstone = args.Tombstone,
                    Credential = args.Credential
                };
                Logger.Write_Verbose($@"UserGroupIdentity: {args.UserGroupIdentity.ToJoinedString()}");
                TargetUsers = Get_DomainGroupMember(GroupSearcherArguments).Select(x => x.MemberName).ToArray();
            }

            // build the set of computers to enumerate
            string[] TargetComputers = null;
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                // if not -ComputerName is passed, query the current (or target) domain for domain controllers
                var DCSearcherArguments = new Args_Get_DomainController
                {
                    LDAP = true,
                    Domain = args.Domain,
                    Server = args.Server,
                    Credential = args.Credential
                };
                Logger.Write_Verbose($@"[Find-DomainUserEvent] Querying for domain controllers in domain: {args.Domain}");
                TargetComputers = Get_DomainController(DCSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
            }
            Logger.Write_Verbose($@"[Find-DomainUserEvent] TargetComputers length: {TargetComputers.Count()}");
            Logger.Write_Verbose($@"[Find-DomainUserEvent] TargetComputers {TargetComputers.ToJoinedString()}");
            if (TargetComputers == null || TargetComputers.Length == 0)
            {
                throw new Exception("[Find-DomainUserEvent] No hosts found to enumerate");
            }

            var rets = new List<IWinEvent>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0 || args.StopOnSuccess)
            {
                Logger.Write_Verbose($@"[Find-DomainUserEvent] TargetComputers length: {TargetComputers.Length}");
                Logger.Write_Verbose($@"[Find-DomainUserEvent] Delay: {args.Delay}, Jitter: {args.Jitter}");
                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-DomainUserEvent] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var Result = _Find_DomainUserEvent(new[] { TargetComputer }, args.StartTime, args.EndTime, args.MaxEvents, TargetUsers, args.Filter, args.Credential);
                    if (Result != null)
                        rets.AddRange(Result);

                    if (Result != null && args.StopOnSuccess)
                    {
                        Logger.Write_Verbose("[Find-DomainUserEvent] Target user found, returning early");
                        return rets;
                    }
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainUserEvent] Using threading with threads: {args.Threads}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                                TargetComputers,
                                TargetComputer =>
                                {
                                    var Result = _Find_DomainUserEvent(new[] { TargetComputer }, args.StartTime, args.EndTime, args.MaxEvents, TargetUsers, args.Filter, args.Credential);
                                    lock (rets)
                                    {
                                        if (Result != null)
                                            rets.AddRange(Result);
                                    }
                                });
            }

            return rets;
        }

        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<UserProcess> _Find_DomainProcess(string[] ComputerName, string[] ProcessName, string[] TargetUsers, System.Net.NetworkCredential Credential)
        {
            List<UserProcess> DomainProcesses = new List<UserProcess>();
            foreach (var TargetComputer in ComputerName)
            {
                var Up = TestConnection.Ping(TargetComputer, 1);
                if (Up)
                {
                    // try to enumerate all active processes on the remote host
                    // and search for a specific process name
                    IEnumerable<UserProcess> Processes;
                    if (Credential != null)
                    {
                        Processes = Get_WMIProcess(new Args_Get_WMIProcess { Credential = Credential, ComputerName = new[] { TargetComputer } });
                    }
                    else
                    {
                        Processes = Get_WMIProcess(new Args_Get_WMIProcess { ComputerName = new[] { TargetComputer } });
                    }
                    foreach (var Process in Processes)
                    {
                        // if we're hunting for a process name or comma-separated names
                        if (ProcessName != null)
                        {
                            if (ProcessName.Contains(Process.ProcessName))
                            {
                                DomainProcesses.Add(Process);
                            }
                        }
                        // if the session user is in the target list, display some output
                        else if (TargetUsers.Contains(Process.User))
                        {
                            DomainProcesses.Add(Process);
                        }
                    }
                }
            }

            return DomainProcesses;
        }

        public static IEnumerable<UserProcess> Find_DomainProcess(Args_Find_DomainProcess args = null)
        {
            if (args == null) args = new Args_Find_DomainProcess();

            var ComputerSearcherArguments = new Args_Get_DomainComputer
            {
                Properties = new[] { "dnshostname" },
                Domain = args.Domain,
                LDAPFilter = args.ComputerLDAPFilter,
                SearchBase = args.ComputerSearchBase,
                Unconstrained = args.Unconstrained,
                OperatingSystem = args.OperatingSystem,
                ServicePack = args.ServicePack,
                SiteName = args.SiteName,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            if (!string.IsNullOrEmpty(args.ComputerDomain))
                ComputerSearcherArguments.Domain = args.ComputerDomain;

            var UserSearcherArguments = new Args_Get_DomainUser
            {
                Properties = new[] { "samaccountname" },
                Identity = args.UserIdentity,
                Domain = args.Domain,
                LDAPFilter = args.UserLDAPFilter,
                SearchBase = args.UserSearchBase,
                AdminCount = args.UserAdminCount,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            if (!string.IsNullOrEmpty(args.UserDomain))
                UserSearcherArguments.Domain = args.UserDomain;

            // first, build the set of computers to enumerate
            string[] TargetComputers = null;
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                Logger.Write_Verbose(@"[Find-DomainProcess] Querying computers in the domain");
                TargetComputers = Get_DomainComputer(ComputerSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
            }
            if (TargetComputers == null || TargetComputers.Length == 0)
            {
                throw new Exception("[Find-DomainProcess] No hosts found to enumerate");
            }
            Logger.Write_Verbose($@"[Find-DomainProcess] TargetComputers length: {TargetComputers.Length}");

            // now build the user target set
            List<string> TargetProcessName = null;
            string[] TargetUsers = null;
            if (args.ProcessName != null)
            {
                TargetProcessName = new List<string>();
                foreach (var T in args.ProcessName)
                {
                    TargetProcessName.AddRange(T.Split(','));
                }
            }
            else if (args.UserIdentity != null || args.UserLDAPFilter != null || args.UserSearchBase != null || args.UserAdminCount/* || args.UserAllowDelegation*/)
            {
                TargetUsers = Get_DomainUser(UserSearcherArguments).Select(x => (x as LDAPProperty).samaccountname).ToArray();
            }
            else
            {
                var GroupSearcherArguments = new Args_Get_DomainGroupMember
                {
                    Identity = args.UserGroupIdentity,
                    Recurse = true,
                    Domain = args.UserDomain,
                    SearchBase = args.UserSearchBase,
                    Server = args.Server,
                    SearchScope = args.SearchScope,
                    ResultPageSize = args.ResultPageSize,
                    ServerTimeLimit = args.ServerTimeLimit,
                    Tombstone = args.Tombstone,
                    Credential = args.Credential
                };
                TargetUsers = Get_DomainGroupMember(GroupSearcherArguments).Select(x => x.MemberName).ToArray();
            }

            var rets = new List<UserProcess>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0 || args.StopOnSuccess)
            {
                Logger.Write_Verbose($@"[Find-DomainProcess] Total number of hosts: {TargetComputers.Count()}");
                Logger.Write_Verbose($@"[Find-DomainProcess] Delay: {args.Delay}, Jitter: {args.Jitter}");
                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-DomainProcess] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var Result = _Find_DomainProcess(new[] { TargetComputer }, TargetProcessName?.ToArray(), TargetUsers, args.Credential);
                    if (Result != null)
                        rets.AddRange(Result);

                    if (Result != null && args.StopOnSuccess)
                    {
                        Logger.Write_Verbose("[Find-DomainProcess] Target user found, returning early");
                        return rets;
                    }
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainProcess] Using threading with threads: {args.Threads}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                                    TargetComputers,
                                    TargetComputer =>
                                    {
                                        var Result = _Find_DomainProcess(new[] { TargetComputer }, TargetProcessName?.ToArray(), TargetUsers, args.Credential);
                                        lock (rets)
                                        {
                                            if (Result != null)
                                                rets.AddRange(Result);
                                        }
                                    });
            }

            return rets;
        }

        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<UserLocation> _Find_DomainUserLocation(string[] ComputerName, string[] TargetUsers, string CurrentUser, bool Stealth, bool CheckAccess, IntPtr TokenHandle)
        {
            var LogonToken = IntPtr.Zero;
            if (TokenHandle != IntPtr.Zero)
            {
                // impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    TokenHandle = TokenHandle,
                    Quiet = true
                });
            }

            var UserLocations = new List<UserLocation>();
            foreach (var TargetComputer in ComputerName)
            {
                var Up = TestConnection.Ping(TargetComputer, 1);
                if (Up)
                {
                    var Sessions = Get_NetSession(new Args_Get_NetSession { ComputerName = new[] { TargetComputer } });
                    foreach (var Session in Sessions)
                    {
                        var UserName = Session.UserName;
                        var CName = Session.CName;

                        if (!CName.IsNullOrEmpty() && CName.StartsWith(@"\\"))
                        {
                            CName = CName.TrimStart('\\');
                        }

                        // make sure we have a result, and ignore computer$ sessions
                        if ((UserName != null) && (UserName.Trim() != "") && (!UserName.IsRegexMatch(CurrentUser)) && (!UserName.IsRegexMatch(@"\$$")))
                        {
                            if ((TargetUsers == null) || (TargetUsers.Contains(UserName)))
                            {
                                var UserLocation = new UserLocation
                                {
                                    UserDomain = null,
                                    UserName = UserName,
                                    ComputerName = TargetComputer,
                                    SessionFrom = CName
                                };

                                // try to resolve the DNS hostname of $Cname
                                try
                                {
                                    var CNameDNSName = System.Net.Dns.GetHostEntry(CName).HostName;
                                    UserLocation.SessionFromName = CNameDNSName;
                                }
                                catch
                                {
                                    UserLocation.SessionFromName = null;
                                }

                                // see if we're checking to see if we have local admin access on this machine
                                if (CheckAccess)
                                {
                                    var Admin = Test_AdminAccess(new Args_Test_AdminAccess { ComputerName = new[] { CName } }).FirstOrDefault();
                                    UserLocation.LocalAdmin = Admin != null ? Admin.IsAdmin : false;
                                }
                                else
                                {
                                    UserLocation.LocalAdmin = false;
                                }
                                UserLocations.Add(UserLocation);
                            }
                        }
                    }
                    if (!Stealth)
                    {
                        // if we're not 'stealthy', enumerate loggedon users as well
                        var LoggedOn = Get_NetLoggedon(new Args_Get_NetLoggedon { ComputerName = new[] { TargetComputer } });
                        foreach (var User in LoggedOn)
                        {
                            var UserName = User.UserName;
                            var UserDomain = User.LogonDomain;

                            // make sure wet have a result
                            if ((UserName != null) && (UserName.Trim() != ""))
                            {
                                if ((TargetUsers == null) || (TargetUsers.Contains(UserName)) && (!UserName.IsRegexMatch(@"\$$")))
                                {
                                    var IPAddress = Resolve_IPAddress(new Args_Resolve_IPAddress { ComputerName = new[] { TargetComputer } }).FirstOrDefault()?.IPAddress;
                                    var UserLocation = new UserLocation
                                    {
                                        UserDomain = UserDomain,
                                        UserName = UserName,
                                        ComputerName = TargetComputer,
                                        IPAddress = IPAddress,
                                        SessionFrom = null,
                                        SessionFromName = null
                                    };

                                    // see if we're checking to see if we have local admin access on this machine
                                    if (CheckAccess)
                                    {
                                        var Admin = Test_AdminAccess(new Args_Test_AdminAccess { ComputerName = new[] { TargetComputer } }).FirstOrDefault();
                                        UserLocation.LocalAdmin = Admin.IsAdmin;
                                    }
                                    else
                                    {
                                        UserLocation.LocalAdmin = false;
                                    }
                                    UserLocations.Add(UserLocation);
                                }
                            }
                        }
                    }
                }
            }

            if (TokenHandle != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return UserLocations;
        }

        public static IEnumerable<UserLocation> Find_DomainUserLocation(Args_Find_DomainUserLocation args = null)
        {
            if (args == null) args = new Args_Find_DomainUserLocation();

            var ComputerSearcherArguments = new Args_Get_DomainComputer
            {
                Properties = new[] { "dnshostname" },
                Domain = args.Domain,
                LDAPFilter = args.ComputerLDAPFilter,
                SearchBase = args.ComputerSearchBase,
                Unconstrained = args.Unconstrained,
                OperatingSystem = args.OperatingSystem,
                ServicePack = args.ServicePack,
                SiteName = args.SiteName,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            if (!string.IsNullOrEmpty(args.ComputerDomain))
                ComputerSearcherArguments.Domain = args.ComputerDomain;

            var UserSearcherArguments = new Args_Get_DomainUser
            {
                Properties = new[] { "samaccountname" },
                Identity = args.UserIdentity,
                Domain = args.Domain,
                LDAPFilter = args.UserLDAPFilter,
                SearchBase = args.UserSearchBase,
                AdminCount = args.UserAdminCount,
                AllowDelegation = args.AllowDelegation,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            if (!string.IsNullOrEmpty(args.UserDomain))
                UserSearcherArguments.Domain = args.UserDomain;

            string[] TargetComputers = null;

            // first, build the set of computers to enumerate
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                if (args.Stealth)
                {
                    Logger.Write_Verbose($@"[Find-DomainUserLocation] Stealth enumeration using source: {args.StealthSource}");
                    var TargetComputerArrayList = new System.Collections.ArrayList();

                    if (args.StealthSource.ToString().IsRegexMatch("File|All"))
                    {
                        Logger.Write_Verbose("[Find-DomainUserLocation] Querying for file servers");
                        var FileServerSearcherArguments = new Args_Get_DomainFileServer
                        {
                            Domain = new[] { args.Domain },
                            SearchBase = args.ComputerSearchBase,
                            Server = args.Server,
                            SearchScope = args.SearchScope,
                            ResultPageSize = args.ResultPageSize,
                            ServerTimeLimit = args.ServerTimeLimit,
                            Tombstone = args.Tombstone,
                            Credential = args.Credential
                        };
                        if (!string.IsNullOrEmpty(args.ComputerDomain))
                            FileServerSearcherArguments.Domain = new[] { args.ComputerDomain };
                        var FileServers = Get_DomainFileServer(FileServerSearcherArguments);
                        TargetComputerArrayList.AddRange(FileServers);
                    }
                    if (args.StealthSource.ToString().IsRegexMatch("DFS|All"))
                    {
                        Logger.Write_Verbose(@"[Find-DomainUserLocation] Querying for DFS servers");
                        // # TODO: fix the passed parameters to Get-DomainDFSShare
                        // $ComputerName += Get-DomainDFSShare -Domain $Domain -Server $DomainController | ForEach-Object {$_.RemoteServerName}
                    }
                    if (args.StealthSource.ToString().IsRegexMatch("DC|All"))
                    {
                        Logger.Write_Verbose(@"[Find-DomainUserLocation] Querying for domain controllers");
                        var DCSearcherArguments = new Args_Get_DomainController
                        {
                            LDAP = true,
                            Domain = args.Domain,
                            Server = args.Server,
                            Credential = args.Credential
                        };
                        if (!string.IsNullOrEmpty(args.ComputerDomain))
                            DCSearcherArguments.Domain = args.ComputerDomain;
                        var DomainControllers = Get_DomainController(DCSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
                        TargetComputerArrayList.AddRange(DomainControllers);
                    }
                    TargetComputers = TargetComputerArrayList.ToArray() as string[];
                }
            }
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                if (args.Stealth)
                {
                    Logger.Write_Verbose($@"[Find-DomainUserLocation] Stealth enumeration using source: {args.StealthSource}");
                    var TargetComputerArrayList = new System.Collections.ArrayList();

                    if (args.StealthSource.ToString().IsRegexMatch("File|All"))
                    {
                        Logger.Write_Verbose("[Find-DomainUserLocation] Querying for file servers");
                        var FileServerSearcherArguments = new Args_Get_DomainFileServer
                        {
                            Domain = new[] { args.Domain },
                            SearchBase = args.ComputerSearchBase,
                            Server = args.Server,
                            SearchScope = args.SearchScope,
                            ResultPageSize = args.ResultPageSize,
                            ServerTimeLimit = args.ServerTimeLimit,
                            Tombstone = args.Tombstone,
                            Credential = args.Credential
                        };
                        if (!string.IsNullOrEmpty(args.ComputerDomain))
                            FileServerSearcherArguments.Domain = new[] { args.ComputerDomain };
                        var FileServers = Get_DomainFileServer(FileServerSearcherArguments);
                        TargetComputerArrayList.AddRange(FileServers);
                    }
                    if (args.StealthSource.ToString().IsRegexMatch("DFS|All"))
                    {
                        Logger.Write_Verbose(@"[Find-DomainUserLocation] Querying for DFS servers");
                        // # TODO: fix the passed parameters to Get-DomainDFSShare
                        // $ComputerName += Get-DomainDFSShare -Domain $Domain -Server $DomainController | ForEach-Object {$_.RemoteServerName}
                    }
                    if (args.StealthSource.ToString().IsRegexMatch("DC|All"))
                    {
                        Logger.Write_Verbose(@"[Find-DomainUserLocation] Querying for domain controllers");
                        var DCSearcherArguments = new Args_Get_DomainController
                        {
                            LDAP = true,
                            Domain = args.Domain,
                            Server = args.Server,
                            Credential = args.Credential
                        };
                        if (!string.IsNullOrEmpty(args.ComputerDomain))
                            DCSearcherArguments.Domain = args.ComputerDomain;
                        var DomainControllers = Get_DomainController(DCSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
                        TargetComputerArrayList.AddRange(DomainControllers);
                    }
                    TargetComputers = TargetComputerArrayList.ToArray() as string[];
                }
                else
                {
                    Logger.Write_Verbose("[Find-DomainUserLocation] Querying for all computers in the domain");
                    TargetComputers = Get_DomainComputer(ComputerSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
                }
            }
            Logger.Write_Verbose($@"[Find-DomainUserLocation] TargetComputers length: {TargetComputers.Length}");
            if (TargetComputers.Length == 0)
            {
                throw new Exception("[Find-DomainUserLocation] No hosts found to enumerate");
            }

            // get the current user so we can ignore it in the results
            string CurrentUser;
            if (args.Credential != null)
            {
                CurrentUser = args.Credential.UserName;
            }
            else
            {
                CurrentUser = Environment.UserName.ToLower();
            }

            // now build the user target set
            string[] TargetUsers = null;
            if (args.ShowAll)
            {
                TargetUsers = new string[] { };
            }
            else if (args.UserIdentity != null || args.UserLDAPFilter != null || args.UserSearchBase != null || args.UserAdminCount || args.UserAllowDelegation)
            {
                TargetUsers = Get_DomainUser(UserSearcherArguments).Select(x => (x as LDAPProperty).samaccountname).ToArray();
            }
            else
            {
                var GroupSearcherArguments = new Args_Get_DomainGroupMember
                {
                    Identity = args.UserGroupIdentity,
                    Recurse = true,
                    Domain = args.UserDomain,
                    SearchBase = args.UserSearchBase,
                    Server = args.Server,
                    SearchScope = args.SearchScope,
                    ResultPageSize = args.ResultPageSize,
                    ServerTimeLimit = args.ServerTimeLimit,
                    Tombstone = args.Tombstone,
                    Credential = args.Credential
                };
                TargetUsers = Get_DomainGroupMember(GroupSearcherArguments).Select(x => x.MemberName).ToArray();
            }

            Logger.Write_Verbose($@"[Find-DomainUserLocation] TargetUsers length: {TargetUsers.Length}");
            if ((!args.ShowAll) && (TargetUsers.Length == 0))
            {
                throw new Exception("[Find-DomainUserLocation] No users found to target");
            }

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                if (args.Delay != 0 || args.StopOnSuccess)
                {
                    LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential
                    });
                }
                else
                {
                    LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential,
                        Quiet = true
                    });
                }
            }

            var rets = new List<UserLocation>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0/* || args.StopOnSuccess*/)
            {
                Logger.Write_Verbose($@"[Find-DomainUserLocation] Total number of hosts: {TargetComputers.Count()}");
                Logger.Write_Verbose($@"[Find-DomainUserLocation] Delay: {args.Delay}, Jitter: {args.Jitter}");

                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-DomainUserLocation] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var Result = _Find_DomainUserLocation(new[] { TargetComputer }, TargetUsers, CurrentUser, args.Stealth, args.CheckAccess, LogonToken);
                    if (Result != null)
                        rets.AddRange(Result);
                    if (Result != null && args.StopOnSuccess)
                    {
                        Logger.Write_Verbose("[Find-DomainUserLocation] Target user found, returning early");
                        return rets;
                    }
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainUserLocation] Using threading with threads: {args.Threads}");
                Logger.Write_Verbose($@"[Find-DomainUserLocation] TargetComputers length: {TargetComputers.Length}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                            TargetComputers,
                            TargetComputer =>
                            {
                                var Result = _Find_DomainUserLocation(new[] { TargetComputer }, TargetUsers, CurrentUser, args.Stealth, args.CheckAccess, LogonToken);
                                lock (rets)
                                {
                                    if (Result != null)
                                        rets.AddRange(Result);
                                }
                            });
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return rets;
        }

        private static bool Test_Write(string Path)
        {
            // short helper to check is the current user can write to a file
            try {
                var Filetest = File.OpenWrite(Path);
                Filetest.Close();
                return true;
            }
            catch {
                return false;
            }
        }

        public static IEnumerable<FoundFile> Find_InterestingFile(Args_Find_InterestingFile args = null)
        {
            if (args == null) args = new Args_Find_InterestingFile();

            if (args.OfficeDocs)
            {
                args.Include = new[] { ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx" };
            }
            else if (args.FreshEXEs)
            {
                // find .exe's accessed within the last 7 days
                args.LastAccessTime = DateTime.Now.Date.AddDays(-7);
                args.Include = new[] { ".exe" };
            }

            var FoundFiles = new List<FoundFile>();
            var MappedComputers = new Dictionary<string, bool>();
            foreach (var TargetPath in args.Path)
            {
                if ((TargetPath.IsRegexMatch(@"\\\\.*\\.*")) && (args.Credential != null))
                {
                    var HostComputer = new System.Uri(TargetPath).Host;
                    if (!MappedComputers[HostComputer])
                    {
                        // map IPC$ to this computer if it's not already
                        Add_RemoteConnection(new Args_Add_RemoteConnection { ComputerName = new[] { HostComputer }, Credential = args.Credential });
                        MappedComputers[HostComputer] = true;
                    }
                }

                var files = PathExtension.GetDirectoryFiles(TargetPath, args.Include, SearchOption.AllDirectories);
                //var files = Directory.EnumerateFiles(TargetPath, "*.*", SearchOption.AllDirectories)
                //                                   .Where(x => args.Include.EndsWith(x, StringComparison.OrdinalIgnoreCase));

                foreach (var file in files)
                {
                    var Continue = true;
                    // check if we're excluding hidden files
                    if (args.ExcludeHidden)
                    {
                        Continue = !File.GetAttributes(file).HasFlag(FileAttributes.Hidden);
                    }
                    // check if we're excluding folders
                    if (args.ExcludeFolders && Directory.Exists(file))
                    {
                        Logger.Write_Verbose($@"Excluding: {file}");
                        Continue = false;
                    }
                    if (args.LastAccessTime != null && (File.GetLastAccessTime(file) < args.LastAccessTime.Value))
                    {
                        Continue = false;
                    }
                    if (args.LastWriteTime != null && (File.GetLastWriteTime(file) < args.LastWriteTime.Value))
                    {
                        Continue = false;
                    }
                    if (args.CreationTime != null && (File.GetCreationTime(file) < args.CreationTime.Value))
                    {
                        Continue = false;
                    }
                    if (args.CheckWriteAccess && !Test_Write(file))
                    {
                        Continue = false;
                    }
                    if (Continue)
                    {

                        String owner;
                        try
                        {
                             owner = File.GetAccessControl(file).GetOwner(typeof(SecurityIdentifier)).Translate(typeof(System.Security.Principal.NTAccount)).Value;
                        }
                        catch (UnauthorizedAccessException) {
                             owner = "Access was Denied"; 
                        }

                        DateTime lastAccessTime;
                        try
                        {
                            lastAccessTime = File.GetLastAccessTime(file);
                        }
                        catch { lastAccessTime = new DateTime(); }

                        DateTime lastWriteTime;
                        try
                        {
                            lastWriteTime = File.GetLastWriteTime(file);
                        } catch { lastWriteTime = new DateTime(); }

                        DateTime creationTime;
                        try
                        {
                            creationTime = File.GetCreationTime(file);
                        } catch { creationTime = new DateTime(); }

                        long length;
                        try
                        {
                            length =new FileInfo(file).Length; 
                        }catch { length = 0; }
                      

                        var FoundFile = new FoundFile
                        {
                            Path = file,
                            Owner = owner,
                            LastAccessTime = lastAccessTime,
                            LastWriteTime = lastWriteTime,
                            CreationTime = creationTime,
                            Length = length
                        };
                        FoundFiles.Add(FoundFile);
                    }
                }
            }

            // remove the IPC$ mappings
            foreach (var key in MappedComputers.Keys)
            {
                Remove_RemoteConnection(new Args_Remove_RemoteConnection { ComputerName = new[] { key } });
            }
            return FoundFiles;
        }

        // the host enumeration block we're using to enumerate all servers
        private static IEnumerable<FoundFile> _Find_InterestingDomainShareFile(string[] ComputerName, string[] Include, string[] ExcludedShares, bool OfficeDocs, bool ExcludeHidden, bool FreshEXEs, bool CheckWriteAccess, DateTime? LastAccessTime, DateTime? LastWriteTime, DateTime? CreationTime, IntPtr TokenHandle)
        {
            var LogonToken = IntPtr.Zero;
            if (TokenHandle != IntPtr.Zero)
            {
                // impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                {
                    TokenHandle = TokenHandle,
                    Quiet = true
                });
            }

            var FoundFiles = new List<FoundFile>();
            foreach (var TargetComputer in ComputerName)
            {
                var SearchShares = new List<string>();
                if (TargetComputer.StartsWith(@"\\"))
                {
                    // if a share is passed as the server
                    SearchShares.Add(TargetComputer);
                }
                else
                {
                    var Up = TestConnection.Ping(TargetComputer, 1);
                    if (Up)
                    {
                        // get the shares for this host and check what we find
                        var Shares = Get_NetShare(new Args_Get_NetShare
                        {
                            ComputerName = new[] { TargetComputer }
                        });

                        foreach (var Share in Shares)
                        {
                            var ShareName = Share.Name;
                            var Path = @"\\" + TargetComputer + @"\" + ShareName;

                            // make sure we get a real share name back
                            if ((!string.IsNullOrEmpty(ShareName)) && (ShareName.Trim() != ""))
                            {
                                // skip this share if it's in the exclude list
                                if (!ExcludedShares.ContainsNoCase(ShareName))
                                {
                                    // check if the user has access to this path
                                    try
                                    {
                                        Directory.GetFiles(Path);
                                        SearchShares.Add(Path);
                                    }
                                    catch
                                    {
                                        Logger.Write_Verbose($@"[!] No access to {Path}");
                                    }
                                }
                            }
                        }
                    }
                }

                foreach (var Share in SearchShares) {
                    Logger.Write_Verbose($@"Searching share: {Share}");
                    var SearchArgs = new Args_Find_InterestingFile
                    {
                        Path = new[] { Share },
                        Include = Include
                    };
                    if (OfficeDocs) {
                        SearchArgs.OfficeDocs = OfficeDocs;
                    }
                    if (FreshEXEs) {
                        SearchArgs.FreshEXEs = FreshEXEs;
                    }
                    if (LastAccessTime != null) {
                        SearchArgs.LastAccessTime = LastAccessTime;
                    }
                    if (LastWriteTime != null) {
                        SearchArgs.LastWriteTime = LastWriteTime;
                    }
                    if (CreationTime != null) {
                        SearchArgs.CreationTime = CreationTime;
                    }
                    if (CheckWriteAccess) {
                        SearchArgs.CheckWriteAccess = CheckWriteAccess;
                    }
                    FoundFiles.AddRange(Find_InterestingFile(SearchArgs));
                }
            }

            if (TokenHandle != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return FoundFiles;
        }

        public static IEnumerable<FoundFile> Find_InterestingDomainShareFile(Args_Find_InterestingDomainShareFile args = null)
        {
            if (args == null) args = new Args_Find_InterestingDomainShareFile();

            var ComputerSearcherArguments = new Args_Get_DomainComputer
            {
                Properties = new[] { "dnshostname" },
                Domain = args.ComputerDomain,
                LDAPFilter = args.ComputerLDAPFilter,
                SearchBase = args.ComputerSearchBase,
                OperatingSystem = args.OperatingSystem,
                ServicePack = args.ServicePack,
                SiteName = args.SiteName,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            string[] TargetComputers;
            if (args.ComputerName != null)
            {
                TargetComputers = args.ComputerName;
            }
            else
            {
                Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] Querying computers in the domain");
                TargetComputers = Get_DomainComputer(ComputerSearcherArguments).Select(x => (x as LDAPProperty).dnshostname).ToArray();
            }

            if (TargetComputers == null || TargetComputers.Length == 0)
            {
                throw new Exception("[Find-InterestingDomainShareFile] No hosts found to enumerate");
            }
            Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] TargetComputers length: {TargetComputers.Length}");

            var LogonToken = IntPtr.Zero;
            if (args.Credential != null)
            {
                if (args.Delay != 0 || args.StopOnSuccess)
                {
                    LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential
                    });
                }
                else
                {
                    LogonToken = Invoke_UserImpersonation(new Args_Invoke_UserImpersonation
                    {
                        Credential = args.Credential,
                        Quiet = true
                    });
                }
            }

            var rets = new List<FoundFile>();
            // only ignore threading if -Delay is passed
            if (args.Delay != 0 || args.StopOnSuccess)
            {
                Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] Total number of hosts: {TargetComputers.Count()}");
                Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] Delay: {args.Delay}, Jitter: {args.Jitter}");

                var Counter = 0;
                var RandNo = new System.Random();

                foreach (var TargetComputer in TargetComputers)
                {
                    Counter = Counter + 1;

                    // sleep for our semi-randomized interval
                    System.Threading.Thread.Sleep(RandNo.Next((int)((1 - args.Jitter) * args.Delay), (int)((1 + args.Jitter) * args.Delay)) * 1000);

                    Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] Enumerating server {TargetComputer} ({Counter} of {TargetComputers.Count()})");
                    var ret = _Find_InterestingDomainShareFile(new[] { TargetComputer }, args.Include, args.ExcludedShares, args.OfficeDocs, /*args.ExcludeHidden*/false, args.FreshEXEs, /*args.CheckWriteAccess*/ false, args.LastAccessTime, args.LastWriteTime, args.CreationTime, LogonToken);
                    if (ret != null)
                        rets.AddRange(ret);
                }
            }
            else
            {
                Logger.Write_Verbose($@"[Find-InterestingDomainShareFile] Using threading with threads: {args.Threads}");

                // if we're using threading, kick off the script block with New-ThreadedFunction
                // if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
                System.Threading.Tasks.Parallel.ForEach(
                            TargetComputers,
                            TargetComputer =>
                            {
                                var ret = _Find_InterestingDomainShareFile(new[] { TargetComputer }, args.Include, args.ExcludedShares, args.OfficeDocs, /*args.ExcludeHidden*/false, args.FreshEXEs, /*args.CheckWriteAccess*/ false, args.LastAccessTime, args.LastWriteTime, args.CreationTime, LogonToken);
                                lock (rets)
                                {
                                    if (ret != null)
                                        rets.AddRange(ret);
                                }
                            });
            }

            if (LogonToken != IntPtr.Zero)
            {
                Invoke_RevertToSelf(LogonToken);
            }
            return rets;
        }

        public static IEnumerable<PropertyOutlier> Find_DomainObjectPropertyOutlier(Args_Find_DomainObjectPropertyOutlier args = null)
        {
            if (args == null) args = new Args_Find_DomainObjectPropertyOutlier();

            var UserReferencePropertySet = new[] { "admincount", "accountexpires", "badpasswordtime", "badpwdcount", "cn", "codepage", "countrycode", "description", "displayname", "distinguishedname", "dscorepropagationdata", "givenname", "instancetype", "iscriticalsystemobject", "lastlogoff", "lastlogon", "lastlogontimestamp", "lockouttime", "logoncount", "memberof", "msds-supportedencryptiontypes", "name", "objectcategory", "objectclass", "objectguid", "objectsid", "primarygroupid", "pwdlastset", "samaccountname", "samaccounttype", "sn", "useraccountcontrol", "userprincipalname", "usnchanged", "usncreated", "whenchanged", "whencreated" };

            var GroupReferencePropertySet = new[] { "admincount", "cn", "description", "distinguishedname", "dscorepropagationdata", "grouptype", "instancetype", "iscriticalsystemobject", "member", "memberof", "name", "objectcategory", "objectclass", "objectguid", "objectsid", "samaccountname", "samaccounttype", "systemflags", "usnchanged", "usncreated", "whenchanged", "whencreated" };

            var ComputerReferencePropertySet = new[] { "accountexpires", "badpasswordtime", "badpwdcount", "cn", "codepage", "countrycode", "distinguishedname", "dnshostname", "dscorepropagationdata", "instancetype", "iscriticalsystemobject", "lastlogoff", "lastlogon", "lastlogontimestamp", "localpolicyflags", "logoncount", "msds-supportedencryptiontypes", "name", "objectcategory", "objectclass", "objectguid", "objectsid", "operatingsystem", "operatingsystemservicepack", "operatingsystemversion", "primarygroupid", "pwdlastset", "samaccountname", "samaccounttype", "serviceprincipalname", "useraccountcontrol", "usnchanged", "usncreated", "whenchanged", "whencreated" };

            var SearcherArgumentsForUser = new Args_Get_DomainUser
            {
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var SearcherArgumentsForGroup = new Args_Get_DomainGroup
            {
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };
            var SearcherArgumentsForComputer = new Args_Get_DomainComputer
            {
                Domain = args.Domain,
                LDAPFilter = args.LDAPFilter,
                SearchBase = args.SearchBase,
                Server = args.Server,
                SearchScope = args.SearchScope,
                ResultPageSize = args.ResultPageSize,
                ServerTimeLimit = args.ServerTimeLimit,
                Tombstone = args.Tombstone,
                Credential = args.Credential
            };

            // Domain / Credential
            var TargetForest = string.Empty;
            if (!args.Domain.IsNullOrEmpty())
            {
                if (args.Credential != null)
                {
                    TargetForest = Get_Domain(new Args_Get_Domain { Domain = args.Domain }).Forest.Name;
                }
                else
                {
                    TargetForest = Get_Domain(new Args_Get_Domain { Domain = args.Domain, Credential = args.Credential }).Forest.Name;
                }
                Logger.Write_Verbose($@"[Find-DomainObjectPropertyOutlier] Enumerated forest '{TargetForest}' for target domain '{args.Domain}'");
            }

            var SchemaArguments = new
            {
                Credential = args.Credential,
                Forest = TargetForest
            };

            string[] ReferenceObjectProperties = null;
            ClassType? ReferenceObjectClass = null;
            if (args.ReferencePropertySet != null)
            {
                Logger.Write_Verbose(@"[Find-DomainObjectPropertyOutlier] Using specified -ReferencePropertySet");
                ReferenceObjectProperties = args.ReferencePropertySet;
            }
            else if (args.ReferenceObject != null)
            {
                Logger.Write_Verbose(@"[Find-DomainObjectPropertyOutlier] Extracting property names from -ReferenceObject to use as the reference property set");
                ReferenceObjectProperties = args.ReferenceObject.GetType().GetProperties().Select(x => x.Name).ToArray();
                ReferenceObjectClass = args.ReferenceObject.GetPropValue<ClassType>("objectclass");
                Logger.Write_Verbose($@"[Find-DomainObjectPropertyOutlier] Calculated ReferenceObjectClass : {ReferenceObjectClass}");
            }
            else
            {
                Logger.Write_Verbose($@"[Find-DomainObjectPropertyOutlier] Using the default reference property set for the object class '{args.ClassName}'");
            }

            IEnumerable<object> Objects;
            if ((args.ClassName == ClassType.User) || (ReferenceObjectClass == ClassType.User))
            {
                Objects = Get_DomainUser(SearcherArgumentsForUser);
                if (ReferenceObjectProperties == null)
                {
                    ReferenceObjectProperties = UserReferencePropertySet;
                }
            }
            else if ((args.ClassName == ClassType.Group) || (ReferenceObjectClass == ClassType.Group))
            {
                Objects = Get_DomainGroup(SearcherArgumentsForGroup);
                if (ReferenceObjectProperties == null)
                {
                    ReferenceObjectProperties = GroupReferencePropertySet;
                }
            }
            else if ((args.ClassName == ClassType.Computer) || (ReferenceObjectClass == ClassType.Computer))
            {
                Objects = Get_DomainComputer(SearcherArgumentsForComputer);
                if (ReferenceObjectProperties == null)
                {
                    ReferenceObjectProperties = ComputerReferencePropertySet;
                }
            }
            else
            {
                throw new Exception($@"[Find-DomainObjectPropertyOutlier] Invalid class: {args.ClassName}");
            }

            var PropertyOutliers = new List<PropertyOutlier>();
            foreach (LDAPProperty Object in Objects)
            {
                var ObjectProperties = Object.GetType().GetProperties().Select(x => x.Name).ToArray();
                foreach (var ObjectProperty in ObjectProperties)
                {
                    var val = Object.GetPropValue<object>(ObjectProperty);
                    if (val is Dictionary<string, object>)
                    {
                        var dic = val as Dictionary<string, object>;
                        foreach (var ObjectProperty1 in dic.Keys)
                        {
                            if (!ReferenceObjectProperties.ContainsNoCase(ObjectProperty1))
                            {
                                var Out = new PropertyOutlier
                                {
                                    SamAccountName = Object.samaccountname,
                                    Property = ObjectProperty1,
                                    Value = dic[ObjectProperty1]
                                };
                                PropertyOutliers.Add(Out);
                            }
                        }
                    }
                    else if (val != null && !ReferenceObjectProperties.ContainsNoCase(ObjectProperty))
                    {
                        var Out = new PropertyOutlier
                        {
                            SamAccountName = Object.samaccountname,
                            Property = ObjectProperty,
                            Value = Object.GetPropValue<object>(ObjectProperty)
                        };
                        PropertyOutliers.Add(Out);
                    }
                }
            }

            return PropertyOutliers;
        }
    }
}
