using SharpView.Enums;
using SharpView.Returns;
using SharpView.Utils;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SharpView
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Logger.Write_Output("Ex: SharpView.exe Method-Name -Switch -String domain -Array domain,user -Enum ResetPassword -IntEnum CREATED_BY_SYSTEM,APP_BASIC -PointEnum ResetPassword,All -Credential admin@domain.local/password");
                Logger.Write_Output("Execute 'Sharpview.exe <Method-Name> -Help' to get arguments list and expected types");
                return;
            }
            try
            {
                Run(args);
            }
            catch (Exception e)
            {
                Console.WriteLine("An error occurred: '{0}'", e);
            }
        }

        static void Run(string[] args)
        {
            var methodName = args[0];
            switch (methodName.ToLower())
            {
                case "get-domaingpouserlocalgroupmapping":
                    methodName = "Get_DomainGPOUserLocalGroupMapping";
                    break;
                case "find-gpolocation":
                    methodName = "Find_GPOLocation";
                    break;
                case "get-domaingpocomputerlocalgroupmapping":
                    methodName = "Get_DomainGPOComputerLocalGroupMapping";
                    break;
                case "find-gpocomputeradmin":
                    methodName = "Find_GPOComputerAdmin";
                    break;
                case "get-domainobjectacl":
                    methodName = "Get_DomainObjectAcl";
                    break;
                case "get-objectacl":
                    methodName = "Get_ObjectAcl";
                    break;
                case "add-domainobjectacl":
                    methodName = "Add_DomainObjectAcl";
                    break;
                case "add-objectacl":
                    methodName = "Add_ObjectAcl";
                    break;
                case "remove-domainobjectacl":
                    methodName = "Remove_DomainObjectAcl";
                    break;
                case "get-regloggedon":
                    methodName = "Get_RegLoggedOn";
                    break;
                case "get-loggedonlocal":
                    methodName = "Get_LoggedOnLocal";
                    break;
                case "get-netrdpsession":
                    methodName = "Get_NetRDPSession";
                    break;
                case "test-adminaccess":
                    methodName = "Test_AdminAccess";
                    break;
                case "invoke-checklocaladminaccess":
                    methodName = "Invoke_CheckLocalAdminAccess";
                    break;
                case "get-wmiprocess":
                    methodName = "Get_WMIProcess";
                    break;
                case "get-netprocess":
                    methodName = "Get_NetProcess";
                    break;
                case "get-wmiregproxy":
                    methodName = "Get_WMIRegProxy";
                    break;
                case "get-proxy":
                    methodName = "Get_Proxy";
                    break;
                case "get-wmireglastloggedon":
                    methodName = "Get_WMIRegLastLoggedOn";
                    break;
                case "get-lastloggedon":
                    methodName = "Get_LastLoggedOn";
                    break;
                case "get-wmiregcachedrdpconnection":
                    methodName = "Get_WMIRegCachedRDPConnection";
                    break;
                case "get-cachedrdpconnection":
                    methodName = "Get_CachedRDPConnection";
                    break;
                case "get-wmiregmounteddrive":
                    methodName = "Get_WMIRegMountedDrive";
                    break;
                case "get-registrymounteddrive":
                    methodName = "Get_RegistryMountedDrive";
                    break;
                case "find-interestingdomainacl":
                    methodName = "Find_InterestingDomainAcl";
                    break;
                case "invoke-aclscanner":
                    methodName = "Invoke_ACLScanner";
                    break;
                case "get-netshare":
                    methodName = "Get_NetShare";
                    break;
                case "get-netloggedon":
                    methodName = "Get_NetLoggedon";
                    break;
                case "get-netlocalgroup":
                    methodName = "Get_NetLocalGroup";
                    break;
                case "get-netlocalgroupmember":
                    methodName = "Get_NetLocalGroupMember";
                    break;
                case "get-netsession":
                    methodName = "Get_NetSession";
                    break;
                case "get-pathacl":
                    methodName = "Get_PathAcl";
                    break;
                case "convertfrom-uacvalue":
                    methodName = "ConvertFrom_UACValue";
                    break;
                case "get-principalcontext":
                    methodName = "Get_PrincipalContext";
                    break;
                case "new-domaingroup":
                    methodName = "New_DomainGroup";
                    break;
                case "new-domainuser":
                    methodName = "New_DomainUser";
                    break;
                case "add-domaingroupmember":
                    methodName = "Add_DomainGroupMember";
                    break;
                case "set-domainuserpassword":
                    methodName = "Set_DomainUserPassword";
                    break;
                case "invoke-kerberoast":
                    methodName = "Invoke_Kerberoast";
                    break;
                case "export-powerviewcsv":
                    methodName = "Export_PowerViewCSV";
                    break;
                case "find-localadminaccess":
                    methodName = "Find_LocalAdminAccess";
                    break;
                case "find-domainlocalgroupmember":
                    methodName = "Find_DomainLocalGroupMember";
                    break;
                case "find-domainshare":
                    methodName = "Find_DomainShare";
                    break;
                case "find-domainuserevent":
                    methodName = "Find_DomainUserEvent";
                    break;
                case "find-domainprocess":
                    methodName = "Find_DomainProcess";
                    break;
                case "find-domainuserlocation":
                    methodName = "Find_DomainUserLocation";
                    break;
                case "find-interestingfile":
                    methodName = "Find_InterestingFile";
                    break;
                case "find-interestingdomainsharefile":
                    methodName = "Find_InterestingDomainShareFile";
                    break;
                case "find-domainobjectpropertyoutlier":
                    methodName = "Find_DomainObjectPropertyOutlier";
                    break;
                case "testmethod":
                    methodName = "TestMethod";
                    break;
                case "get-domain":
                    methodName = "Get_Domain";
                    break;
                case "get-netdomain":
                    methodName = "Get_NetDomain";
                    break;
                case "get-domaincomputer":
                    methodName = "Get_DomainComputer";
                    break;
                case "get-netcomputer":
                    methodName = "Get_NetComputer";
                    break;
                case "get-domaincontroller":
                    methodName = "Get_DomainController";
                    break;
                case "get-netdomaincontroller":
                    methodName = "Get_NetDomainController";
                    break;
                case "get-domainfileserver":
                    methodName = "Get_DomainFileServer";
                    break;
                case "get-netfileserver":
                    methodName = "Get_NetFileServer";
                    break;
                case "convert-adname":
                    methodName = "Convert_ADName";
                    break;
                case "get-domainobject":
                    methodName = "Get_DomainObject";
                    break;
                case "get-adobject":
                    methodName = "Get_ADObject";
                    break;
                case "get-domainuser":
                    methodName = "Get_DomainUser";
                    break;
                case "get-netuser":
                    methodName = "Get_NetUser";
                    break;
                case "get-domaingroup":
                    methodName = "Get_DomainGroup";
                    break;
                case "get-netgroup":
                    methodName = "Get_NetGroup";
                    break;
                case "get-domaindfsshare":
                    methodName = "Get_DomainDFSShare";
                    break;
                case "get-dfsshare":
                    methodName = "Get_DFSshare";
                    break;
                case "get-domaindnsrecord":
                    methodName = "Get_DomainDNSRecord";
                    break;
                case "get-dnsrecord":
                    methodName = "Get_DNSRecord";
                    break;
                case "get-domaindnszone":
                    methodName = "Get_DomainDNSZone";
                    break;
                case "get-dnszone":
                    methodName = "Get_DNSZone";
                    break;
                case "get-domainforeigngroupmember":
                    methodName = "Get_DomainForeignGroupMember";
                    break;
                case "find-foreigngroup":
                    methodName = "Find_ForeignGroup";
                    break;
                case "get-domainforeignuser":
                    methodName = "Get_DomainForeignUser";
                    break;
                case "find-foreignuser":
                    methodName = "Find_ForeignUser";
                    break;
                case "convertfrom-sid":
                    methodName = "ConvertFrom_SID";
                    break;
                case "convert-sidtoname":
                    methodName = "Convert_SidToName";
                    break;
                case "get-domaingroupmember":
                    methodName = "Get_DomainGroupMember";
                    break;
                case "get-netgroupmember":
                    methodName = "Get_NetGroupMember";
                    break;
                case "get-domainmanagedsecuritygroup":
                    methodName = "Get_DomainManagedSecurityGroup";
                    break;
                case "find-managedsecuritygroups":
                    methodName = "Find_ManagedSecurityGroups";
                    break;
                case "get-domainou":
                    methodName = "Get_DomainOU";
                    break;
                case "get-netou":
                    methodName = "Get_NetOU";
                    break;
                case "get-domainsid":
                    methodName = "Get_DomainSID";
                    break;
                case "get-forest":
                    methodName = "Get_Forest";
                    break;
                case "get-netforest":
                    methodName = "Get_NetForest";
                    break;
                case "get-foresttrust":
                    methodName = "Get_ForestTrust";
                    break;
                case "get-netforesttrust":
                    methodName = "Get_NetForestTrust";
                    break;
                case "get-domaintrust":
                    methodName = "Get_DomainTrust";
                    break;
                case "get-netdomaintrust":
                    methodName = "Get_NetDomainTrust";
                    break;
                case "get-forestdomain":
                    methodName = "Get_ForestDomain";
                    break;
                case "get-netforestdomain":
                    methodName = "Get_NetForestDomain";
                    break;
                case "get-domainsite":
                    methodName = "Get_DomainSite";
                    break;
                case "get-netsite":
                    methodName = "Get_NetSite";
                    break;
                case "get-domainsubnet":
                    methodName = "Get_DomainSubnet";
                    break;
                case "get-netsubnet":
                    methodName = "Get_NetSubnet";
                    break;
                case "get-domaintrustmapping":
                    methodName = "Get_DomainTrustMapping";
                    break;
                case "invoke-mapdomaintrust":
                    methodName = "Invoke_MapDomainTrust";
                    break;
                case "get-forestglobalcatalog":
                    methodName = "Get_ForestGlobalCatalog";
                    break;
                case "get-netforestcatalog":
                    methodName = "Get_NetForestCatalog";
                    break;
                case "get-domainuserevent":
                    methodName = "Get_DomainUserEvent";
                    break;
                case "get-userevent":
                    methodName = "Get_UserEvent";
                    break;
                case "get-domainguidmap":
                    methodName = "Get_DomainGUIDMap";
                    break;
                case "get-guidmap":
                    methodName = "Get_GUIDMap";
                    break;
                case "resolve-ipaddress":
                    methodName = "Resolve_IPAddress";
                    break;
                case "get-ipaddress":
                    methodName = "Get_IPAddress";
                    break;
                case "convertto-sid":
                    methodName = "ConvertTo_SID";
                    break;
                case "invoke-userimpersonation":
                    methodName = "Invoke_UserImpersonation";
                    break;
                case "invoke-reverttoself":
                    methodName = "Invoke_RevertToSelf";
                    break;
                case "get-domainspnticket":
                    methodName = "Get_DomainSPNTicket";
                    break;
                case "request-spnticket":
                    methodName = "Request_SPNTicket";
                    break;
                case "get-netcomputersitename":
                    methodName = "Get_NetComputerSiteName";
                    break;
                case "get-sitename":
                    methodName = "Get_SiteName";
                    break;
                case "get-domaingpo":
                    methodName = "Get_DomainGPO";
                    break;
                case "get-netgpo":
                    methodName = "Get_NetGPO";
                    break;
                case "set-domainobject":
                    methodName = "Set_DomainObject";
                    break;
                case "set-adobject":
                    methodName = "Set_ADObject";
                    break;
                case "add-remoteconnection":
                    methodName = "Add_RemoteConnection";
                    break;
                case "remove-remoteconnection":
                    methodName = "Remove_RemoteConnection";
                    break;
                case "get-inicontent":
                    methodName = "Get_IniContent";
                    break;
                case "get-gpttmpl":
                    methodName = "Get_GptTmpl";
                    break;
                case "get-groupsxml":
                    methodName = "Get_GroupsXML";
                    break;
                case "get-domainpolicydata":
                    methodName = "Get_DomainPolicyData";
                    break;
                case "get-domainpolicy":
                    methodName = "Get_DomainPolicy";
                    break;
                case "get-domaingpolocalgroup":
                    methodName = "Get_DomainGPOLocalGroup";
                    break;
                case "get-netgpogroup":
                    methodName = "Get_NetGPOGroup";
                    break;
                default:
                    Console.WriteLine("No Valid Method entered");
                    Environment.Exit(0);
                    break;
            }

            var method = typeof(PowerView).GetMethod(methodName);
            if (method == null)
            {
                Logger.Write_Warning($@"There is no method does match with '{methodName}'");
                return;
            }
            if(args[1].ToLower() == "-help" || args[1].ToLower() == "help")
            {
                Logger.Write_Output(Environment.NewLine + GetMethodHelp(method));
                Environment.Exit(0);
            }
            ParameterInfo[] parameters = method.GetParameters();
            if (parameters == null || parameters.Length != 1)
            {
                Logger.Write_Warning("The method has no parameter");
                return;
            }
            Type paramType = Type.GetType(parameters[0].ParameterType.FullName);
            if (paramType == null)
            {
                Logger.Write_Warning($@"There is no type for '{parameters[0].ParameterType.FullName}'");
                return;
            }
            object argObject = Activator.CreateInstance(paramType, false);
            if (argObject != null)
            {
                for (int i = 1; i < args.Length; i++)
                {
                    var argName = args[i];
                    if (argName.StartsWith("-"))
                    {
                        argName = argName.TrimStart(new[] { '-' });
                        PropertyInfo pinfo = paramType.GetProperty(argName);
                        if (pinfo == null)
                            continue;
                        i++;
                        try
                        {
                            var strValue = "";
                            if (i < args.Length)
                                strValue = args[i];
                            else
                            {
                                if (pinfo.PropertyType.FullName == "System.Boolean")
                                    strValue = "true";
                            }
                            TypeConverter tc = TypeDescriptor.GetConverter(pinfo.PropertyType);
                            if (tc is BooleanConverter)
                            {
                                if (strValue.StartsWith("-"))
                                {
                                    i--;
                                    strValue = "true";
                                }
                            }
                            else if (tc is ArrayConverter)
                                tc = new StringArrayConverter();
                            else if (pinfo.PropertyType.FullName == "System.Net.NetworkCredential")
                                tc = new NetworkCredentialConverter();
                            var argValue = tc.ConvertFromString(strValue);
                            pinfo.SetValue(argObject, argValue);
                        }
                        catch (Exception ex)
                        {
                            Logger.Write_Warning($@"Parsing Error {argName}: {ex.Message}");
                        }
                    }
                }
            }
            // Leaving out try catch block to see errors for now
            var ret = method.Invoke(null, new[] { argObject });
            ObjectDumper.Write(ret);
        }

        static string GetMethodHelp(MethodInfo method)
        {
            var helpArgs = "";
            var args = method.GetParameters();
            foreach (var arg in args)
            {
                helpArgs += GetClassHelpAsParameter(arg);
            }
            return $@"{method.Name} {helpArgs}";
        }

        static string GetClassHelpAsParameter(ParameterInfo parameter)
        {
            var type = Type.GetType(parameter.ParameterType.FullName);
            var info = type.GetTypeInfo();

            IEnumerable<PropertyInfo> pList = info.DeclaredProperties;

            StringBuilder sb = new StringBuilder();

            foreach (PropertyInfo p in pList)
            {
                sb.Append($@"-{p.Name} <{p.PropertyType.Name}> ");
            }
            return sb.ToString();
        }
    }
}
