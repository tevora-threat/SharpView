using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public static class NativeMethods
    {
        #region Netapi32

        [StructLayout(LayoutKind.Sequential)]
        public struct DS_DOMAIN_TRUSTS
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string NetbiosDomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsDomainName;
            public uint Flags;
            public uint ParentIndex;
            public uint TrustType;
            public uint TrustAttributes;
            public IntPtr DomainSid;
            public Guid DomainGuid;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            public string shi1_netname;
            public uint shi1_type;
            public string shi1_remark;
            public SHARE_INFO_1(string sharename, uint sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }
            public override string ToString()
            {
                return shi1_netname;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_USER_INFO_1
        {
            public string wkui1_username;
            public string wkui1_logon_domain;
            public string wkui1_oth_domains;
            public string wkui1_logon_server;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_INFO_1
        {
            public string lgrpi1_name;
            public string lgrpi1_comment;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_MEMBERS_INFO_2
        {
            public IntPtr lgrmi2_sid;
            public SID_NAME_USE lgrmi2_sidusage;
            public string lgrmi2_domainandname;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SESSION_INFO_10
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string sesi10_cname;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string sesi10_username;
            public uint sesi502_time;
            public uint sesi502_idle_time;
        }

        [Flags]
        public enum DS_DOMAIN_TRUST_TYPE : uint
        {
            DS_DOMAIN_IN_FOREST = 0x0001,  // Domain is a member of the forest
            DS_DOMAIN_DIRECT_OUTBOUND = 0x0002,  // Domain is directly trusted
            DS_DOMAIN_TREE_ROOT = 0x0004,  // Domain is root of a tree in the forest
            DS_DOMAIN_PRIMARY = 0x0008,  // Domain is the primary domain of queried server
            DS_DOMAIN_NATIVE_MODE = 0x0010,  // Primary domain is running in native mode
            DS_DOMAIN_DIRECT_INBOUND = 0x0020   // Domain is directly trusting
        }

        public enum SID_NAME_USE : UInt16
        {
            SidTypeUser             = 1,
            SidTypeGroup            = 2,
            SidTypeDomain           = 3,
            SidTypeAlias            = 4,
            SidTypeWellKnownGroup   = 5,
            SidTypeDeletedAccount   = 6,
            SidTypeInvalid          = 7,
            SidTypeUnknown          = 8,
            SidTypeComputer         = 9
        }

        public const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;

        [DllImport("Netapi32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern uint DsEnumerateDomainTrusts(string ServerName,
                                                        uint Flags,
                                                        out IntPtr Domains,
                                                        out uint DomainCount);

        [DllImport("Netapi32.dll", EntryPoint = "NetApiBufferFree")]
        public static extern uint NetApiBufferFree(IntPtr buffer);

        [DllImport("NetApi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern UInt32 DsGetSiteName([MarshalAs(UnmanagedType.LPTStr)]string ComputerName, out IntPtr SiteNameBuffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int NetShareEnum(
                                         string ServerName,
                                         int level,
                                         ref IntPtr bufPtr,
                                         uint prefmaxlen,
                                         ref int entriesread,
                                         ref int totalentries,
                                         ref int resume_handle
                                         );

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetWkstaUserEnum(
                                       string servername,
                                       int level,
                                       out IntPtr bufptr,
                                       int prefmaxlen,
                                       out int entriesread,
                                       out int totalentries,
                                       ref int resume_handle);

        [DllImport("Netapi32.dll")]
        public static extern int NetLocalGroupEnum([MarshalAs(UnmanagedType.LPWStr)]
                                        string servername,
                                        int level,
                                        out IntPtr bufptr,
                                        uint prefmaxlen,
                                        out int entriesread,
                                        out int totalentries,
                                        ref int resume_handle);

        [DllImport("NetAPI32.dll", CharSet = CharSet.Unicode)]
        public extern static int NetLocalGroupGetMembers(
                                    [MarshalAs(UnmanagedType.LPWStr)] string servername,
                                    [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
                                    int level,
                                    out IntPtr bufptr,
                                    int prefmaxlen,
                                    out int entriesread,
                                    out int totalentries,
                                    IntPtr resume_handle);

        [DllImport("netapi32.dll", SetLastError = true)]
        public static extern int NetSessionEnum(
                                [In, MarshalAs(UnmanagedType.LPWStr)] string ServerName,
                                [In, MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
                                [In, MarshalAs(UnmanagedType.LPWStr)] string UserName,
                                Int32 Level,
                                out IntPtr bufptr,
                                int prefmaxlen,
                                ref Int32 entriesread,
                                ref Int32 totalentries,
                                ref Int32 resume_handle);

        #endregion

        #region Advapi32

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid([MarshalAs(UnmanagedType.LPArray)] byte[] pSID,
                                                out IntPtr ptrSid);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        [DllImport("advapi32.dll", SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LogonUser(
              [MarshalAs(UnmanagedType.LPStr)] string pszUserName,
              [MarshalAs(UnmanagedType.LPStr)] string pszDomain,
              [MarshalAs(UnmanagedType.LPStr)] string pszPassword,
              LogonType dwLogonType,
              LogonProvider dwLogonProvider,
              ref IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("advapi32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManagerW(
             string machineName,
             string databaseName,
             uint dwAccess
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        #endregion

        #region Kernel32

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hHandle);

        #endregion

        #region Mpr

        [StructLayout(LayoutKind.Sequential)]
        public class NetResource
        {
            public ResourceScope Scope;
            public ResourceType ResourceType;
            public ResourceDisplaytype DisplayType;
            public int Usage;
            public string LocalName;
            public string RemoteName;
            public string Comment;
            public string Provider;
        }

        public enum ResourceScope : int
        {
            Connected = 1,
            GlobalNetwork,
            Remembered,
            Recent,
            Context
        };

        public enum ResourceType : int
        {
            Any = 0,
            Disk = 1,
            Print = 2,
            Reserved = 8,
        }

        public enum ResourceDisplaytype : int
        {
            Generic = 0x0,
            Domain = 0x01,
            Server = 0x02,
            Share = 0x03,
            File = 0x04,
            Group = 0x05,
            Network = 0x06,
            Root = 0x07,
            Shareadmin = 0x08,
            Directory = 0x09,
            Tree = 0x0a,
            Ndscontainer = 0x0b
        }

        [DllImport("mpr.dll")]
        public static extern int WNetAddConnection2(NetResource netResource,
            string password, string username, int flags);

        [DllImport("mpr.dll")]
        public static extern int WNetCancelConnection2(string name, int flags,
            bool force);

        #endregion

        #region Wtsapi32

        public enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        public enum WTS_INFO_CLASS
        {
            WTSInitialProgram = 0,
            WTSApplicationName = 1,
            WTSWorkingDirectory = 2,
            WTSOEMId = 3,
            WTSSessionId = 4,
            WTSUserName = 5,
            WTSWinStationName = 6,
            WTSDomainName = 7,
            WTSConnectState = 8,
            WTSClientBuildNumber = 9,
            WTSClientName = 10,
            WTSClientDirectory = 11,
            WTSClientProductId = 12,
            WTSClientHardwareId = 13,
            WTSClientAddress = 14,
            WTSClientDisplay = 15,
            WTSClientProtocolType = 16,
            WTSIdleTime = 17,
            WTSLogonTime = 18,
            WTSIncomingBytes = 19,
            WTSOutgoingBytes = 20,
            WTSIncomingFrames = 21,
            WTSOutgoingFrames = 22,
            WTSClientInfo = 23,
            WTSSessionInfo = 24,
            WTSSessionInfoEx = 25,
            WTSConfigInfo = 26,
            WTSValidationInfo = 27,
            WTSSessionAddressV4 = 28,
            WTSIsRemoteSession = 29
        }

        public enum WTS_TYPE_CLASS
        {
            WTSTypeProcessInfoLevel0,
            WTSTypeProcessInfoLevel1,
            WTSTypeSessionInfoLevel1
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_SESSION_INFO_1
        {
            public Int32 ExecEnvId;
            public WTS_CONNECTSTATE_CLASS State;
            public Int32 SessionId;
            [MarshalAs(UnmanagedType.LPStr)]
            public String pSessionName;
            [MarshalAs(UnmanagedType.LPStr)]
            public String pHostName;
            [MarshalAs(UnmanagedType.LPStr)]
            public String pUserName;
            [MarshalAs(UnmanagedType.LPStr)]
            public String pDomainName;
            [MarshalAs(UnmanagedType.LPStr)]
            public String pFarmName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_CLIENT_ADDRESS
        {
            public uint AddressFamily;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public byte[] Address;
        }

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern IntPtr WTSOpenServerEx(string pServerName);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSCloseServer(IntPtr hServer);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern int WTSEnumerateSessionsEx(
                System.IntPtr hServer,
                ref UInt32 pLevel,
                int Filter,
                ref System.IntPtr ppSessionInfo,
                ref UInt32 pCount);

        [DllImport("Wtsapi32.dll")]
        public static extern bool WTSQuerySessionInformation(
            System.IntPtr hServer,
            int sessionId,
            WTS_INFO_CLASS wtsInfoClass,
            out System.IntPtr ppBuffer,
            out uint pBytesReturned);

        [DllImport("wtsapi32.dll", ExactSpelling = true, SetLastError = false)]
        public static extern void WTSFreeMemory(IntPtr memory);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemoryEx(
            WTS_TYPE_CLASS WTSTypeClass,
            IntPtr pMemory,
            UInt32 NumberOfEntries
        );

        #endregion
    }
}
