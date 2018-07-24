using SharpView.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class DNSZone
    {
        public string adspath { get; set; }

        public string[] objectsid { get; set; }

        public string[] sidhistory { get; set; }

        public GroupType? grouptype { get; set; }

        public SamAccountType? samaccounttype { get; set; }

        public string objectguid { get; set; }

        public Enums.UACEnumValue? useraccountcontrol { get; set; }

        public SecurityIdentifier Owner { get; set; }

        public SecurityIdentifier Group { get; set; }

        public RawAcl DiscretionaryAcl { get; set; }

        public RawAcl SystemAcl { get; set; }

        public object accountexpires { get; set; } // DateTime or string ("NEVER")

        public DateTime? lastlogon { get; set; }

        public DateTime? lastlogontimestamp { get; set; }

        public DateTime? pwdlastset { get; set; }

        public DateTime? lastlogoff { get; set; }

        public DateTime? badPasswordTime { get; set; }

        public string name { get; set; }

        public string distinguishedname { get; set; }

        public object dnsrecord { get; set; }

        public DateTime? whencreated { get; set; }

        public DateTime? whenchanged { get; set; }

        public string ZoneName { get; set; }

        public string samaccountname { get; set; }

        public string[] member { get; set; }

        public string[] memberof { get; set; }

        public string[] cn { get; set; }

        public string[] objectclass { get; set; }

        public string managedby { get; set; }

        public string siteobject { get; set; }

        public string ServicePrincipalName { get; set; }

        public string dnshostname { get; set; }

        public string gplink { get; set; }

        public Dictionary<string, object> others { get; set; } = new Dictionary<string, object>();

        public DNSZone(LDAPProperty ldapProperty)
        {
            if (ldapProperty == null) return;

            adspath = ldapProperty.adspath;
            objectsid = ldapProperty.objectsid;
            sidhistory = ldapProperty.sidhistory;
            grouptype = ldapProperty.grouptype;
            samaccounttype = ldapProperty.samaccounttype;
            objectguid = ldapProperty.objectguid;
            useraccountcontrol = ldapProperty.useraccountcontrol;
            Owner = ldapProperty.Owner;
            Group = ldapProperty.Group;
            DiscretionaryAcl = ldapProperty.DiscretionaryAcl;
            SystemAcl = ldapProperty.SystemAcl;
            accountexpires = ldapProperty.accountexpires;
            lastlogon = ldapProperty.lastlogon;
            lastlogontimestamp = ldapProperty.lastlogontimestamp;
            pwdlastset = ldapProperty.pwdlastset;
            lastlogoff = ldapProperty.lastlogoff;
            badPasswordTime = ldapProperty.badPasswordTime;
            name = ldapProperty.name;
            distinguishedname = ldapProperty.distinguishedname;
            dnsrecord = ldapProperty.dnsrecord;
            whencreated = ldapProperty.whencreated;
            whenchanged = ldapProperty.whenchanged;
            samaccountname = ldapProperty.samaccountname;
            member = ldapProperty.member;
            memberof = ldapProperty.memberof;
            cn = ldapProperty.cn;
            objectclass = ldapProperty.objectclass;
            ZoneName = ldapProperty.name;
            managedby = ldapProperty.managedby;
            siteobject = ldapProperty.siteobject;
            ServicePrincipalName = ldapProperty.siteobject;
            dnshostname = ldapProperty.dnshostname;
            gplink = ldapProperty.gplink;
            others = ldapProperty.others;
        }
    }
}
