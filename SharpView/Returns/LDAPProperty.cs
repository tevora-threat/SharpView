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
    public class LDAPProperty
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

        public int? gpoptions { get; set; }

        public string displayname { get; set; }

        public string path { get; set; }

        public string siteobjectbl { get; set; }

        public Dictionary<string, object> others { get; set; } = new Dictionary<string, object>();

        public LDAPProperty()
        {

        }

        public LDAPProperty(LDAPProperty property)
        {
            adspath = property.adspath;
            objectsid = property.objectsid;
            sidhistory = property.sidhistory;
            grouptype = property.grouptype;
            samaccounttype = property.samaccounttype;
            objectguid = property.objectguid;
            useraccountcontrol = property.useraccountcontrol;
            Owner = property.Owner;
            Group = property.Group;
            DiscretionaryAcl = property.DiscretionaryAcl;
            SystemAcl = property.SystemAcl;
            accountexpires = property.accountexpires; // DateTime or string ("NEVER")
            lastlogon = property.lastlogon;
            lastlogontimestamp = property.lastlogontimestamp;
            pwdlastset = property.pwdlastset;
            lastlogoff = property.lastlogoff;
            badPasswordTime = property.badPasswordTime;
            name = property.name;
            distinguishedname = property.distinguishedname;
            dnsrecord = property.dnsrecord;
            whencreated = property.whencreated;
            whenchanged = property.whenchanged;
            samaccountname = property.samaccountname;
            member = property.member;
            memberof = property.memberof;
            cn = property.cn;
            objectclass = property.objectclass;
            managedby = property.managedby;
            siteobject = property.siteobject;
            ServicePrincipalName = property.ServicePrincipalName;
            dnshostname = property.dnshostname;
            gplink = property.gplink;
            gpoptions = property.gpoptions;
            displayname = property.displayname;
            path = property.path;
            others = property.others;
        }
    }
}
