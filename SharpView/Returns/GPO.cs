using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Returns
{
    public class GPO : LDAPProperty
    {
        public string gpcfilesyspath { get; set; }

        public GPO()
        {

        }

        public GPO(LDAPProperty property)
            :base(property)
        {
        }
    }
}
