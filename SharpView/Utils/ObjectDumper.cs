using System;
using System.Collections;
using System.IO;
using System.Reflection;

namespace SharpView.Utils
{
    public class ObjectDumper
    {
        TextWriter writer;
        int pos;
        int level;
        int depth;

        /*public static string ToDetails(this object obj)
        {
            var details = obj.ToString();
            foreach (PropertyDescriptor descriptor in TypeDescriptor.GetProperties(obj))
            {
                string name = descriptor.Name;
                object value = descriptor.GetValue(obj);
                details += $@"{Environment.NewLine}{name} : {value}";
            }
            return details;
        }*/

        public static void Write(object o)
        {
            Write(o, 0);
        }

        public static void Write(object o, int depth)
        {
            ObjectDumper dumper = new ObjectDumper(depth);
            dumper.WriteObject(null, o);
        }

        private ObjectDumper(int depth)
        {
            this.writer = Console.Out;
            this.depth = depth;
        }

        private void Write(string s)
        {
            if (s != null)
            {
                writer.Write(s);
                pos += s.Length;
            }
        }

        private void WriteIndent()
        {
            //for (int i = 0; i < level; i++) writer.Write("  ");
        }

        private void WriteLine()
        {
            writer.WriteLine();
            pos = 0;
        }

        private void WriteTab()
        {
            Write("  ");
            while (pos % 8 != 0) Write(" ");
        }

        private void WriteObject(string prefix, object o)
        {
            if (o == null || o is ValueType || o is string)
            {
                if (o != null)
                {
                    WriteIndent();
                    Write(prefix);
                    WriteValue(o);
                    WriteLine();
                }
                return;
            }
            else if (o is IEnumerable)
            {
                foreach (object element in (IEnumerable)o)
                {
                    if (element is IEnumerable && !(element is string))
                    {
                        WriteIndent();
                        Write(prefix);
                        Write("...");
                        WriteLine();
                        if (level < depth)
                        {
                            level++;
                            WriteObject(prefix, element);
                            level--;
                        }
                    }
                    else
                    {
                        WriteObject(prefix, element);
                    }
                }
            }
            else
            {
                MemberInfo[] members = o.GetType().GetMembers(BindingFlags.Public | BindingFlags.Instance);
                WriteIndent();
                Write(prefix);
                bool propWritten = false;
                foreach (MemberInfo m in members)
                {
                    FieldInfo f = m as FieldInfo;
                    PropertyInfo p = m as PropertyInfo;
                    if (f != null || p != null)
                    {
                        if (propWritten)
                        {
                            WriteTab();
                        }
                        else
                        {
                            //propWritten = true;
                            propWritten = false;
                        }
                        Type t = f != null ? f.FieldType : p.PropertyType;
                        if (t.IsValueType || t == typeof(string) || t == typeof(object))
                        {
                            var val = f != null ? f.GetValue(o) : p.GetValue(o, null);
                            if (val != null)
                            {
                                if (!(val is Guid) || !((Guid)val).Equals(Guid.Empty))
                                {
                                    Write(m.Name.ShortenString(30));
                                    Write(" : ");
                                    WriteValue(val);
                                    WriteLine();
                                }
                            }
                        }
                        else
                        {
                            var val = f != null ? f.GetValue(o) : p.GetValue(o, null);
                            if (val != null)
                            {
                                if (typeof(IEnumerable).IsAssignableFrom(t))
                                {
                                    if (val is System.Collections.Generic.Dictionary<string, object>)
                                    {
                                        foreach (var item in (val as System.Collections.Generic.Dictionary<string, object>))
                                        {
                                            Write(item.Key.ShortenString(30));
                                            Write(" : ");
                                            //Write("...");
                                            WriteValue(item.Value);
                                            WriteLine();
                                        }
                                    }
                                    else
                                    {
                                        Write(m.Name.ShortenString(30));
                                        Write(" : ");
                                        //Write("...");
                                        WriteValue(val);
                                        WriteLine();
                                    }
                                }
                                else
                                {
                                    if (m.Name.Equals("Ace", StringComparison.OrdinalIgnoreCase))
                                    {
                                        level++;
                                        WriteObject(prefix, val);
                                        level--;
                                    }
                                    else
                                    {
                                        Write(m.Name.ShortenString(30));
                                        Write(" : ");
                                        //Write("{ }");
                                        WriteValue(val.ToString());
                                        WriteLine();
                                    }
                                }
                            }
                        }
                    }
                }
                if (propWritten) WriteLine();
                if (level < depth)
                {
                    foreach (MemberInfo m in members)
                    {
                        FieldInfo f = m as FieldInfo;
                        PropertyInfo p = m as PropertyInfo;
                        if (f != null || p != null)
                        {
                            Type t = f != null ? f.FieldType : p.PropertyType;
                            if (!(t.IsValueType || t == typeof(string)))
                            {
                                object value = f != null ? f.GetValue(o) : p.GetValue(o, null);
                                if (value != null)
                                {
                                    level++;
                                    WriteObject(/*m.Name + ": "*/prefix, value);
                                    level--;
                                }
                            }
                        }
                    }
                }
            }

            if (level == 0)
                WriteLine();
        }

        private void WriteValue(object o)
        {
            if (o == null)
            {
                Write("null");
            }
            else if (o is DateTime)
            {
                Write(((DateTime)o).ToString());
            }
            else if (o is ValueType || o is string)
            {
                Write(o.ToString());
            }
            else if (o is IEnumerable)
            {
                var enumObj = o as IEnumerable;
                Write("{");
                bool first = true;
                foreach (var item in enumObj)
                {
                    if (!first)
                        Write(", ");
                    Write(item.ToString());
                    first = false;
                }
                Write("}");
                //Write("...");
            }
            else
            {
                Write("{ }");
            }
        }
    }
}
