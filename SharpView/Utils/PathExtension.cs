using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public static class PathExtension
    {
        public static bool EndsWith(this IEnumerable<string> patterns, string obj, StringComparison comparisionType)
        {
            return patterns.Any(x => obj.IsLikeMatch(x));
        }

        public static IEnumerable<string> GetDirectoryFiles(string rootPath, string[] patternMatchs, SearchOption searchOption)
        {
            var foundFiles = Enumerable.Empty<string>();

            if (searchOption == SearchOption.AllDirectories)
            {
                try
                {
                    IEnumerable<string> subDirs = Directory.EnumerateDirectories(rootPath);
                    foreach (string dir in subDirs)
                    {
                        System.Console.WriteLine("Searching Directory: " + dir);
                        foundFiles = foundFiles.Concat(GetDirectoryFiles(dir, patternMatchs, searchOption)); // Add files in subdirectories recursively to the list
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (PathTooLongException) { }
            }

            try
            {
                foundFiles = foundFiles.Concat(Directory.EnumerateFiles(rootPath, "*.*").Where(x => patternMatchs.EndsWith(x, StringComparison.OrdinalIgnoreCase))); // Add files from the current directory
            }
            catch (UnauthorizedAccessException) { }

            return foundFiles;
        }
    }
}
