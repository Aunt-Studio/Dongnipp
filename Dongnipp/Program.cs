using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
// This is just a TESTING file!!!
namespace Dongnipp
{
    internal class Program
    {
        public static async Task Main()
        {
            string token = "556148c2de0841ee90313c177c3b120a___1";
            (string schoolId, string schoolName) = await dongniSDK.getSchoolInfo(token);

            Console.WriteLine("SchoolId: " + schoolId);
            Console.WriteLine("SchoolName: " + schoolName);

            await Task.Delay(10000);
        }
    }
}
