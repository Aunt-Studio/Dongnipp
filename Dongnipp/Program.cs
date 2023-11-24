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
            Console.WriteLine("\r\n  _____                          _             \r\n |  __ \\                        (_)  _     _   \r\n | |  | | ___  _ __   __ _ _ __  _ _| |_ _| |_ \r\n | |  | |/ _ \\| '_ \\ / _` | '_ \\| |_   _|_   _|\r\n | |__| | (_) | | | | (_| | | | | | |_|   |_|  \r\n |_____/ \\___/|_| |_|\\__, |_| |_|_|            \r\n                      __/ |                    \r\n                     |___/                     \r\n");
            Console.WriteLine();
            Console.WriteLine("请输入UserName:");
            string userName = Console.ReadLine();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("请输入pwd:");
            string pwd = Console.ReadLine();
            Console.WriteLine();
            Console.WriteLine("Login...");
            (string Token, string userId, string studentId, string userNickName, string accountName, string errorInfo) = await dongniSDK.dongni_login(userName, pwd);

            if(errorInfo != null ) {
                Console.WriteLine("悲报: 出现错误");
                Console.WriteLine(errorInfo);
            }else
            {
                Console.WriteLine("喜报: 没报错 ^o^y");
                Console.WriteLine("解析结果返回: ");
                Console.WriteLine("Token = " + Token);
                Console.WriteLine("userId = "+  userId);
                Console.WriteLine("studentId = " +  studentId);
                Console.WriteLine("userNickName = " +  userNickName);
                Console.WriteLine("accountName = " +  accountName);

            }
            await Task.Delay(10000);
        }
    }
}
