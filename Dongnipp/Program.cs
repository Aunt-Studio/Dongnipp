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
            dongniSDK.setDebug(false);
            Console.WriteLine("\r\n  _____                          _             \r\n |  __ \\                        (_)  _     _   \r\n | |  | | ___  _ __   __ _ _ __  _ _| |_ _| |_ \r\n | |  | |/ _ \\| '_ \\ / _` | '_ \\| |_   _|_   _|\r\n | |__| | (_) | | | | (_| | | | | | |_|   |_|  \r\n |_____/ \\___/|_| |_|\\__, |_| |_|_|            \r\n                      __/ |                    \r\n                     |___/                     \r\n");
            Console.WriteLine();
            Console.WriteLine("请输入UserName:");
            string userName = Console.ReadLine();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("请输入pwd:");
            string pwd = ReadPassword();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Login...");
            Console.WriteLine("\n================================\n");
            (string Token, string userId, string studentId, string userNickName, string accountName, string errorInfo) = await dongniSDK.login(userName, pwd.ToString());

            if(errorInfo != null ) {
                Console.WriteLine("悲报: 登录出现错误");
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
                Console.WriteLine("\n================================\n");
                (string[] firstExam, string[] secondExam, string Status) = await dongniSDK.getLatest(Token, userId, studentId);
                
                Console.WriteLine("开始输出第一个考试信息");
                Console.WriteLine("考试名称 = " + firstExam[0]);
                Console.WriteLine("考试ID = " + firstExam[1]);
                Console.WriteLine("考试类型 = " + firstExam[2]);
                Console.WriteLine("考试开始时间 = " + firstExam[3]);
                Console.WriteLine("考试结束时间 = " + firstExam[4]);
                Console.WriteLine("\n--------------------------------\n");
                Console.WriteLine("开始输出第二个考试信息");
                Console.WriteLine("考试名称 = " + secondExam[0]);
                Console.WriteLine("考试ID = " + secondExam[1]);
                Console.WriteLine("考试类型 = " + secondExam[2]);
                Console.WriteLine("考试开始时间 = " + secondExam[3]);
                Console.WriteLine("考试结束时间 = " + secondExam[4]);
            }
            await Task.Delay(100000);
        }
        static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo key;

            do
            {
                key = Console.ReadKey(true);

                // 如果用户按下回车键，则停止接收输入
                if (key.Key == ConsoleKey.Enter)
                    break;

                // 如果用户按下退格键，则删除最后一个字符
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password = password.Remove(password.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    // 将用户输入的字符添加到密码字符串中
                    password += key.KeyChar;
                    Console.Write("*");
                }
            } while (true);

            return password;
        }
    }
}
