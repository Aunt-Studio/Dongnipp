using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
// This is just a TESTING file!!!
namespace top.nuozhen.Dongnipp.test
{
    internal class Program
    {
        // This is just a TESTING file!!!
        public static async Task Main()
        {

            dongniSDK.setDebug(false);
            dongniSDK.ErrorOccurred += (sender, e) =>
            {
                Console.WriteLine("\n******************************\n\n!! ERROR OCCURRED !!\n\n");
                Console.WriteLine(e.Exception.ToString());
                Console.WriteLine("\n\nDongni++ SDK Version: " + dongniSDK.Version);
                Console.WriteLine("\n\n!! ERROR OCCURRED !!\n\n******************************");
                Console.WriteLine("你希望程序继续运行吗？请输入Y或N：");

                string userResponse = Console.ReadLine();

                if (userResponse.ToUpper() != "Y" && userResponse.ToUpper() != "y")
                {
                    Environment.Exit(0);
                }
                Console.WriteLine("\n\n");
            };
            Console.WriteLine("\r\n  _____                          _             \r\n |  __ \\                        (_)  _     _   \r\n | |  | | ___  _ __   __ _ _ __  _ _| |_ _| |_ \r\n | |  | |/ _ \\| '_ \\ / _` | '_ \\| |_   _|_   _|\r\n | |__| | (_) | | | | (_| | | | | | |_|   |_|  \r\n |_____/ \\___/|_| |_|\\__, |_| |_|_|            \r\n                      __/ |                    \r\n                     |___/                     \r\n");
            Console.WriteLine();
            Console.WriteLine("Dongni++ SDK 版本号: " + dongniSDK.Version);
            if (dongniSDK.debugging)
            {
                Console.WriteLine("[Warning] 已启用全局调试模式，将可能输出服务器原始返回信息，请注意隐私保护。");
            }
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
            (string Token, string userId, string userNickName, string accountName) = await dongniSDK.login(userName, pwd.ToString());
            (string schoolId, _, _, _, _, string studentId, _, _, _) = await dongniSDK.getRoleInfo(Token, 0);
            Console.WriteLine("解析结果返回: ");
            Console.WriteLine("Token = " + Token);
            Console.WriteLine("userId = " + userId);
            Console.WriteLine("studentId = " + studentId);
            Console.WriteLine("userNickName = " + userNickName);
            Console.WriteLine("accountName = " + accountName);
            Console.WriteLine("\n================================\n");
            (string[] firstExam, string[] secondExam) = await dongniSDK.getLatest(Token, userId, studentId);

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

            Console.WriteLine("\n================================\n");
            Console.WriteLine("即将输出考试列表, 开始请求考试列表。");
            Console.WriteLine("\n================================\n");
            (string[] examName, string[] examId, string[] examType, string[] startDate, string[] endDate) = await dongniSDK.getExamList(Token, userId, studentId, schoolId);
            for (int i = 0; i < examName.Length; i++)
            {
                Console.WriteLine("\n******************************");
                Console.WriteLine($"第{i + 1}个考试");
                Console.WriteLine($"考试名称(examName): {examName[i]}");
                Console.WriteLine($"考试ID(examId): {examId[i]}");
                Console.WriteLine($"考试类型(examType): {examType[i]}");
                Console.WriteLine($"考试开始时间(startDate): {startDate[i]}");
                Console.WriteLine($"考试结束时间(endDate): {endDate[i]}");
                Console.WriteLine("******************************");
            }
            Console.WriteLine("\n================================");
            Console.WriteLine("即将开始测试考试信息查询");
            Console.WriteLine("================================\n");
            Console.WriteLine("-------------分数查询-------------\n");
            Console.WriteLine("请输入欲查询考试的examId:");
            string score_examId = Console.ReadLine();
            Console.WriteLine("\n请输入欲查询科目的courseId (以半角逗号分割, 留空则代表取得默认科目或者全科总分):");
            string score_courseId = Console.ReadLine();
            Console.WriteLine("\n开始查询....");
            (string[] score_courseName, string[] score_stuScore, string[] score_exScore) = await dongniSDK.getScore(Token, userId, studentId, score_examId, schoolId, score_courseId);
            for(int i = 0; i< score_courseName.Length; i++)
            {
                Console.WriteLine("\n*********************");
                Console.WriteLine("科目: " + score_courseName[i]);
                Console.WriteLine("本科目总分: " + score_exScore[i]);
                Console.WriteLine("学生取得总分: " + score_stuScore[i]);
                Console.WriteLine("*********************\n");
            }
            
            Console.WriteLine("\n-------------分数查询-------------");
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
