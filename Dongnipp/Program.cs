using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
// This is just a TESTING file!!!
namespace top.nuozhen.Dongnipp.test
{
    internal class Program
    {
        static DongnippSDK.DongniUser dongniUser;
        static DongnippSDK.DongniRole currentRole;
        // This is just a TESTING file!!!
        public static async Task Main()
        {
            //RunTesting();
            DongnippSDK.SetDebug(false);
            DongnippSDK.ErrorOccurred += (sender, e) =>
            {
                ConsoleColor originalForegroundColor = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\n****************************************************\n\n!! ERROR OCCURRED !!\n\n");
                Console.WriteLine(e.Exception.ToString());
                Console.WriteLine("\n\nDongni++ SDK Version: " + DongnippSDK.Version);
                Console.WriteLine("\n\n!! ERROR OCCURRED !!\n\n****************************************************");
                Console.WriteLine("继续运行可能会发生不可预期的异常。");
                Console.WriteLine("你希望程序继续运行吗？请输入Y或N: ");
                

                string userResponse = Console.ReadLine();

                if (userResponse.ToUpper() != "Y" && userResponse.ToUpper() != "y")
                {
                    Environment.Exit(0);
                }
                Console.WriteLine("\n\n");
                Console.ForegroundColor = originalForegroundColor;
            };
            Console.WriteLine("\r\n  _____                          _             \r\n |  __ \\                        (_)  _     _   \r\n | |  | | ___  _ __   __ _ _ __  _ _| |_ _| |_ \r\n | |  | |/ _ \\| '_ \\ / _` | '_ \\| |_   _|_   _|\r\n | |__| | (_) | | | | (_| | | | | | |_|   |_|  \r\n |_____/ \\___/|_| |_|\\__, |_| |_|_|            \r\n                      __/ |                    \r\n                     |___/                     \r\n");
            Console.WriteLine();
            Console.WriteLine("Dongni++ SDK 版本号: " + DongnippSDK.Version);
            if (DongnippSDK.debugging)
            {
                Console.WriteLine("[Warning] 已启用全局调试模式，将可能输出服务器原始返回信息，请注意隐私保护。");
            }
            await Login();
            await SelectRole();
            PrintHelp();
            while (true) {
                Console.Write("请输入指令 (输入h以获取帮助): ");
                string userCommandInput = Console.ReadLine();
                switch (userCommandInput)
                {
                    case "h":
                        PrintHelp();
                        break;
                    case "a":
                        await ListAllExams();
                        break;
                    case "r":
                        await SelectRole();
                        break;
                    case "l":
                        await ListLatestExams();
                        break;
                    case "o":
                        await Logout();
                        await Login();
                        await SelectRole();
                        break;
                    case "s":
                        await InquireExamScore();
                        break;
                    case "g":
                        //
                        break;
                    case "c":
                        //
                        break;
                    case "q":
                        await Logout();
                        Environment.Exit(0);
                        break;
                    default:
                        ConsoleColor originalForegroundColor = Console.ForegroundColor;
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("未知的命令。");
                        Console.ForegroundColor = originalForegroundColor;
                        PrintHelp();
                        break;
                }
            }
            //Console.WriteLine("即将开始测试考试信息查询");
            //Console.WriteLine("================================\n");
            //Console.WriteLine("-------------分数查询-------------\n");
            //Console.WriteLine("请输入欲查询考试的examId:");
            //string score_examId = Console.ReadLine();
            //Console.WriteLine("\n请输入欲查询科目的courseId (以半角逗号分割, 留空则代表取得默认科目或者全科总分):");
            //string score_courseId = Console.ReadLine();
            //Console.WriteLine("\n开始查询....");
            //(string[] score_courseName, string[] score_stuScore, string[] score_exScore) = await dongniSDK.getScore(Token, userId, studentId, score_examId, schoolId, score_courseId);
            //for(int i = 0; i< score_courseName.Length; i++)
            //{
            //    Console.WriteLine("\n*********************");
            //    Console.WriteLine("科目: " + score_courseName[i]);
            //    Console.WriteLine("本科目总分: " + score_exScore[i]);
            //    Console.WriteLine("学生取得总分: " + score_stuScore[i]);
            //    Console.WriteLine("*********************\n");
            //}

            //Console.WriteLine("\n-------------分数查询-------------");
        }

        private static async Task Logout()
        {
            await dongniUser.Logout();
            dongniUser = null;
            currentRole = null;
        }

        private static void PrintHelp()
        {
            Console.WriteLine("""


                             | Dongni++ 测试程序 |
                             |      命令帮助     |
                ===============================================

                h | 显示此帮助。
                a | 列出当前角色所有考试。
                r | 重新选择角色。
                l | 列出当前角色最近两次考试。
                o | 退出当前用户登录。
                s | 查询某次考试成绩。
                g | 查询某次考试段排。
                c | 查询某次考试班排。
                q | 退出登录并退出本程序。

                ==============================================


                """);
        }

        private static async Task ListAllExams()
        {
            Console.WriteLine("即将输出考试列表, 开始请求考试列表。");
            DongnippSDK.DongniExam[] examList = await currentRole.GetList();
            Console.WriteLine("\n================================\n");
            for (int i = 0; i < examList.Length; i++)
            {
                Console.WriteLine("\n******************************");
                Console.WriteLine($"第{i + 1}个考试");
                Console.WriteLine($"考试名称(examName): {examList[i].ExamName}");
                Console.WriteLine($"考试ID(examId): {examList[i].ExamId}");
                Console.WriteLine($"考试类型(examType): {examList[i].ExamType}");
                Console.WriteLine($"考试开始时间(startDate): {examList[i].StartDate}");
                Console.WriteLine($"考试结束时间(endDate): {examList[i].EndDate}");
                Console.WriteLine("******************************");
            }
            Console.WriteLine("\n================================\n");
        }

        private static async Task ListLatestExams()
        {
            Console.WriteLine("开始请求最近两场考试信息");
            DongnippSDK.DongniExam[] latestExams = await currentRole.GetLatest();
            Console.WriteLine("\n================================\n");
            Console.WriteLine("开始输出第一个考试信息");
            Console.WriteLine("考试名称 (examName) = " + latestExams[0].ExamName);
            Console.WriteLine("考试ID (examId) = " + latestExams[0].ExamId);
            Console.WriteLine("考试类型 (examType) = " + latestExams[0].ExamType);
            Console.WriteLine("考试开始时间 (startDate) = " + latestExams[0].StartDate);
            Console.WriteLine("考试结束时间 (endDate) = " + latestExams[0].EndDate);
            Console.WriteLine("\n--------------------------------\n");
            Console.WriteLine("开始输出第二个考试信息");
            Console.WriteLine("考试名称 (examName) = " + latestExams[1].ExamName);
            Console.WriteLine("考试ID = (examId) " + latestExams[1].ExamId);
            Console.WriteLine("考试类型 (examType) = " + latestExams[1].ExamType);
            Console.WriteLine("考试开始时间 (startDate) = " + latestExams[1].StartDate);
            Console.WriteLine("考试结束时间 (endDate) = " + latestExams[1].EndDate);
            Console.WriteLine("\n================================\n");
        }

        private static async Task Login()
        {
            Console.WriteLine("\n请输入用户名 [通常为手机号]:");
            string userName = Console.ReadLine();
            Console.WriteLine("\n\n请输入密码:");
            string pwd = ReadPassword();
            Console.WriteLine("\n\nLogin...");
            dongniUser = await DongnippSDK.DongniUser.Login(userName, pwd);
            Console.WriteLine("\n================================\n");
            Console.WriteLine("登录返回用户: ");
            Console.WriteLine(dongniUser.ToString());
            Console.WriteLine("\n================================\n");
        }

        private static async Task InquireExamScore()
        {
            DongnippSDK.DongniExam currentExam;
        requireUserInput: Console.Write("""

                请选择查询范围
                    [1] 最近两次  |  [2] 所有考试
                请输入:
                """);

            switch (Console.ReadLine())
            {
                case "1":
                    DongnippSDK.DongniExam[] latestExams = await currentRole.GetLatest();
                    Console.WriteLine("\n================================\n");
                    Console.WriteLine("[0]");
                    Console.WriteLine(" | 考试名称 (examName) = " + latestExams[0].ExamName);
                    Console.WriteLine(" | 考试ID (examId) = " + latestExams[0].ExamId);
                    Console.WriteLine(" | 考试类型 (examType) = " + latestExams[0].ExamType);
                    Console.WriteLine(" | 考试开始时间 (startDate) = " + latestExams[0].StartDate);
                    Console.WriteLine(" | 考试结束时间 (endDate) = " + latestExams[0].EndDate);
                    Console.WriteLine("\n--------------------------------\n");
                    Console.WriteLine("[1]");
                    Console.WriteLine(" | 考试名称 (examName) = " + latestExams[1].ExamName);
                    Console.WriteLine(" | 考试ID = (examId) " + latestExams[1].ExamId);
                    Console.WriteLine(" | 考试类型 (examType) = " + latestExams[1].ExamType);
                    Console.WriteLine(" | 考试开始时间 (startDate) = " + latestExams[1].StartDate);
                    Console.WriteLine(" | 考试结束时间 (endDate) = " + latestExams[1].EndDate);
                    Console.WriteLine("\n================================\n");
                    Console.WriteLine("请输入考试前的序号: ");
                    string userInputedExamSort = Console.ReadLine();
                    int examSort;
                    while (!int.TryParse(userInputedExamSort, out examSort))
                    {
                        Console.WriteLine($"无法将输入{userInputedExamSort} 解析为int类型。请重新输入:");
                        userInputedExamSort = Console.ReadLine();

                    }
                    while (examSort >= latestExams.Length)
                    {
                        Console.WriteLine($"输入{examSort} 超过解析出的考试数组下标最大值{latestExams.Length - 1}。请重新输入:");
                        userInputedExamSort = Console.ReadLine();
                        while (!int.TryParse(userInputedExamSort, out examSort))
                        {
                            Console.WriteLine($"无法将输入{userInputedExamSort} 解析为int类型。请重新输入:");
                            userInputedExamSort = Console.ReadLine();
                        }
                    }
                    currentExam = latestExams[examSort];
                    Console.WriteLine($"\n已选择考试:  {currentExam.ExamId} => {currentExam.ExamName}");
                    break;

                case "2":
                    DongnippSDK.DongniExam[] examList = await currentRole.GetList();
                    Console.WriteLine("\n================================\n");
                    for (int i = 0; i < examList.Length; i++)
                    {
                        Console.WriteLine("\n******************************");
                        Console.WriteLine($"[{i}]");
                        Console.WriteLine($" | 考试名称(examName): {examList[i].ExamName}");
                        Console.WriteLine($" | 考试ID(examId): {examList[i].ExamId}");
                        Console.WriteLine($" | 考试类型(examType): {examList[i].ExamType}");
                        Console.WriteLine($" | 考试开始时间(startDate): {examList[i].StartDate}");
                        Console.WriteLine($" | 考试结束时间(endDate): {examList[i].EndDate}");
                        Console.WriteLine("******************************");
                    }
                    Console.WriteLine("\n================================\n");
                    Console.WriteLine("请输入考试前的序号: ");
                    string userInputedExamSortInList = Console.ReadLine();
                    int examSortInList;
                    while (!int.TryParse(userInputedExamSortInList, out examSortInList))
                    {
                        Console.WriteLine($"无法将输入{userInputedExamSortInList} 解析为int类型。请重新输入:");
                        userInputedExamSortInList = Console.ReadLine();

                    }
                    while (examSortInList >= examList.Length)
                    {
                        Console.WriteLine($"输入{examSortInList} 超过解析出的考试数组下标最大值{examList.Length - 1}。请重新输入:");
                        userInputedExamSortInList = Console.ReadLine();
                        while (!int.TryParse(userInputedExamSortInList, out examSortInList))
                        {
                            Console.WriteLine($"无法将输入{userInputedExamSortInList} 解析为int类型。请重新输入:");
                            userInputedExamSortInList = Console.ReadLine();
                        }
                    }
                    currentExam = examList[examSortInList];
                    Console.WriteLine($"\n已选择考试:  {currentExam.ExamId} => {currentExam.ExamName}");
                    break;
                default:
                    goto requireUserInput;  //要求用户重新选择
            }
            Console.WriteLine("\n请输入需查询的科目courseId (多个用半角逗号分割, 留空则为默认科目): ");
            string courseId = Console.ReadLine();
            Console.WriteLine("请输入查询的statId (留空自动获取默认值): ");
            string statId = Console.ReadLine();
            Console.WriteLine("\n正在获取成绩...");
            string[] courseIds = courseId.Split(",");
            string fullMark = "Failed to get";
            string totalScore = "Failed to get";
            if (string.IsNullOrEmpty(statId))
            {
                (fullMark, totalScore) = await currentExam.GetScore(courseIds);
            }
            else
            {
                (fullMark, totalScore) = await currentExam.GetScore(statId, courseIds);
            }
            ConsoleColor originalForegroundColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine($"""


                {currentExam.ExamName}
                =======================================================
                   考生: {dongniUser.NickName}
                   考试: {currentExam.ExamName} ({currentExam.ExamId})
                   考试总分: {fullMark}
                   考生得分: {totalScore}
                =======================================================

                """);
            Console.ForegroundColor = originalForegroundColor;
        }

        private static async Task SelectRole()
        {
            Console.WriteLine("正在列表角色: \n\n");
            DongnippSDK.DongniRole[] userRoles = await dongniUser.ListRole();
            for (int i = 0; i < userRoles.Length; i++)
            {
                Console.WriteLine($"[{i}]");
                Console.WriteLine($"|  StudentId = {userRoles[i].StudentId}");
                Console.WriteLine($"|  StudentName = {userRoles[i].StudentName}");
                Console.WriteLine($"|  ClassName = {userRoles[i].ClassName}");
                Console.WriteLine($"|  ClassId = {userRoles[i].ClassId}");
                Console.WriteLine($"|  GradeName = {userRoles[i].GradeName}");
                Console.WriteLine($"|  GradeId = {userRoles[i].GradeId}");
                Console.WriteLine($"|  SchoolName = {userRoles[i].SchoolName}");
                Console.WriteLine($"|  SchoolId = {userRoles[i].SchoolId}");
                Console.WriteLine($"|  RelativeId = {userRoles[i].RelativeId}");
                Console.WriteLine($"|  UserType = {userRoles[i].UserType}");
            }
            Console.WriteLine("请输入角色头部的序号以选择角色: ");
            string userInputedRoleSort = Console.ReadLine();
            int roleSort;
            while (!int.TryParse(userInputedRoleSort, out roleSort))
            {
                Console.WriteLine($"无法将输入{userInputedRoleSort} 解析为int类型。请重新输入:");
                userInputedRoleSort = Console.ReadLine();

            }
            while (roleSort >= userRoles.Length)
            {
                Console.WriteLine($"输入{roleSort} 超过解析出的角色数组下标最大值{userRoles.Length - 1}。请重新输入:");
                userInputedRoleSort = Console.ReadLine();
                while (!int.TryParse(userInputedRoleSort, out roleSort))
                {
                    Console.WriteLine($"无法将输入{userInputedRoleSort} 解析为int类型。请重新输入:");
                    userInputedRoleSort = Console.ReadLine();

                }
            }
            currentRole = await dongniUser.SelectRole(roleSort);
            Console.WriteLine($"\n已选择角色:  {currentRole.StudentId}");
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
        /// <summary>
        /// 在这里放置运行前用以测试的代码。该方法仅在程序运行之初调用。
        /// </summary>
        private static void RunTesting()
        {

            Console.ReadLine();
        }


    }
}
