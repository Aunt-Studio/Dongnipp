using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Net;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Policy;

namespace top.nuozhen.Dongnipp
{
    /*
      _____                               _                  _____  _____   _  __
     |  __ \                             (_)   _      _     / ____||  __ \ | |/ /
     | |  | |  ___   _ __    __ _  _ __   _  _| |_  _| |_  | (___  | |  | || ' / 
     | |  | | / _ \ | '_ \  / _` || '_ \ | ||_   _||_   _|  \___ \ | |  | ||  <  
     | |__| || (_) || | | || (_| || | | || |  |_|    |_|    ____) || |__| || . \ 
     |_____/  \___/ |_| |_| \__, ||_| |_||_|               |_____/ |_____/ |_|\_\
                             __/ |                                               
                            |___/                                                
    Dongni++ SDK
    V0.0.0 Developing
    Developed by Aunt Studio
    Also see this: https://github.com/Aunt-Studio/Dongnipp
    */

    internal class dongniSDK
    {
        private static RSAParameters publicKey; // 全局RSA公钥Parameters
        public static bool debugging;
        public static string Version = "V0.0.0 Developing";//全局版本号
        /// <summary>
        /// 登录懂你平台，并获取查询需要用的各种参数数据。
        /// 对于studentId，请使用getRoleInfo()获取。
        /// 
        /// </summary>
        /// <param name="username">用户名 (应该是手机号)</param>
        /// <param name="password">密码</param>
        /// <returns></returns>
        public static async Task<(string Token, string userId, string userName, string accountName)> login(string username, string password)
        {
            string accountName = null;
            string userName = null;
            string userId = null;
            string post = null;
            string back = null;
            string aN = null;
            string pw = null;
            string Token = null;
            try
            {
                // 加载RSA公钥
                string publicKeyPem = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCphVCsMh1khU8W0l1WBu0RHTprNr+e2iO0+lLdx+I0tAzCj7jdr5h+tcqZazFuwa751wuegYb0XDbm+/Ti7mWH/Etm+Qc9c5+dBZGzEH0zH8f1cV8EfU8qcsNtn/ixAS7HDl0nzhzlATmH8iFa3l2dYoMBxUZV6Bpyj+gSWg+Y5QIDAQAB-----END PUBLIC KEY-----";
                publicKey = RSAUtils.GetPublicKeyParameters(publicKeyPem);

                aN = RSAUtils.EncryptToBase64(publicKey, Encoding.Default.GetBytes(username));
                pw = RSAUtils.EncryptToBase64(publicKey, Encoding.Default.GetBytes(password));

                post = "{\"accountName\":\"" + aN + "\",\"password\":\"" + pw + "\",\"validate\":null,\"userId\":null,\"clientType\":1}";
                back = await PostRequest("https://www.dongni100.com/api/base/data/encrypt/login", post, "application/json");

                writeLog("dongni_login Back: " + back, "Server Back", true);

                JObject json = JObject.Parse(back);
                string status = json["status"].ToString();

                if (status == "0")
                {
                    Token = json["data"]["dongniLoginToken"].ToString();
                    accountName = json["data"]["accountName"].ToString();
                    userName = json["data"]["userName"].ToString();
                    userId = json["data"]["userId"].ToString();

                }
                else
                {
                    throw new APIException("Coursed by: Status value is not 0.\n\nThe server returned: " + back);

                }

                json = null;

            }
            catch (APIException ex)
            {
                ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at Dongnipp.login Method.", ex));
            }
            catch (Exception ex)
            {
                ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at Dongnipp.login Method.", ex));
            }

            return (Token, userId, userName, accountName);
        }
        /// <summary>
        /// 获取最近两次考试信息。
        /// </summary>
        /// <param name="Token">登录时获取的用户 Token</param>
        /// <param name="userId">登录时获取的用户 userId</param>
        /// <param name="studentId">登录时获取的 studentId</param>
        /// <returns>返回的两个变量数组: 
        /// {1.考试名称, 2.考试ID, 3.考试类型ID, 4.考试开始日期, 5.考试结束日期}</returns>
        public static async Task<(string[] firstExam, string[] secondExam)> getLatest(string Token, string userId, string studentId)
        {
            string[] firstExam = { "", "", "", "", "" };
            //{1.考试名称, 2.考试ID, 3.考试类型ID, 4.考试开始日期, 5.考试结束日期}
            string[] secondExam = { "", "", "", "", "" };
            try
            {


                string URL = "https://www.dongni100.com/api/exam/plan/student/latest?clientType=1&examType=2,3,4,5,7,9,10&userId=" + userId + "&studentId=" + studentId;
                string back = await GetResponse(URL, Token);

                writeLog("Getting Latest Back = " + back, "Server Back", true);

                JObject json = JObject.Parse(back);
                string status = json["status"].ToString();

                if (status == "0")
                {
                    firstExam[0] = json["data"][0]["examName"].ToString();
                    firstExam[1] = json["data"][0]["examId"].ToString();
                    firstExam[2] = json["data"][0]["examId"].ToString();
                    firstExam[3] = json["data"][0]["startDate"].ToString();
                    firstExam[4] = json["data"][0]["endDate"].ToString();
                    secondExam[0] = json["data"][1]["examName"].ToString();
                    secondExam[1] = json["data"][1]["examId"].ToString();
                    secondExam[2] = json["data"][1]["examId"].ToString();
                    secondExam[3] = json["data"][1]["startDate"].ToString();
                    secondExam[4] = json["data"][1]["endDate"].ToString();
                }
                else
                {
                    throw new APIException("Coursed by: Status value is not 0.\n\nThe server returned: " + back);
                }
            }
            catch (APIException ex)
            {
                ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at Dongnipp.getLatest Method.", ex));
            }
            catch (Exception ex)
            {
                ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at Dongnipp.getLatest Method.", ex));
            }
            return (firstExam, secondExam);
        }

        /// <summary>
        /// 获取该studentId下所有考试列表(实际为前100个)，以各考试属性数组形式返回。
        /// 通常而言，数组下标越接近于0，则考试时间越接近。
        /// </summary>
        /// <param name="Token">登录时获取的用户 Token</param>
        /// <param name="userId">登录时获取的用户 userId</param>
        /// <param name="studentId">待获取列表的 studentId</param>
        /// <param name="SchoolId">目标学校schoolId。必须使用getRoleInfo() 获取。</param>
        /// <returns>各考试属性值。以数组形式返回。</returns>
        public static async Task<(string[] examName, string[] examId, string[] examType, string[] startDate, string[] endDate)> getExamList(string Token, string userId, string studentId, string SchoolId)
        {
            try
            {
                string URL = $"https://www.dongni100.com/api/exam/plan/student/exam/list?clientType=1&schoolId={SchoolId}&examType=2,3,4,5,7,10&courseId=&pageSize=100&pageNo=1&userId=" + userId + "&studentId=" + studentId;
                string back = await GetResponse(URL, Token);

                writeLog("Getting Exam List Back = " + back, "Server Back", true);

                JObject json = JObject.Parse(back);
                string status = json["status"].ToString();
                writeLog("Start writing list.", isDebug: true);
                List<string> List_examName = new List<string>();
                List<string> List_examId = new List<string>();
                List<string> List_examType = new List<string>();
                List<string> List_startDate = new List<string>();
                List<string> List_endDate = new List<string>();
                if (status == "0")
                {


                    for (int i = 0; i < json["data"]["exam"].Count(); i++)
                    {

                        List_examName.Add(json["data"]["exam"][i]["examName"].ToString());
                        List_examId.Add(json["data"]["exam"][i]["examId"].ToString());
                        List_examType.Add(json["data"]["exam"][i]["examType"].ToString());
                        List_startDate.Add(json["data"]["exam"][i]["startDate"].ToString());
                        List_endDate.Add(json["data"]["exam"][i]["endDate"].ToString());
                        writeLog($"{i + 1}st exam has written to the list.", isDebug: true);
                    }
                    writeLog("Written to list.", isDebug: true);


                }
                else
                {
                    throw new APIException("Status value is not 0.\n\n The server returned: " + back);
                }
                return (List_examName.ToArray(), List_examId.ToArray(), List_examType.ToArray(), List_startDate.ToArray(), List_endDate.ToArray());
            }
            catch (APIException ex)
            {
                ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at Dongnipp.getExamList Method.", ex));
            }
            catch (Exception ex)
            {
                ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at Dongnipp.getExamList Method.", ex));
            }
            return (null, null, null, null, null);

        }


        /// <summary>
        /// 获取当前用户下的第{Sort}个角色信息。通常Sort = 0取到的是默认角色信息。角色信息包含SchoolId、学校名称、班级名称等。本函数在查询列表、需要切换角色等场景下会使用到。
        /// </summary>
        /// <param name="token">登录时收到的Token</param>
        /// <returns></returns>
        public static async Task<(string schoolId, string schoolName, string className, string gradeName, string studentName, string studentId, string classNickname, string userType, string userName)> getRoleInfo(string Token, int Sort = 0)
        {
            try
            {
                string schoolId = null;
                string schoolName = null;
                string className = null;
                string gradeName = null;
                string studentName = null;
                string studentId = null;
                string classNickname = null;
                string userType = null;
                string userName = null;

                string URL = "https://www.dongni100.com/api/base/data/account/role?clientType=1";
                string back = await GetResponse(URL, Token);

                writeLog("GettingSchoolInfo Back: " + back, "Server Back", true);

                JObject json = JObject.Parse(back);
                string status = json["status"].ToString();
                JArray userList = (JArray)json["data"][0]["userList"];

                if (status == "0")
                {
                    JObject selectedUser = null;

                    foreach (JObject user in userList.Cast<JObject>())
                    {
                        if ((int)user["userSort"] == Sort)
                        {
                            selectedUser = user;
                            break;
                        }
                    }

                    if (selectedUser != null)
                    {
                        schoolId = (string)selectedUser["schoolId"];
                        schoolName = (string)selectedUser["schoolName"];
                        className = (string)selectedUser["className"];
                        gradeName = (string)selectedUser["gradeName"];
                        studentName = (string)selectedUser["studentName"];
                        studentId = (string)selectedUser["studentId"];
                        classNickname = (string)selectedUser["nickname"];
                        userType = (string)selectedUser["userType"];
                        userName = (string)selectedUser["userName"];

                    }
                    else
                    {
                        throw new APIException("Cannot get specified user information.\n\n Server returned: " + back);

                    }

                    
                }
                else
                {
                    throw new APIException("Status value is not 0.\n\n The server returned: " + back);
                }
                return (schoolId, schoolName, className, gradeName, studentName, studentId, classNickname, userType, userName);

            }
            catch (APIException ex)
            {
                ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at Dongnipp.getRole Method.", ex));
            }
            catch (Exception ex)
            {
                ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at Dongnipp.getRole Method.", ex));
            }
            return (null, null, null, null, null, null, null, null, null);

        }

        /// <summary>
        /// 获取当前科目的考生得分与该科目总分。也可用于大型考试的多科目总分。
        /// </summary>
        /// <param name="Token">登录时获取的用户 Token</param>
        /// <param name="userId">登录时获取的用户 userId</param>
        /// <param name="studentId">待查询的角色 studentId</param>
        /// <param name="examId">待查询的考试 examId</param>
        /// <param name="schoolId">当前考试所属的学校 schoolId</param>
        /// <param name="courseId">待查询的科目 courseId。可以不传入或传入空文本, 留空则查询默认科目。在大型考试 (包含"总分"成绩页面) 中留空此参数来查询总分。</param>
        /// <returns>返回值string[] Score 为考生取得的分数; string[] examTotalScore 则为考试该科目的总分值, string[] courseName 则为当前数组索引对应的科目名称。各数组索引均为传入的courseId从小到大的排序次序。例如传入courseId:"4,6,10"，则各返回值的数组索引[0], [1], [2]分别对应着courseId = 4, courseId = 6, courseId = 10 的属性值。</returns>
        public static async Task<(string[] courseName, string[] Score, string[] examTotalScore)> getScore(string Token, string userId, string studentId, string examId, string schoolId, string courseId = "")
        {
            try
            {
                Func<Task<string>> getStatId = async () =>
                {
                    string stat = "0";
                    string stat_back = await GetResponse($"https://www.dongni100.com/api/analysis/data/exam/student/weChat/all/examStatId?clientType=1&examId={examId}&schoolId={schoolId}&userId={userId}&studentId={studentId}", Token);
                    JObject stat_json = JObject.Parse(stat_back);
                    if (stat_json["status"].ToString() == "0")
                    {
                        stat = stat_json["data"]["statId"].ToString();
                    }
                    return stat;
                };
                string statId = await getStatId();
                string URL;
                bool isSpecificCourse = courseId == "";
                if (isSpecificCourse)
                {
                    writeLog("无指定科目输入，将直接获取非分科信息。", isDebug: true);
                    URL = $"https://www.dongni100.com/api/analysis/view/monitor/exam/school/scoreSection?clientType=1&courseId&examId={examId}&statId={statId}&schoolId={schoolId}&userId={userId}&studentId={studentId}";
                    string back = await GetResponse(URL, Token);

                    string studentScore = "", examScore = "";

                    JObject json = JObject.Parse(back);
                    string status = json["status"].ToString();

                    if (status == "0")
                    {
                        studentScore = json["data"]["totalScore"].ToString();
                        examScore = json["data"]["fullMark"].ToString();
                    }
                    else
                    {
                        throw new APIException("Status value is not 0.\n\n The server returned: " + back);
                    }
                    return (new string[] {"总分"}, new string[] { studentScore }, new string[] { examScore });    //Note: 这里可以改一下，等到getCourseName()方法写好后应该用courseId查询科目名称的。
                }
                else {
                    writeLog("存在指定科目输入，将获取全科成绩后分科解析。", isDebug:true);

                    List<string> courseNames = new List<string>();  //初始化科目名称列表，列表按照科目CourseId从小到大索引。
                    List<string> Score = new List<string>();   //初始化分数列表，列表按照科目CourseId从小到大索引。
                    List<string> examTotalScore = new List<string>();   //初始化分数列表，列表按照科目CourseId从小到大索引。

                    string[] Splited_courseId = courseId.Split(',');
                    int[] SelectedCourseId = Array.ConvertAll(Splited_courseId, int.Parse);
                    Array.Sort(SelectedCourseId);   //为选定的CourseId排序。
                    for(int i = 0; i < SelectedCourseId.Length; i++)
                    {
                        writeLog($"已确认选定的CourseID: {SelectedCourseId[i]}", isDebug: true);
                    }

                    writeLog($"开始解析...", isDebug:true);

                    for(int i = 0; i < SelectedCourseId.Length; i++) {
                        URL = $"https://www.dongni100.com/api/analysis/view/monitor/exam/school/course/scoreSection?clientType=1&courseId={SelectedCourseId[i]}&examId={examId}&statId={statId}&schoolId={schoolId}&userId={userId}&studentId={studentId}";
                        string back = await GetResponse(URL, Token);
                        JObject json = JObject.Parse(back);
                        string status = json["status"].ToString();

                        if (status == "0")
                        {
                            courseNames.Add((string)json["data"][0]["courseName"]);
                            Score.Add((string)json["data"][0]["totalScore"]);
                            examTotalScore.Add((string)json["data"][0]["fullMark"]);
                        }
                        else
                        {
                            throw new APIException($"Status value is not 0.\n\nAt CourseId = {SelectedCourseId[i]} \n\nThe server returned: " + back);
                        }
                        
                    }
                    return (courseNames.ToArray(), Score.ToArray(), examTotalScore.ToArray());
                }


            }
            catch (APIException ex)
            {
                ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at Dongnipp.getScore Method.", ex));
            }
            catch (Exception ex)
            {
                ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at Dongnipp.getScore Method.", ex));
            }
            return (new string[] { "获取失败" }, new string[] { "0" }, new string[] { "0" });
        }

        /// <summary>
        /// 传入懂你的登录Token，向服务器发起GET请求。
        /// </summary>
        /// <param name="url">欲发送请求的URL</param>
        /// <param name="token">登录获取的Token 值，即Header的Dongni-login 值。</param>
        /// <returns>返回服务器的Response</returns>
        private static async Task<string> GetResponse(string url, string token)
        {
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Dongni-login", token);
                HttpResponseMessage response = await client.GetAsync(url);
                string responseContent = await response.Content.ReadAsStringAsync();
                return responseContent;
            }
        }
        /// <summary>
        /// 向服务器发起POST请求。用以登录获取Token。
        /// </summary>
        /// <param name="url">欲发送请求的URL</param>
        /// <param name="postData">欲POST的内容</param>
        /// <param name="contentType">内容类型</param>
        /// <returns>返回服务器的Response。</returns>
        private static async Task<string> PostRequest(string url, string postData, string contentType)
        {
            using (HttpClient client = new HttpClient())
            {
                StringContent content = new StringContent(postData, Encoding.UTF8, contentType);
                HttpResponseMessage response = await client.PostAsync(url, content);
                string responseContent = await response.Content.ReadAsStringAsync();
                return responseContent;
            }
        }
        /// <summary>
        /// 写入日志，如果要修改日志的输出方式，请修改这个函数的代码。默认是向控制台输出日志信息。
        /// </summary>
        /// <param name="message">欲输出的日志内容</param>
        /// <param name="eventType">日志信息的类型 (例如INFO、WARNING等)</param>
        /// <param name="isDebug">是否是Debug类型。如果为true，则仅在全局debugging==true时输出。默认为false。</param>
        private static void writeLog(string message, string eventType = "INFO", bool isDebug = false)
        {
            if (isDebug && debugging)
            {
                Console.WriteLine($"[Debug / {eventType}] " + message);
            }
            else if (!isDebug)
            {
                Console.WriteLine($"[{eventType}]" + message);
            }

        }
        /// <summary>
        /// 设置在dongniSDK中是否输出调试信息。
        /// </summary>
        /// <param name="debug">true为全局输出调试日志，反之不输出。</param>
        public static void setDebug(bool debug)
        {
            debugging = debug;
        }
        public delegate void ErrorHandler(object sender, ErrorEventArgs e);

        public static event ErrorHandler ErrorOccurred;

        public class ErrorEventArgs : EventArgs
        {
            public string Message { get; set; }
            public Exception Exception { get; set; }

            public ErrorEventArgs(string message, Exception exception)
            {
                Message = message;
                Exception = exception;
            }


        }
        public class APIException : Exception
        {
            public APIException()
            {
            }

            public APIException(string message)
                : base(message)
            {
            }

            public APIException(string message, Exception inner)
                : base(message, inner)
            {
            }
        }

    }
}
