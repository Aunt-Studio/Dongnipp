using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Reflection;

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
    Learn more: https://github.com/Aunt-Studio/Dongnipp
    */

    class DongnippSDK
    {
        public static bool debugging;
        public static string Version = "V0.0.0 Developing";//全局版本号

        public class DongniUser
        {
            private const string PublicKey = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCphVCsMh1khU8W0l1WBu0RHTprNr+e2iO0+lLdx+I0tAzCj7jdr5h+tcqZazFuwa751wuegYb0XDbm+/Ti7mWH/Etm+Qc9c5+dBZGzEH0zH8f1cV8EfU8qcsNtn/ixAS7HDl0nzhzlATmH8iFa3l2dYoMBxUZV6Bpyj+gSWg+Y5QIDAQAB-----END PUBLIC KEY-----";

            public string AccountName { get; }
            public string Token { get; }
            public string NickName { get; }
            public string UserId { get; }

            /// <summary>
            /// DongniUser 的构造函数，不应被外部直接调用，创建DongniUser 实例请使用Login()异步工厂方法。
            /// </summary>
            /// <param name="accountName"></param>
            /// <param name="token"></param>
            /// <param name="nickName"></param>
            /// <param name="userId"></param>
            private DongniUser(string accountName, string token, string nickName, string userId)
            {
                this.AccountName = accountName;
                this.Token = token;
                this.NickName = nickName;
                this.UserId = userId;
            }

            public static async Task<DongniUser> Login(string userName, string password)
            {
                string accountName = "";
                string token = "";
                string nickName = "";    //这里的nickName是接口返回的userName，通常是学生姓名
                string userId = "";

                try
                {
                    string encUserName;
                    string encPassword;
                    string postContent;
                    string serverResponse;

                    RSAParameters dongniPublicKey = RSAUtils.GetPublicKeyParameters(PublicKey);

                    encUserName = RSAUtils.EncryptToBase64(dongniPublicKey, Encoding.Default.GetBytes(userName));
                    encPassword = RSAUtils.EncryptToBase64(dongniPublicKey, Encoding.Default.GetBytes(password));

                    postContent = "{\"accountName\":\"" + encUserName + "\",\"password\":\"" + encPassword + "\",\"validate\":null,\"userId\":null,\"clientType\":1}";
                    serverResponse = await PostRequest("https://www.dongni100.com/api/base/data/encrypt/login", postContent, "application/json");

                    WriteLog("DongniUser.Login | RSRR: " + serverResponse, isDebug: true);

                    JObject json = JObject.Parse(serverResponse);
                    

                    if (json["status"].ToString() == "0")
                    {
                        token = json["data"]["dongniLoginToken"].ToString();
                        accountName = json["data"]["accountName"].ToString();
                        nickName = json["data"]["userName"].ToString();
                        userId = json["data"]["userId"].ToString();

                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responsed: " + serverResponse);

                    }
                    return new DongniUser(accountName, token, nickName, userId);
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniUser.Login Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniUser.Login Method.", ex));
                }
                return null;
            }

            public async Task<DongniRole[]> ListRole()
            {

                try
                {
                    string url = "https://www.dongni100.com/api/base/data/account/role?clientType=1";
                    string response = await GetResponse(url, Token);
                    WriteLog("DongniUser.ListRole | RSRR: " + response, isDebug: true);

                    WriteLog("DongniUser.ListRole: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);

                    if (json["status"].ToString() == "0")
                    {
                        List<DongniRole> roles = new List<DongniRole>();

                        foreach (var account in json["data"])
                        {
                            foreach (var user in account["userList"])
                            {
                                DongniRole role = new DongniRole(
                                    this,
                                    user["userSort"].ToString(),
                                    user["classId"].ToString(),
                                    user["className"].ToString(),
                                    user["gradeId"].ToString(),
                                    user["gradeName"].ToString(),
                                    user["relativeId"].ToString(),
                                    user["schoolId"].ToString(),
                                    user["schoolName"].ToString(),
                                    user["studentId"].ToString(),
                                    user["studentName"].ToString(),
                                    user["userType"].ToString()
                                );

                                roles.Add(role);
                                WriteLog($"DongniUser.ListRole: Already parsed {roles.Count} roles.", isDebug: true);
                            }
                        }
                        return (roles.ToArray());
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responsed: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniUser.ListRole Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniUser.ListRole Method.", ex));
                }
                return null;
            }

            public async Task<DongniRole> SelectRole(int roleSort)
            {

                try
                {
                    string url = "https://www.dongni100.com/api/base/data/account/role?clientType=1";
                    string response = await GetResponse(url, Token);
                    WriteLog("DongniUser.SelectRole | RSRR: " + response, isDebug: true);

                    WriteLog("DongniUser.ListRole: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);


                    if (json["status"].ToString() == "0")
                    {
                        JObject selectedUser = null;
                        JArray userList = (JArray)json["data"][0]["userList"];

                        foreach (JObject user in userList.Cast<JObject>())
                        {
                            if ((int)user["userSort"] == roleSort)
                            {
                                selectedUser = user;
                                break;
                            }
                        }
                        if (selectedUser != null)
                        {
                            DongniRole role = new DongniRole(
                                this,
                                selectedUser["userSort"].ToString(),
                                selectedUser["classId"].ToString(),
                                selectedUser["className"].ToString(),
                                selectedUser["gradeId"].ToString(),
                                selectedUser["gradeName"].ToString(),
                                selectedUser["relativeId"].ToString(),
                                selectedUser["schoolId"].ToString(),
                                selectedUser["schoolName"].ToString(),
                                selectedUser["studentId"].ToString(),
                                selectedUser["studentName"].ToString(),
                                selectedUser["userType"].ToString()
                            );

                            return role;
                        }
                        else
                        {
                            throw new APIException("Coursed by: Cannot get specified user information.\n\nRemote server responsed: " + response);

                        }
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responsed: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniUser.SelectRole Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniUser.SelectRole Method.", ex));
                }
                return null;
            }

            public async Task<DongniRole> SelectRole(string roleSort)
            {

                try
                {
                    string url = "https://www.dongni100.com/api/base/data/account/role?clientType=1";
                    string response = await GetResponse(url, Token);
                    WriteLog("DongniUser.SelectRole | RSRR: " + response, isDebug: true);

                    WriteLog("DongniUser.ListRole: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);


                    if (json["status"].ToString() == "0")
                    {
                        JObject selectedUser = null;
                        JArray userList = (JArray)json["data"][0]["userList"];

                        foreach (JObject user in userList.Cast<JObject>())
                        {
                            if ((string)user["userSort"] == roleSort)
                            {
                                selectedUser = user;
                                break;
                            }
                        }
                        if (selectedUser != null)
                        {
                            DongniRole role = new DongniRole(
                                this,
                                selectedUser["userSort"].ToString(),
                                selectedUser["classId"].ToString(),
                                selectedUser["className"].ToString(),
                                selectedUser["gradeId"].ToString(),
                                selectedUser["gradeName"].ToString(),
                                selectedUser["relativeId"].ToString(),
                                selectedUser["schoolId"].ToString(),
                                selectedUser["schoolName"].ToString(),
                                selectedUser["studentId"].ToString(),
                                selectedUser["studentName"].ToString(),
                                selectedUser["userType"].ToString()
                            );

                            return role;
                        }
                        else
                        {
                            throw new APIException("Coursed by: Cannot get specified user information.\n\nRemote server responsed: " + response);

                        }
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responsed: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniUser.SelectRole Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniUser.SelectRole Method.", ex));
                }
                return null;
            }

            public static DongniRole SelectRole(DongniRole[] roleArrow, int roleSort)
            {
                try
                {
                    if (roleSort >= roleArrow.Length)
                    {
                        throw new APIException($"Coursed by: The role object pointed to by the passed parameter \"roleSort\" is out of the array index range of \"roleArrow\".\nroleArrow.length = {roleArrow.Length} \n roleSort = {roleSort}");
                    }
                    return roleArrow[roleSort];
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniUser.SelectRole Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniUser.SelectRole Method.", ex));
                }
                return null;
            }

            public static DongniRole SelectRole(DongniRole[] roleArrow, string roleSort)
            {
                int sort = int.Parse(roleSort);
                return SelectRole(roleArrow, sort);
            }


            public override string ToString()
            {
                Type type = this.GetType();
                string className = type.Name;
                string namespaceName = type.Namespace;

                PropertyInfo[] properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
                var propertiesWithGet = properties.Where(p => p.GetGetMethod() != null);
                var propertyValues = propertiesWithGet.Select(p => $"{p.Name}: {p.GetValue(this)}");

                return $"Class: {className}\n   Namespace: {namespaceName}\n    Properties: \n      {string.Join("\n      ", propertyValues)}";
            }
        }

        public class DongniRole
        {
            public DongniUser User { get; }
            public string RoleSort { get; }
            public string ClassId { get; }
            public string ClassName { get; }
            public string GradeId { get; }
            public string GradeName { get; }
            public string RelativeId { get; }
            public string SchoolId { get; }
            public string SchoolName { get; }
            public string StudentId { get; }
            public string StudentName { get; }
            public string UserType { get; }

            public DongniRole(DongniUser user, string roleSort, string classId, string className, string gradeId, string gradeName, string relativeId, string schoolId, string schoolName, string studentId, string studentName, string userType)
            {
                this.User = user;
                this.RoleSort = roleSort;
                this.ClassId = classId;
                this.ClassName = className;
                this.GradeId = gradeId;
                this.GradeName = gradeName;
                this.RelativeId = relativeId;
                this.SchoolId = schoolId;
                this.SchoolName = schoolName;
                this.StudentId = studentId;
                this.StudentName = studentName;
                this.UserType = userType;
            }


            public async Task<DongniExam[]> GetLatest()
            {
                try
                {
                    string url = $"https://www.dongni100.com/api/exam/plan/student/latest?clientType=1&examType=2,3,4,5,7,9,10&userId={User.UserId}&studentId={StudentId}";
                    string response = await GetResponse(url, User.Token);

                    WriteLog("DongniRole.GetLatest | RSRR: " + response, isDebug: true);

                    WriteLog("DongniRole.GetLatest: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);

                    if (json["status"].ToString() == "0")
                    {
                        DongniExam firstExam = new DongniExam(
                            this,
                            (string)json["data"][0]["examId"],
                            (string)json["data"][0]["examName"],
                            (string)json["data"][0]["examType"],
                            (string)json["data"][0]["startDate"],
                            (string)json["data"][0]["endDate"]
                            );
                        WriteLog("DongniRole.GetLatest: Parsed 1st exam.", isDebug: true);
                        DongniExam secondExam = new DongniExam(
                            this,
                            (string)json["data"][1]["examId"],
                            (string)json["data"][1]["examName"],
                            (string)json["data"][1]["examType"],
                            (string)json["data"][1]["startDate"],
                            (string)json["data"][1]["endDate"]
                            );
                        WriteLog("DongniRole.GetLatest: Parsed 2st exam.", isDebug: true);

                        return [firstExam, secondExam];
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniRole.GetLatest Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniRole.GetLatest Method.", ex));
                }
                return null;
            }

            public async Task<DongniExam[]> GetList()
            {
                try
                {
                    string url = $"https://www.dongni100.com/api/exam/plan/student/exam/list?clientType=1&schoolId={SchoolId}&examType=2,3,4,5,7,10&pageSize=100&pageNo=1&userId={User.UserId}&studentId={StudentId}";
                    string response = await GetResponse(url, User.Token);

                    WriteLog("DongniRole.GetList | RSRR: " + response, isDebug: true);

                    WriteLog("DongniRole.GetList: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"].ToString() == "0")
                    {
                        List<DongniExam> dongniExams = new List<DongniExam>();

                        for(int i = 0; i < json["data"]["exam"].Count(); i++)
                        {
                            DongniExam dongniExam = new DongniExam(
                                this,
                                (string)json["data"]["exam"][i]["examId"],
                                (string)json["data"]["exam"][i]["examName"],
                                (string)json["data"]["exam"][i]["examType"],
                                (string)json["data"]["exam"][i]["startDate"],
                                (string)json["data"]["exam"][i]["endDate"]
                                );
                            dongniExams.Add(dongniExam);
                            WriteLog($"DongniRole.GetList: Parsed {dongniExams.Count} exams.", isDebug: true);
                        }

                        return dongniExams.ToArray();
                    }
                    else
                    {
                        throw new APIException("Coursed by: Cannot get specified user information.\n\nRemote server responsed: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniUser.SelectRole Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniUser.SelectRole Method.", ex));
                }
                return null;
            }

            public override string ToString()
            {
                Type type = this.GetType();
                string className = type.Name;
                string namespaceName = type.Namespace;

                PropertyInfo[] properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
                var propertiesWithGet = properties.Where(p => p.GetGetMethod() != null);
                var propertyValues = propertiesWithGet.Select(p => $"{p.Name}: {p.GetValue(this)}");

                return $"Class: {className}\n   Namespace: {namespaceName}\n    Properties: \n      {string.Join("\n      ", propertyValues)}";
            }
        }

        public class DongniExam
        {
            public DongniRole Role { get; }
            public string ExamId { get;  }
            public string ExamName { get; }
            public string ExamType { get; }
            public string StartDate { get; }
            public string EndDate { get; }

            /// <summary>
            /// 构造一个DongniExam。
            /// </summary>
            /// <param name="role">该Exam所属的DongniRole</param>
            /// <param name="examId"></param>
            /// <param name="examName"></param>
            /// <param name="examType">考试类型ID</param>
            /// <param name="startDate">开始时间，为13位北京时间时间戳</param>
            /// <param name="endDate">结束时间，为13位北京时间时间戳</param>
            public DongniExam(DongniRole role, string examId, string examName, string examType, string startDate, string endDate)
            {
                this.Role = role;
                this.ExamId = examId;
                this.ExamName = examName;
                this.ExamType = examType;
                this.StartDate = startDate;
                this.EndDate = endDate;
            }

            public async Task<(string, string)> GetScore()
            {
                try
                {
                    string url = $"https://www.dongni100.com/api/analysis/view/monitor/exam/school/scoreSection?clientType=1&courseId=&examId={ExamId}&statId={await GetDefaultStatId()}&classId={Role.ClassId}&schoolId={Role.SchoolId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);

                    JObject json = JObject.Parse(response);
                    if (json["status"].ToString() == "0")
                    {
                        string fullMark = (string)json["data"]["fullMark"];
                        string totalScore = (string)json["data"]["totalScore"];

                        return (fullMark, totalScore);
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responsed: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.GetScore Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.GetScore Method.", ex));
                }
                return (null, null);
            }

            public async Task<(string, string)> GetScore(string statId)
            {
                try
                {
                    string url = $"https://www.dongni100.com/api/analysis/view/monitor/exam/school/scoreSection?clientType=1&courseId=&examId={ExamId}&statId={statId}&classId={Role.ClassId}&schoolId={Role.SchoolId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);

                    JObject json = JObject.Parse(response);
                    if (json["status"].ToString() == "0")
                    {
                        string fullMark = (string)json["data"]["fullMark"];
                        string totalScore = (string)json["data"]["totalScore"];

                        return (fullMark, totalScore);
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responsed: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.GetScore Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.GetScore Method.", ex));
                }
                return (null, null);
            }

            private async Task<string> GetDefaultStatId()
            {

                try
                {
                    string url = $"https://www.dongni100.com/api/analysis/data/exam/student/weChat/all/examStatId?clientType=1&examId={ExamId}&schoolId={Role.SchoolId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetDeafultStatId | RSRR: " + response, isDebug: true);

                    WriteLog("DongniExam.GetDeafultStatId: Trying to parse... ", isDebug: true);
                    JObject json = JObject.Parse(response);

                    if (json["status"].ToString() == "0")
                    {
                        return json["data"]["statId"].ToString();
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responsed: " + response);

                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.GetDefaultStatId Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.GetDefaultStatId Method.", ex));
                }
                return null;
            }

            public override string ToString()
            {
                Type type = this.GetType();
                string className = type.Name;
                string namespaceName = type.Namespace;

                PropertyInfo[] properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
                var propertiesWithGet = properties.Where(p => p.GetGetMethod() != null);
                var propertyValues = propertiesWithGet.Select(p => $"{p.Name}: {p.GetValue(this)}");

                return $"Class: {className}\n   Namespace: {namespaceName}\n    Properties: \n      {string.Join("\n      ", propertyValues)}";
            }
        }




        /// <summary>
        /// 向服务器发起带有 Dongni-login 请求头的GET请求。
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
        /// 向服务器发起不具有其它请求头的GET请求，通用方法。
        /// </summary>
        /// <param name="url">欲发送请求的URL</param>
        /// <returns>返回服务器的Response</returns>
        private static async Task<string> GetResponse(string url)
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(url);
                string responseContent = await response.Content.ReadAsStringAsync();
                return responseContent;
            }
        }

        /// <summary>
        /// 向服务器发起POST请求。
        /// </summary>
        /// <param name="url">欲发送请求的URL</param>
        /// <param name="postContent">欲POST的内容 (请求体)</param>
        /// <param name="contentType">请求体内容类型</param>
        /// <returns>返回服务器的Response。</returns>
        private static async Task<string> PostRequest(string url, string postContent, string contentType)
        {
            using (HttpClient client = new HttpClient())
            {
                StringContent content = new StringContent(postContent, Encoding.UTF8, contentType);
                HttpResponseMessage response = await client.PostAsync(url, content);
                string responseContent = await response.Content.ReadAsStringAsync();
                return responseContent;
            }
        }

        /// <summary>
        /// 写入日志，如果要修改日志的输出方式，请修改这个函数的代码。默认是向控制台输出日志信息。
        /// </summary>
        /// <param name="message">欲输出的日志内容</param>
        /// <param name="eventType">日志信息的类型 (例如INFO、WARNING等, 默认为INFO)</param>
        /// <param name="isDebug">是否是Debug类型。如果为true，则仅在全局debugging == true时输出。默认为false。</param>
        private static void WriteLog(string message, string eventType = "INFO", bool isDebug = false)
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
        public static void SetDebug(bool debug)
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
