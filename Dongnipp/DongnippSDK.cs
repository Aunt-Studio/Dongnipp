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
    Learn more: https://github.com/Aunt-Studio/Dongnipp
    */

    class DongnippSDK
    {
        public static bool debugging;
        public static string Version = "V0.0.0 Developing";//全局版本号
        class DongniUser
        {
            public string accountName { get; private set; }
            public string token { get; private set; }
            public string nickName { get; private set; }
            public string userId { get; private set; }
            private bool isLogon;

            private DongniUser(string accountName, string token, string nickName, string userId)
            {
                this.accountName = accountName;
                this.token = token;
                this.nickName = nickName;
                this.userId = userId;
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

                    RSAParameters dongniPublicKey = RSAUtils.GetPublicKeyParameters("-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCphVCsMh1khU8W0l1WBu0RHTprNr+e2iO0+lLdx+I0tAzCj7jdr5h+tcqZazFuwa751wuegYb0XDbm+/Ti7mWH/Etm+Qc9c5+dBZGzEH0zH8f1cV8EfU8qcsNtn/ixAS7HDl0nzhzlATmH8iFa3l2dYoMBxUZV6Bpyj+gSWg+Y5QIDAQAB-----END PUBLIC KEY-----");

                    encUserName = RSAUtils.EncryptToBase64(dongniPublicKey, Encoding.Default.GetBytes(userName));
                    encPassword = RSAUtils.EncryptToBase64(dongniPublicKey, Encoding.Default.GetBytes(password));

                    postContent = "{\"accountName\":\"" + encUserName + "\",\"password\":\"" + encPassword + "\",\"validate\":null,\"userId\":null,\"clientType\":1}";
                    serverResponse = await PostRequest("https://www.dongni100.com/api/base/data/encrypt/login", postContent, "application/json");

                    writeLog("DongniUser.Login() | Server Resopnse: " + serverResponse, "Server Response", true);

                    JObject json = JObject.Parse(serverResponse);
                    string status = json["status"].ToString();

                    if (status == "0")
                    {
                        token = json["data"]["dongniLoginToken"].ToString();
                        accountName = json["data"]["accountName"].ToString();
                        nickName = json["data"]["userName"].ToString();
                        userId = json["data"]["userId"].ToString();

                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nThe server responsed: " + serverResponse);

                    }

                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at Dongnipp.login Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at Dongnipp.login Method.", ex));
                }
                if (accountName != string.Empty && token != string.Empty && nickName != string.Empty && userId != string.Empty)
                {
                    return new DongniUser(accountName, token, nickName, userId);
                }
                return null;
            }
        }

        class DongniRole
        {
            public DongniUser user { get; private set; }
            public string classId { get; private set; }
            public string className { get; private set; }
            public string gradeId { get; private set; }
            public string gradeName { get; private set; }
            public string relativeId { get; private set; }
            public string schoolId { get; private set; }
            public string schoolName { get; private set; }
            public string studentId { get; private set; }
            public string studentName { get; private set; }
            public string userType { get; private set; }

            public DongniRole(DongniUser user, string classId, string className, string gradeId, string gradeName, string relativeId, string schoolId, string schoolName, string studentId, string studentName, string userType)
            {
                this.user = user;
                this.classId = classId;
                this.className = className;
                this.gradeId = gradeId;
                this.gradeName = gradeName;
                this.relativeId = relativeId;
                this.schoolId = schoolId;
                this.schoolName = schoolName;
                this.studentId = studentId;
                this.studentName = studentName;
                this.userType = userType;
            }
        }

        class DongniExam
        {
            public DongniRole role { get; private set; }
            public string examId { get; private set; }
            public string examName { get; private set; }
            public string examType { get; private set; }
            public string startDate { get; private set; }
            public string endDate { get; private set; }
            public string defaultStatId { get; private set; }

            public DongniExam(DongniRole role, string examId, string examName, string examType, string startDate, string endDate, string defaultStatId)
            {
                this.role = role;
                this.examId = examId;
                this.examName = examName;
                this.examType = examType;
                this.startDate = startDate;
                this.endDate = endDate;
                this.defaultStatId = defaultStatId;
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
