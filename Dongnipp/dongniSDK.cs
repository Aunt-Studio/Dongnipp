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

namespace top.nuozhen.Dongnipp
{
    internal class dongniSDK
    {
        private static RSAParameters publicKey; // 全局RSA公钥Parameters
        private static bool debugging;
        /// <summary>
        /// 登录懂你平台，并获取查询需要用的各种参数数据。
        /// 
        /// 
        /// </summary>
        /// <param name="username">用户名 (应该是手机号)</param>
        /// <param name="password">密码</param>
        /// <returns>返回值 string errorInfo 出现错误则存在返回，无错误(status == 0)返回NULL =_=</returns>
        public static async Task<(string Token, string userId, string studentId, string userName, string accountName, string errorInfo)> login(string username, string password)
        {

            string errorInfo;
            string accountName;
            string userName;
            string userId;
            string targetStudentId;
            string post;
            string back;
            string back_stuid;
            string aN;
            string pw;
            string Token;

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

            if (status != "0")
            {
                errorInfo = "服务器返回错误。JSON返回：" + back;
                Token = accountName = userName = userId = targetStudentId = null;
            }
            else
            {
               
                Token = json["data"]["dongniLoginToken"].ToString();
                accountName = json["data"]["accountName"].ToString();
                userName = json["data"]["userName"].ToString();
                userId = json["data"]["userId"].ToString();

                back_stuid = await GetResponse("https://www.dongni100.com/api/base/data/account/role?clientType=1", Token);

                JObject json_stuid = JObject.Parse(back_stuid);

                int lastIndex = json_stuid["data"][0]["userList"].Count() - 1;
                targetStudentId = json_stuid["data"][0]["userList"][lastIndex]["studentId"].ToString();
                

                json_stuid = null;
                errorInfo = null;
            }

            json = null;

            return (Token, userId, targetStudentId, userName, accountName, errorInfo);
        }
        /// <summary>
        /// 获取最近两次考试信息。
        /// </summary>
        /// <param name="Token">登录时获取的用户 Token</param>
        /// <param name="userId">登录时获取的用户 userId</param>
        /// <param name="studentId">登录时获取的 studentId</param>
        /// <param name="status">状态值，非0即错误</param>
        /// <returns>返回的两个变量数组: 
        /// {1.考试名称, 2.考试ID, 3.考试类型ID, 4.考试开始日期, 5.考试结束日期}</returns>
        public static async Task<(string[] firstExam, string[] secondExam, string status)> getLatest(string Token, string userId, string studentId)
        {
            string[] firstExam = { "", "", "", "", "" };
            //{1.考试名称, 2.考试ID, 3.考试类型ID, 4.考试开始日期, 5.考试结束日期}
            string[] secondExam = { "", "", "", "", "" };

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
                
            }
            return (firstExam, secondExam, status);
        }
        public static async Task<(string, string)> getSchoolInfo(string token)
        {
            string schoolId = "";
            string schoolName = "";

            string URL = "https://www.dongni100.com/api/base/data/account/role?clientType=1";
            string back = await GetResponse(URL, token);

            writeLog("GettingSchoolInfo Back: " + back, "Server Back", true);

            JObject json = JObject.Parse(back);
            string status = json["status"].ToString();

            if (status == "0")
            {
                int userListCount = json["data"][0]["userList"].Count();
                int lastIndex = userListCount - 1;

                schoolId = json["data"][0]["userList"][lastIndex]["schoolId"].ToString();
                schoolName = json["data"][0]["userList"][lastIndex]["schoolName"].ToString();
            }
            else
            {
                schoolId = "0";
                schoolName = "Error, back=" + back;
                writeLog("Error while getSchoolInfo. Server returned: " + back, "Error");
            }
            return (schoolId, schoolName);
        }

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
        private static void writeLog(string message,string eventType="INFO",  bool isDebug=false) { 
            if(isDebug && debugging)
            {
                Console.WriteLine($"[Debug / {eventType}] " + message);
            }else if(!isDebug) { 
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
    }
}
