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
    Developed by Aunt Studio
    Also see this: https://github.com/Aunt-Studio/Dongnipp
    */

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

            if (status == "0")
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
            else
            {
                errorInfo = "服务器返回错误。JSON返回：" + back;
                Token = accountName = userName = userId = targetStudentId = null;

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

        /// <summary>
        /// 获取该studentId下所有考试列表(实际为前100个)，以各考试属性数组形式返回。| 通常而言，数组下标越接近于0，则考试时间越接近。
        /// </summary>
        /// <param name="Token">登录时获取的用户 Token</param>
        /// <param name="userId">登录时获取的用户 userId</param>
        /// <param name="studentId">待获取列表的studentId</param>
        /// <param name="SchoolId">目标学校schoolId。必须使用getRoleInfo() 获取。</param>
        /// <returns>各考试属性值。以数组形式返回。</returns>
        public static async Task<(string[] examName, string[] examId, string[] examType, string[] startDate, string[] endDate)> getExamList(string Token, string userId, string studentId, string SchoolId)
        {
            string URL = $"https://www.dongni100.com/api/exam/plan/student/exam/list?clientType=1&schoolId={SchoolId}&examType=2,3,4,5,7,10&courseId=&pageSize=100&pageNo=1&userId=" + userId + "&studentId=" + studentId;
            string back = await GetResponse(URL, Token);

            writeLog("Getting Exam List Back = " + back, "Server Back", true);

            JObject json = JObject.Parse(back);
            string status = json["status"].ToString();
            writeLog("Start writing list.", isDebug: true);
            List<string> List_examName = new List<string> ();
            List<string> List_examId = new List<string> ();
            List<string> List_examType = new List<string> ();
            List<string> List_startDate = new List<string> ();
            List<string> List_endDate = new List<string> ();
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
                writeLog("An error occurred while getting exam list: \n\nStatus value is not 0.\n\n Server return: " + back, "Error");
            }
            return (List_examName.ToArray(), List_examId.ToArray(), List_examType.ToArray(), List_startDate.ToArray(), List_endDate.ToArray());
        }


        /// <summary>
        /// 获取当前用户下的第{Sort}个角色信息。通常Sort = 0取到的是默认角色信息。角色信息包含SchoolId、学校名称、班级名称等。本函数在查询列表、需要切换角色等场景下会使用到。
        /// </summary>
        /// <param name="token">登录时收到的Token</param>
        /// <returns></returns>
        public static async Task<(string schoolId, string schoolName, string className, string gradeName, string studentName, string classNickname, string userType, string userName)> getRoleInfo(string token, int Sort)
        {

            string URL = "https://www.dongni100.com/api/base/data/account/role?clientType=1";
            string back = await GetResponse(URL, token);

            writeLog("GettingSchoolInfo Back: " + back, "Server Back", true);
            
            JObject json = JObject.Parse(back);
            string status = json["status"].ToString();
            JArray userList = (JArray)json["data"][0]["userList"];

            if (status == "0")
            {

                foreach (JObject user in userList)
                {
                    if ((int)user["userSort"] == Sort)
                    {
                        JObject selectedUser = user;
                    }
                    if (user != null)
                    {
                        string schoolId = (string)user["schoolId"];
                        string schoolName = (string)user["schoolName"];
                        string className = (string)user["className"];
                        string gradeName = (string)user["gradeName"];
                        string studentName = (string)user["studentName"];
                        string classNickname = (string)user["nickname"];
                        string userType = (string)user["userType"];
                        string userName = (string)user["userName"];
                        return (schoolId, schoolName, className, gradeName, studentName, classNickname, userType, userName);
                    }
                    else
                    {
                        writeLog("An error occurred while getSchoolInfo: \n\nCannot get specified user infomations.\n\n Server returned: " + back, "Error");
                    }
                }
            }
            else
            {
                
                writeLog("An error occurred while getSchoolInfo: \n\nStatus value is not 0.\n\n Server returned: " + back, "Error");
                return (null, null, null, null, null, null, null, null);
            }
            return (null, null, null, null, null, null, null, null);


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
