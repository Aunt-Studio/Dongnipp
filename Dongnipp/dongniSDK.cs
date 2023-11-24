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

namespace Dongnipp
{
    internal class dongniSDK
    {
        private static RSAParameters publicKey; // 全局RSA公钥
        public static async Task<(string Token, string userId, string studentId, string userName, string accountName, string errorInfo)> dongni_login(string username, string password)
        {
            //登录懂你平台，并获取查询需要用的各种参数数据。
            //返回值 string errorInfo 出现错误则存在返回，无错误(status = 0)返回NULL =_=
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

            Console.WriteLine("dongni_login Back: " + back);

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

        public static async Task<(string, string)> getSchoolInfo(string token)
        {
            string schoolId = "";
            string schoolName = "";

            string URL = "https://www.dongni100.com/api/base/data/account/role?clientType=1";
            string back = await GetResponse(URL, token);

            Console.WriteLine("GettingSchoolInfo Back: " + back);

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
    }
}
