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
                    encPassword = RSAUtils.EncryptToBase64(publicKey, Encoding.Default.GetBytes(password));

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

    }
}
