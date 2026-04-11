using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using ICSharpCode.SharpZipLib.GZip;
using Org.BouncyCastle.Ocsp;
using Microsoft.Extensions.Caching.Memory;
using System.Net.Http.Headers;

namespace com.auntstudio.Dongnipp.SDK
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
    V4.0.11 Stable
    Developed by Aunt Studio
    Learn more: https://github.com/Aunt-Studio/Dongnipp
    */

    /// <summary>
    /// Dongni++ SDK 主类。
    /// </summary>
    public class DongnippSDK
    {
        /// <summary>
        /// 定义一个委托，用于自定义日志输出方法。
        /// </summary>
        /// <param name="message"></param>
        /// <param name="eventType"></param>
        /// <param name="isDebug"></param>
        public delegate void LogHandler(string message, string eventType, bool isDebug);
        /// <summary>
        /// 存储自定义日志输出方法的静态字段。
        /// </summary>
        public static LogHandler? CustomLogHandler;

        /// <summary>
        /// 调试信息输出开关，控制是否在控制台中输出调试信息。
        /// </summary>
        public static bool debugging;
        /// <summary>
        /// SDK 版本号。
        /// </summary>
        public static string Version = "V4.0.11 Stable";

        private static APIException BuildMissingFieldException(string fieldName, string serverResponse)
        {
            return new APIException($"Coursed by: Failed to retrieve {fieldName}.\n\nRemote server responded: {serverResponse}");
        }

        private static string RequireString(JToken? token, string fieldName, string serverResponse)
        {
            var value = token?.ToString();
            if (string.IsNullOrEmpty(value))
            {
                throw BuildMissingFieldException(fieldName, serverResponse);
            }

            return value;
        }

        private static JObject RequireObject(JToken? token, string fieldName, string serverResponse)
        {
            if (token is not JObject jsonObject)
            {
                throw BuildMissingFieldException(fieldName, serverResponse);
            }

            return jsonObject;
        }

        private static JArray RequireArray(JToken? token, string fieldName, string serverResponse)
        {
            if (token is not JArray jsonArray)
            {
                throw BuildMissingFieldException(fieldName, serverResponse);
            }

            return jsonArray;
        }

        private static int RequireInt(JToken? token, string fieldName, string serverResponse)
        {
            var value = RequireString(token, fieldName, serverResponse);
            if (!int.TryParse(value, out var number))
            {
                throw new APIException($"Coursed by: {fieldName} is not a valid integer.\n\nRemote server responded: {serverResponse}");
            }

            return number;
        }

        /// <summary>
        /// <see cref="DongniUser"/> 类，用于封装一个已登录的懂你平台用户。
        /// </summary>
        public class DongniUser
        {
            /// <summary>
            /// 懂你平台用户名、密码加密传输所使用的 RSA 公钥。
            /// </summary>
            private const string PublicKey = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCphVCsMh1khU8W0l1WBu0RHTprNr+e2iO0+lLdx+I0tAzCj7jdr5h+tcqZazFuwa751wuegYb0XDbm+/Ti7mWH/Etm+Qc9c5+dBZGzEH0zH8f1cV8EfU8qcsNtn/ixAS7HDl0nzhzlATmH8iFa3l2dYoMBxUZV6Bpyj+gSWg+Y5QIDAQAB-----END PUBLIC KEY-----";

            /// <summary>
            /// 登录后的用户名。通常是手机号。
            /// </summary>
            public string AccountName { get; }
            /// <summary>
            /// 登录后的用户令牌。即接口请求头中的 Dongni-Login 字段。
            /// </summary>
            public string Token { get; }
            /// <summary>
            /// 登录接口返回的 userName，通常是学生姓名。
            /// </summary>
            public string NickName { get; }
            /// <summary>
            /// 登录接口返回的用户 ID。
            /// </summary>
            public string UserId { get; }
            /// <summary>
            /// 预留的登录状态。
            /// </summary>
            public bool IsLogon { get; private set; }
            /// <summary>
            /// 该用户是否升级了好专业平台。
            /// </summary>
            public bool IsNiceZhuanye { get; private set; }
            /// <summary>
            /// 全局懂你平台 API 接口地址。
            /// <para>
            /// 通常是 https://www.dongni100.com ,但如果学校升级了好专业平台, 可能为 https://nicezhuanye.dongni100.com。
            /// </para>
            /// 如果学校有私有 Endpoint 也可以修改该属性。
            /// </summary>
            public string ApiEndpoint { get; private set; }


            /// <summary>
            /// <see cref="DongniUser"/> 的构造函数，不应被外部直接调用，创建 <see cref="DongniUser"/> 实例请使用 <see cref="Login"/> 异步工厂方法。
            /// </summary>
            /// <param name="accountName"></param>
            /// <param name="token"></param>
            /// <param name="nickName"></param>
            /// <param name="userId"></param>
            /// <param name="apiEndpoint"></param>
            /// <param name="isNiceZhuanye"></param>
            private DongniUser(string accountName, string token, string nickName, string userId, string apiEndpoint, bool isNiceZhuanye = false)
            {
                this.AccountName = accountName;
                this.Token = token;
                this.NickName = nickName;
                this.UserId = userId;
                this.IsLogon = true;
                ApiEndpoint = apiEndpoint;
                IsNiceZhuanye = isNiceZhuanye;
            }


            /// <summary>
            /// 登录到懂你平台，获得一个 <see cref="DongniUser"/> 实例。
            /// </summary>
            /// <param name="userName">用户名 (通常是手机号)</param>
            /// <param name="password">明文密码</param>
            /// <returns>DongniUser 实例</returns>
            public static async Task<DongniUser?> Login(string userName, string password)
            {
                try
                {
                    ArgumentException.ThrowIfNullOrWhiteSpace(userName);
                    ArgumentException.ThrowIfNullOrWhiteSpace(password);

                    string apiEndpoint = "https://www.dongni100.com";

                    RSAParameters dongniPublicKey = RSAUtils.GetPublicKeyParameters(PublicKey);

                    string encUserName = RSAUtils.EncryptToBase64(dongniPublicKey, Encoding.Default.GetBytes(userName));
                    string encPassword = RSAUtils.EncryptToBase64(dongniPublicKey, Encoding.Default.GetBytes(password));

                    string postContent = "{\"accountName\":\"" + encUserName + "\",\"password\":\"" + encPassword + "\",\"validate\":null,\"userId\":null,\"clientType\":1}";
                    string serverResponse = await PostRequest("https://www.dongni100.com/api/base/data/encrypt/login", postContent, "application/json");

                    WriteLog("DongniUser.Login | RSRR: " + serverResponse, isDebug: true);

                    JObject json = JObject.Parse(serverResponse);


                    string accountName = string.Empty;
                    string token = string.Empty;
                    string nickName = string.Empty;    //这里的 nickName 是接口返回的 userName，通常是学生姓名
                    string userId = string.Empty;
                    bool isNiceZhuanye = false;
                    if (json["status"]?.ToString() == "0")
                    {
                        var data = RequireObject(json["data"], "data", serverResponse);
                        if (data["hzyFlag"]?.Value<bool>() == true)
                        {
                            // 学校升级好专业平台，切换 API Endpoint。
                            apiEndpoint = "https://nicezhuanye.dongni100.com";
                            isNiceZhuanye = true;
                            var hzyUser = await HzyLogin(userName, password)
                                ?? throw BuildMissingFieldException("hzyUser", serverResponse);
                            WriteLog("DongniUser.Login | Your school has updated to Nicezhuanye platform, which has an other API endpoint.");
                            WriteLog("DongniUser.Login | API Endpoint switched to: " + apiEndpoint, isDebug: true);
                            return await hzyUser.ToDongniUser(hzyUser.RoleType);
                        }
                        else if (data["dongniLoginToken"] is not null)
                        {
                            token = RequireString(data["dongniLoginToken"], "data.dongniLoginToken", serverResponse);
                            accountName = RequireString(data["accountName"], "data.accountName", serverResponse);
                            nickName = RequireString(data["userName"], "data.userName", serverResponse);
                            userId = RequireString(data["userId"], "data.userId", serverResponse);
                        }
                        else
                        {
                            throw new APIException("Coursed by: Failed to retrieve login information.\n\nRemote server responded: " + serverResponse);
                        }

                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + serverResponse);

                    }
                    return new DongniUser(accountName, token, nickName, userId, apiEndpoint, isNiceZhuanye);
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
            enum RoleType
            {
                Student = 0,
                Parent = 2
            }

            private DongniRole BuildRoleFromJson(JObject user, string serverResponse)
            {
                return new DongniRole(
                    this,
                    RequireString(user["userSort"], "userSort", serverResponse),
                    RequireString(user["classId"], "classId", serverResponse),
                    RequireString(user["className"], "className", serverResponse),
                    RequireString(user["gradeId"], "gradeId", serverResponse),
                    RequireString(user["gradeName"], "gradeName", serverResponse),
                    RequireString(user["relativeId"], "relativeId", serverResponse),
                    RequireString(user["schoolId"], "schoolId", serverResponse),
                    RequireString(user["schoolName"], "schoolName", serverResponse),
                    RequireString(user["studentId"], "studentId", serverResponse),
                    RequireString(user["studentName"], "studentName", serverResponse),
                    RequireString(user["userType"], "userType", serverResponse)
                );
            }

            private class HzyUser
            {
                /// <summary>
                /// 好专业平台的 UserId
                /// </summary>
                public required string UserId { get; set; }
                /// <summary>
                /// 好专业平台用户所属的地区 ID
                /// </summary>
                public required string RegionId { get; set; }
                /// <summary>
                /// 好专业平台用户所属的分校 ID
                /// </summary>
                public required string BranchId { get; set; }
                /// <summary>
                /// 好专业平台用户所属的学校 ID
                /// </summary>
                public required string SchoolId { get; set; }
                /// <summary>
                /// 好专业平台用户所属的年段 ID
                /// </summary>
                public required string GradeId { get; set; }
                /// <summary>
                /// 好专业平台用户 System ID，我这里是学籍号
                /// </summary>
                public required string SystemId { get; set; }
                /// <summary>
                /// 好专业平台用户 accessToken
                /// </summary>
                public required string Token { get; set; }
                /// <summary>
                /// 用户身份类别。
                /// </summary>
                public required RoleType RoleType { get; set; }

                public async Task<string?> GetTicketAsync(RoleType? roleType = null)
                {
                    if (roleType is not null)
                    {
                        RoleType = roleType.Value;
                    }
                    string roleTypeStr = RoleType switch
                    {
                        RoleType.Student => "Student",
                        RoleType.Parent => "Parent",
                        _ => throw new APIException("Coursed by: Invalid role type.")
                    };
                    // 构造请求 json
                    JObject parameterJson = new()
                    {
                        ["UserID"] = UserId,
                        ["RegionID"] = RegionId,
                        ["branchId"] = BranchId,
                        ["SchoolID"] = SchoolId,
                        ["gradeId"] = GradeId,
                        ["SystemID"] = SystemId,
                        ["token"] = Token,
                        ["parameter"] = new JObject
                        {
                            ["userID"] = UserId,
                            ["roleType"] = roleTypeStr
                        }
                    };
                    var url = $"https://school.nicezhuanye.com/nicezhuanye/ssoLogin/getTicket?t={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
                    var response = await PostRequest(url, parameterJson.ToString(), "application/json");
                    var responseJson = JObject.Parse(response);
                    if (responseJson["code"]?.ToString() == "0")
                    {
                        return responseJson["result"]?.ToString();
                    }
                    else
                    {
                        throw new APIException("Coursed by: Failed to retrieve ticket from Nicezhuanye platform.\n\nRemote server responded: " + response);
                    }
                }

                public async Task<DongniUser> ToDongniUser(RoleType roleType)
                {
                    var ticket = await GetTicketAsync(roleType)
                        ?? throw new APIException("Coursed by: Failed to retrieve ticket from Nicezhuanye platform.");
                    JObject ssoParameterJson = new()
                    {
                        ["dictKey"] = "nicezhuanye",
                        ["ticket"] = ticket,
                        ["clientType"] = "1"
                    };

                    var url = "https://nicezhuanye.dongni100.com/api/base/data/system/auth/sso";
                    var ssoResponse = await PostRequest(url, ssoParameterJson.ToString(), "application/json");
                    var ssoResponseJson = JObject.Parse(ssoResponse);
                    if (ssoResponseJson["status"]?.ToString() == "0")
                    {
                        var data = ssoResponseJson["data"];
                        return new DongniUser(
                            accountName: data?["accountName"]?.ToString() ?? throw new APIException("Coursed by: Failed to retrieve accountName from Dongni platform.\n\nRemote server responded: " + ssoResponse),
                            token: data?["dongniLoginToken"]?.ToString() ?? throw new APIException("Coursed by: Failed to retrieve dongniLoginToken from Dongni platform.\n\nRemote server responded: " + ssoResponse),
                            nickName: data?["userName"]?.ToString() ?? throw new APIException("Coursed by: Failed to retrieve userName from Dongni platform.\n\nRemote server responded: " + ssoResponse),
                            userId: data?["userId"]?.ToString() ?? throw new APIException("Coursed by: Failed to retrieve userId from Dongni platform.\n\nRemote server responded: " + ssoResponse),
                            apiEndpoint: "https://nicezhuanye.dongni100.com",
                            isNiceZhuanye: true
                        );
                    }
                    else
                    {
                        throw new APIException("Coursed by: Failed to retrieve login information from Dongni platform.\n\nRemote server responded: " + ssoResponse);
                    }
                }
            }

            /// <summary>
            /// 从好专业平台登录。返回<seealso cref="HzyUser"/>.
            /// </summary>
            /// <param name="cellPhone">手机号</param>
            /// <param name="password">密码</param>
            /// <returns></returns>
            private static async Task<HzyUser> HzyLogin(string cellPhone, string password)
            {
                ArgumentException.ThrowIfNullOrWhiteSpace(cellPhone);
                ArgumentException.ThrowIfNullOrWhiteSpace(password);

                // 构造 parameter json
                JObject parameterJson = new JObject
                {
                    ["parameter"] = new JObject
                    {
                        ["cellphone"] = cellPhone,
                        ["pwd"] = password,
                        ["saveCookie"] = false
                    }
                };


                var loginResponse = await PostRequest("https://school.nicezhuanye.com/loginserv/login/login", parameterJson.ToString(),
                                                      "application/json");
                WriteLog("HzyLogin | RSRR: " + loginResponse, isDebug: true);

                var loginJson = JObject.Parse(loginResponse);

                var users = RequireArray(loginJson["result"]?["userList"], "result.userList", loginJson.ToString());
                Console.WriteLine("hzyLogin | Users Count: " + users.Count);
                foreach (var user in users)
                {
                    Console.WriteLine("hzyLogin | User Info: " + user.ToString());
                }
                // 选第一个用户 我也不知道多用户怎么触发的
                var firstUser = users[0];
                if (firstUser is not null)
                {
                    var hzyUser = new HzyUser
                    {
                        UserId = RequireString(firstUser["userID"], "result.userList[0].userID", loginJson.ToString()),
                        RegionId = RequireString(firstUser["regionID"], "result.userList[0].regionID", loginJson.ToString()),
                        BranchId = string.Empty,
                        SchoolId = RequireString(firstUser["schoolID"], "result.userList[0].schoolID", loginJson.ToString()),
                        GradeId = RequireString(firstUser["grade"], "result.userList[0].grade", loginJson.ToString()),
                        SystemId = RequireString(firstUser["systemID"], "result.userList[0].systemID", loginJson.ToString()),
                        Token = RequireString(firstUser["accesstoken"], "result.userList[0].accesstoken", loginJson.ToString()),
                        RoleType = Enum.TryParse<RoleType>(RequireString(firstUser["identity"], "result.userList[0].identity", loginJson.ToString()),
                                                           ignoreCase: true,
                                                           out var roleType) ? roleType : throw new APIException("Coursed by: Failed to retrieve roleType from Nicezhuanye platform.\n\nRemote server responded: " + loginJson.ToString())
                    };
                    return hzyUser;
                }
                else
                {
                    throw new APIException("Coursed by: Failed to retrieve login information from Nicezhuanye platform.\n\nRemote server responded: " + loginJson.ToString());
                }
            }

            // /// <summary>
            // /// 从好专业平台登录。返回<seealso cref="HzyUser"/>.
            // /// </summary>
            // /// <param name="cellPhone">手机号</param>
            // /// <param name="password">密码</param>
            // /// <returns></returns>
            // private static async Task<HzyUser> HzyLogin(string cellPhone, string password)
            // {
            //     ArgumentException.ThrowIfNullOrWhiteSpace(cellPhone);
            //     ArgumentException.ThrowIfNullOrWhiteSpace(password);

            //     // 构造 parameter json
            //     JObject parameterJson = new JObject
            //     {
            //         ["cellphone"] = cellPhone,
            //         ["pwd"] = password,
            //         ["saveCookie"] = false
            //     };

            //     const string hzyKey = "RequestMappingHa";
            //     var encryptedData = Encode(Encoding.UTF8.GetBytes(parameterJson.ToString()), hzyKey);
            //     WriteLog("HzyLogin | Encrypted Data: " + encryptedData, isDebug: true);

            //     var loginResponse = await PostRequest("https://school.nicezhuanye.com/loginserv/login/login", encryptedData,
            //                                           "application/json", new(){{"x-hqjl-ajax", "HQJL"}});
            //     WriteLog("HzyLogin | RSRR: " + loginResponse, isDebug: true);

            //     var loginJson = JObject.Parse(Decode(loginResponse, hzyKey));

            //     var users = RequireArray(loginJson["result"]?["userList"], "result.userList", loginJson.ToString());
            //     Console.WriteLine("hzyLogin | Users Count: " + users.Count);
            //     foreach (var user in users)
            //     {
            //         Console.WriteLine("hzyLogin | User Info: " + user.ToString());
            //     }
            //     // 选第一个用户 我也不知道多用户怎么触发的
            //     var firstUser = users[0];
            //     if (firstUser is not null)
            //     {
            //         var hzyUser = new HzyUser
            //         {
            //             UserId = RequireString(firstUser["userId"], "result.userList[0].userId", loginJson.ToString()),
            //             RegionId = RequireString(firstUser["regionId"], "result.userList[0].regionId", loginJson.ToString()),
            //             BranchId = RequireString(firstUser["branchId"], "result.userList[0].branchId", loginJson.ToString()),
            //             SchoolId = RequireString(firstUser["schoolId"], "result.userList[0].schoolId", loginJson.ToString()),
            //             GradeId = RequireString(firstUser["gradeId"], "result.userList[0].gradeId", loginJson.ToString()),
            //             SystemId = RequireString(firstUser["systemId"], "result.userList[0].systemId", loginJson.ToString()),
            //             Token = RequireString(firstUser["token"], "result.userList[0].token", loginJson.ToString()),
            //             RoleType = Enum.TryParse<RoleType>(RequireString(firstUser["roleType"], "result.userList[0].roleType", loginJson.ToString()),
            //                                                ignoreCase: true,
            //                                                out var roleType) ? roleType : throw new APIException("Coursed by: Failed to retrieve roleType from Nicezhuanye platform.\n\nRemote server responded: " + loginJson.ToString())
            //         };
            //         return hzyUser;
            //     }
            //     else
            //     {
            //         throw new APIException("Coursed by: Failed to retrieve login information from Nicezhuanye platform.\n\nRemote server responded: " + loginJson.ToString());
            //     }




            //     static string Encode(byte[] data, string key)
            //     {
            //         using var ms = new MemoryStream();
            //         using (var gzip = new GZipOutputStream(ms))
            //         {
            //             gzip.SetLevel(6);
            //             gzip.Write(data, 0, data.Length);
            //             gzip.Finish();
            //         }
            //         var zippedData = ms.ToArray();


            //         using var aes = Aes.Create();
            //         aes.Mode = CipherMode.ECB;
            //         aes.Padding = PaddingMode.PKCS7;
            //         aes.Key = Encoding.UTF8.GetBytes(key);
            //         using var encryptor = aes.CreateEncryptor();
            //         var encrypted = encryptor.TransformFinalBlock(zippedData, 0, zippedData.Length);

            //         return Convert.ToBase64String(encrypted);
            //     }
            //     static string Decode(string b64Data, string key)
            //     {
            //         var encrypted = Convert.FromBase64String(b64Data);

            //         // AES-ECB 解密
            //         byte[] decrypted;
            //         using (var aes = Aes.Create())
            //         {
            //             aes.Mode = CipherMode.ECB;
            //             aes.Padding = PaddingMode.PKCS7;
            //             aes.Key = Encoding.UTF8.GetBytes(key);

            //             using var decryptor = aes.CreateDecryptor();
            //             decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
            //         }

            //         // inflate 解压（关键：SharpZipLib.GZip）
            //         using var input = new MemoryStream(decrypted);
            //         using var gzip = new GZipInputStream(input);
            //         using var output = new MemoryStream();

            //         gzip.CopyTo(output);

            //         return Encoding.UTF8.GetString(output.ToArray());
            //     }
            // }

            /// <summary>
            /// 向懂你平台发送登出请求以销毁当前 <see cref="DongniUser"/> 实例中的 <see cref="Token"/>。
            /// </summary>
            /// <returns></returns>
            public async Task Logout()
            {
                try
                {
                    string url = $"{ApiEndpoint}/api/base/data/logout";
                    string serverResponse;
                    using (HttpClient client = new HttpClient())
                    {
                        StringContent content = new StringContent("");
                        client.DefaultRequestHeaders.Add("Dongni-Login", Token);
                        HttpResponseMessage response = await client.PostAsync(url, content);
                        serverResponse = await response.Content.ReadAsStringAsync();
                    }
                    WriteLog("DongniUser.Logout | RSRR: " + serverResponse, isDebug: true);

                    JObject json = JObject.Parse(serverResponse);


                    if (json["status"]?.ToString() == "0")
                    {
                        IsLogon = false;

                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + serverResponse);

                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniUser.Logout Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniUser.Logout Method.", ex));
                }

            }

            /// <summary>
            /// 获取当前用户的所有角色。
            /// </summary>
            /// <returns><see cref="DongniRole"/> 实例数组</returns>
            public async Task<DongniRole[]> ListRole()
            {

                try
                {
                    string url = $"{ApiEndpoint}/api/base/data/account/role?clientType=1";
                    string response = await GetResponse(url, Token);
                    WriteLog("DongniUser.ListRole | RSRR: " + response, isDebug: true);

                    WriteLog("DongniUser.ListRole: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);

                    if (json["status"]?.ToString() == "0")
                    {
                        List<DongniRole> roles = [];
                        var data = RequireArray(json["data"], "data", response);
                        foreach (JObject account in data.Cast<JObject>())
                        {
                            var userList = RequireArray(account["userList"], "data[].userList", response);
                            foreach (JObject user in userList.Cast<JObject>())
                            {
                                DongniRole role = BuildRoleFromJson(user, response);

                                roles.Add(role);
                                WriteLog($"DongniUser.ListRole: Already parsed {roles.Count} roles.", isDebug: true);
                            }
                        }
                        return ([.. roles]);
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
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
                return [];
            }

            /// <summary>
            /// 利用 <paramref name="roleSort"/> 选择一个角色。
            /// 
            /// 将会先请求API枚举所有角色信息，并逐一匹配 <paramref name="roleSort"/> 是否等于某个角色的 userSort。
            /// 通常情况下 <paramref name="roleSort"/> = 0 取得的是默认角色。
            /// </summary>
            /// <param name="roleSort">已转换为整数类型的 roleSort</param>
            /// <returns><see cref="DongniRole"/> 实例</returns>
            public async Task<DongniRole> SelectRole(int roleSort)
            {

                try
                {
                    if (IsNiceZhuanye) roleSort += 1;

                    string url = $"{ApiEndpoint}/api/base/data/account/role?clientType=1";
                    string response = await GetResponse(url, Token);
                    WriteLog("DongniUser.SelectRole | RSRR: " + response, isDebug: true);

                    WriteLog("DongniUser.ListRole: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);


                    if (json["status"]?.ToString() == "0")
                    {
                        JObject? selectedUser = null;
                        var userList = RequireArray(json["data"]?[0]?["userList"], "data[0].userList", response);

                        foreach (JObject user in userList.Cast<JObject>())
                        {
                            if (RequireString(user["userSort"], "userSort", response) == roleSort.ToString())
                            {
                                selectedUser = user;
                                break;
                            }
                        }
                        if (selectedUser != null)
                        {
                            return BuildRoleFromJson(selectedUser, response);
                        }
                        else
                        {
                            throw new APIException("Coursed by: Cannot get specified user information.\n\nRemote server responded: " + response);

                        }
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
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
                throw new APIException("Coursed by: Cannot get specified user information.");
            }

            /// <summary>
            /// 利用 <paramref name="roleSort"/> 选择一个角色。
            /// 
            /// 将会先请求API枚举所有角色信息，并逐一匹配 <paramref name="roleSort"/> 是否等于某个角色的 userSort。
            /// 通常情况下 <paramref name="roleSort"/> = 0 取得的是默认角色。
            /// </summary>
            /// <param name="roleSort">字符串类型的 roleSort</param>
            /// <returns><see cref="DongniRole"/> 实例</returns>
            public async Task<DongniRole> SelectRole(string roleSort)
            {

                try
                {
                    string url = $"{ApiEndpoint}/api/base/data/account/role?clientType=1";
                    string response = await GetResponse(url, Token);
                    WriteLog("DongniUser.SelectRole | RSRR: " + response, isDebug: true);

                    WriteLog("DongniUser.ListRole: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);


                    if (json["status"]?.ToString() == "0")
                    {
                        JObject? selectedUser = null;
                        var userList = RequireArray(json["data"]?[0]?["userList"], "data[0].userList", response);

                        foreach (JObject user in userList.Cast<JObject>())
                        {
                            if (RequireString(user["userSort"], "userSort", response) == roleSort)
                            {
                                selectedUser = user;
                                break;
                            }
                        }
                        if (selectedUser != null)
                        {
                            return BuildRoleFromJson(selectedUser, response);
                        }
                        else
                        {
                            throw new APIException("Coursed by: Cannot get specified user information.\n\nRemote server responded: " + response);

                        }
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
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
                throw new APIException("Coursed by: Cannot get specified user information.");
            }

            /// <summary>
            /// 利用 <paramref name="roleSort"/> 以及一个以 <paramref name="roleSort"/> 为数组下标的 <see cref="DongniRole"/> 实例数组选择一个角色。需要与 <see cref="ListRole"/> 方法配合使用。
            /// 
            /// 注意: 不推荐使用此方法。因为该方法可能会选择预期外的 <see cref="DongniRole"/> 实例。
            /// 但该方法不需要联网。
            /// </summary>
            /// <param name="roleArrow">以 <paramref name="roleSort"/> 为数组下标的 <see cref="DongniRole"/> 实例数组</param>
            /// <param name="roleSort">已转换为整数类型的 roleSort</param>
            /// <returns><paramref name="roleArrow"/>[<paramref name="roleSort"/>]</returns>
            public static DongniRole SelectRole(DongniRole[] roleArrow, int roleSort)
            {
                try
                {
                    ArgumentNullException.ThrowIfNull(roleArrow);

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
                throw new APIException("Coursed by: Failed to select role by roleSort.");
            }

            /// <summary>
            /// 利用 <paramref name="roleSort"/> 以及一个以 <paramref name="roleSort"/> 为数组下标的 <see cref="DongniRole"/> 实例数组选择一个角色。需要与 <see cref="ListRole"/> 方法配合使用。
            /// 
            /// 注意: 不推荐使用此方法。因为该方法可能会选择预期外的 DongniRole 实例，并且类型转换错误将抛出异常。
            /// 但该方法不需要联网。
            /// </summary>
            /// <param name="roleArrow">以 roleSort 为数组下标的 DongniRole 实例数组</param>
            /// <param name="roleSort">字符串类型的 roleSort</param>
            /// <returns>roleArrow[roleSort]</returns>
            public static DongniRole SelectRole(DongniRole[] roleArrow, string roleSort)
            {
                try
                {
                    ArgumentNullException.ThrowIfNull(roleArrow);
                    ArgumentException.ThrowIfNullOrWhiteSpace(roleSort);

                    int sort = 0;
                    if (!int.TryParse(roleSort, out sort))
                    {
                        throw new APIException($"Coursed by: The passed parameter \"roleSort\" cannot be converted to an integer type.\nroleSort = {roleSort}");
                    }
                    return SelectRole(roleArrow, sort);
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniUser.SelectRole Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniUser.SelectRole Method.", ex));
                }
                throw new APIException("Coursed by: Failed to select role by roleSort.");
            }


            /// <summary>
            /// 枚举类的信息和属性等。
            /// </summary>
            /// <returns>类的名称、所属命名空间、所有属性列表。</returns>
            public override string ToString()
            {
                Type type = this.GetType();
                string className = type.Name;
                string namespaceName = type.Namespace ?? string.Empty;

                PropertyInfo[] properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
                var propertiesWithGet = properties.Where(p => p.GetGetMethod() != null);
                var propertyValues = propertiesWithGet.Select(p => $"{p.Name}: {p.GetValue(this)}");

                return $"Class: {className}\n   Namespace: {namespaceName}\n    Properties: \n      {string.Join("\n      ", propertyValues)}";
            }
        }

        /// <summary>
        /// 一个懂你平台账户角色。
        /// </summary>
        public class DongniRole
        {
            /// <summary>
            /// 角色所属的 <see cref="DongniUser"/> 实例
            /// </summary>
            public DongniUser User { get; }
            /// <summary>
            /// 角色的序号
            /// </summary>
            public string RoleSort { get; }
            /// <summary>
            /// 角色所属的班级的 ID
            /// </summary>
            public string ClassId { get; }
            /// <summary>
            /// 角色所属的班级的名称
            /// </summary>
            public string ClassName { get; }
            /// <summary>
            /// 角色所属的年段的 ID
            /// </summary>
            public string GradeId { get; }
            /// <summary>
            /// 角色所属的年段的名称
            /// </summary>
            public string GradeName { get; }
            /// <summary>
            /// 角色亲戚ID，例如该角色为家长，则该值为家长角色的 ID
            /// </summary>
            public string RelativeId { get; }
            /// <summary>
            /// 角色所属的学校 ID
            /// </summary>
            public string SchoolId { get; }
            /// <summary>
            /// 角色所属的学校名称
            /// </summary>
            public string SchoolName { get; }
            /// <summary>
            /// 角色关联的学生 ID
            /// </summary>
            public string StudentId { get; }
            /// <summary>
            /// 角色关联的学生姓名
            /// </summary>
            public string StudentName { get; }
            /// <summary>
            /// 角色类型。
            /// </summary>
            public string UserType { get; }

            /// <summary>
            /// <see cref="DongniRole"/> 的构造函数。通常不需要手动调用，但假如遇到无网情况可以通过这个方法从缓存中构造对象。
            /// </summary>
            /// <param name="user">角色所属的 <see cref="DongniUser"/> 实例</param>
            /// <param name="roleSort"></param>
            /// <param name="classId"></param>
            /// <param name="className"></param>
            /// <param name="gradeId"></param>
            /// <param name="gradeName"></param>
            /// <param name="relativeId"></param>
            /// <param name="schoolId"></param>
            /// <param name="schoolName"></param>
            /// <param name="studentId"></param>
            /// <param name="studentName"></param>
            /// <param name="userType"></param>
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

            private DongniExam BuildExamFromJson(JObject exam, string serverResponse)
            {
                return new DongniExam(
                    this,
                    RequireString(exam["examId"], "examId", serverResponse),
                    RequireString(exam["examName"], "examName", serverResponse),
                    RequireString(exam["examType"], "examType", serverResponse),
                    RequireString(exam["startDate"], "startDate", serverResponse),
                    RequireString(exam["endDate"], "endDate", serverResponse)
                );
            }

            /// <summary>
            /// 获取最近数次的考试结果。
            /// </summary>
            /// <returns><see cref="DongniExam"/> 实例数组</returns>
            public async Task<DongniExam[]> GetLatest()
            {
                try
                {
                    string url = $"{User.ApiEndpoint}/api/exam/plan/student/latest?clientType=1&examType=2,3,4,5,7,9,10&userId={User.UserId}&studentId={StudentId}";
                    if (User.IsNiceZhuanye) url += $"&schoolId={SchoolId}";

                    string response = await GetResponse(url, User.Token);

                    WriteLog("DongniRole.GetLatest | RSRR: " + response, isDebug: true);

                    WriteLog("DongniRole.GetLatest: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);

                    if (User.IsNiceZhuanye)
                    {
                        if (json["status"]?.ToString() == "0")
                        {
                            var examsJArray = RequireArray(json["data"]?["exam"], "data.exam", response);
                            if (examsJArray.Count < 1)
                            {
                                throw new APIException("Coursed by: Failed to retrieve any exams.\n\nRemote server responded: " + response);
                            }

                            List<DongniExam> exams = [];
                            for (int i = 0; i < examsJArray.Count; i++)
                            {
                                var examObject = RequireObject(examsJArray[i], $"data.exam[{i}]", response);
                                DongniExam exam = BuildExamFromJson(examObject, response);
                                exams.Add(exam);
                                WriteLog($"DongniRole.GetLatest: Parsed {exams.Count} exams.", isDebug: true);
                            }
                            return [.. exams];
                        }
                        else
                        {
                            throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                        }
                    }
                    else
                    {
                        if (json["status"]?.ToString() == "0")
                        {
                            var data = RequireArray(json["data"], "data", response);
                            if (data.Count < 1)
                            {
                                throw new APIException("Coursed by: Failed to retrieve any exams.\n\nRemote server responded: " + response);
                            }

                            List<DongniExam> exams = [];

                            for (int i = 0; i < data.Count; i++)
                            {
                                var examObject = RequireObject(data[i], $"data[{i}]", response);
                                DongniExam exam = BuildExamFromJson(examObject, response);
                                exams.Add(exam);
                                WriteLog($"DongniRole.GetLatest: Parsed {exams.Count} exams.", isDebug: true);
                            }


                            return [.. exams];
                        }
                        else
                        {
                            throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                        }
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
                return [];
            }

            /// <summary>
            /// 获取该角色下所有考试结果。
            /// </summary>
            /// <returns><see cref="DongniExam"/> 实例数组</returns>
            public async Task<DongniExam[]> GetList()
            {
                try
                {
                    string url = $"{User.ApiEndpoint}/api/exam/plan/student/exam/list?clientType=1&schoolId={SchoolId}&examType=2,3,4,5,7,10&pageSize=100&pageNo=1&userId={User.UserId}&studentId={StudentId}";
                    string response = await GetResponse(url, User.Token);

                    WriteLog("DongniRole.GetList | RSRR: " + response, isDebug: true);

                    WriteLog("DongniRole.GetList: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        List<DongniExam> dongniExams = [];
                        var examList = RequireArray(json["data"]?["exam"], "data.exam", response);
                        for (int i = 0; i < examList.Count; i++)
                        {
                            var examObject = RequireObject(examList[i], $"data.exam[{i}]", response);
                            DongniExam dongniExam = BuildExamFromJson(examObject, response);
                            dongniExams.Add(dongniExam);
                            WriteLog($"DongniRole.GetList: Parsed {dongniExams.Count} exams.", isDebug: true);
                        }

                        return [.. dongniExams];
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniRole.GetList Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniRole.GetList Method.", ex));
                }
                return [];
            }

            /// <summary>
            /// 获取该角色下所有科目及其对应 ID。正常查询科目应调用 <seealso cref="CourseIdToName"/> 以使用可能的缓存。
            /// </summary>
            /// <returns><see cref="DongniCourse"/> 实例对象，含了每个科目的名称、对应 courseId</returns>
            public async Task<DongniCourse[]> GetCoursesList()
            {
                try
                {
                    string url = $"{User.ApiEndpoint}/api/base/data/system/account/relative/all?clientType=1&relativeId={RelativeId}&userId={User.UserId}&studentId={StudentId}";
                    string response = await GetResponse(url, User.Token);
                    WriteLog("DongniRole.GetCoursesList | RSRR: " + response, isDebug: true);

                    WriteLog("DongniRole.GetCoursesList: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        JArray courseList = RequireArray(json["data"]?["course"], "data.course", response);
                        List<DongniCourse> dongniCourses = [];
                        foreach (JObject course in courseList.Cast<JObject>())
                        {
                            dongniCourses.Add(
                                new DongniCourse(
                                RequireInt(course["courseId"], "courseId", response),
                                RequireString(course["courseName"], "courseName", response))
                                );
                        }
                        return [.. dongniCourses];
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniRole.CourseIdToName Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniRole.CourseIdToName Method.", ex));
                }
                return [];
            }


            /// <summary>
            /// 利用 <paramref name="courseId"/> 获得 courseName。有缓存时将从内存缓存取值，没有缓存时将请求API获取数据并更新缓存。
            /// </summary>
            /// <param name="courseId">已转换为整数类型的 courseId</param>
            /// <returns><paramref name="courseId"/> 对应的科目的中文名称</returns>
            public async Task<string> CourseIdToName(int courseId)
            {
                try
                {
                    if (InternalCacheProvider.Cache.TryGetValue("DNPP_Course", out DongniCourse[]? cachedCourses))
                    {
                        var cachedCourse = cachedCourses?.FirstOrDefault(c => c.CourseId == courseId);
                        if (cachedCourse is not null)
                        {
                            WriteLog($"DongniRole.CourseIdToName: Cache hit for courseId {courseId}.", isDebug: true);
                            return cachedCourse.CourseName;
                        }
                        else
                        {
                            WriteLog($"DongniRole.CourseIdToName: Cache miss for courseId {courseId}. Course not found in cached courses.", isDebug: true);

                            var courses = await GetCoursesList();
                            var cacheOpt = new MemoryCacheEntryOptions()
                                            .SetSlidingExpiration(TimeSpan.FromMinutes(10)) // 活跃就续命
                                            .SetAbsoluteExpiration(TimeSpan.FromHours(6)); // 但封顶寿命为1小时
                            InternalCacheProvider.Cache.Set("DNPP_Course", courses, cacheOpt);

                            return courses.FirstOrDefault(c => c.CourseId == courseId)?.CourseName
                                    ?? throw new APIException($"Coursed by: Cannot fetch specified course.\n\nTarget courseId: {courseId}");
                        }
                    }
                    else
                    {
                        WriteLog($"DongniRole.CourseIdToName: Cache miss for courseId {courseId}.", isDebug: true);

                        var courses = await GetCoursesList();
                        var cacheOpt = new MemoryCacheEntryOptions()
                                        .SetSlidingExpiration(TimeSpan.FromMinutes(10))
                                        .SetAbsoluteExpiration(TimeSpan.FromHours(6));
                        InternalCacheProvider.Cache.Set("DNPP_Course", courses, cacheOpt);

                        return courses.FirstOrDefault(c => c.CourseId == courseId)?.CourseName
                                ?? throw new APIException($"Coursed by: Cannot fetch specified course.\n\nTarget courseId: {courseId}");
                    }

                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniRole.CourseIdToName Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniRole.CourseIdToName Method.", ex));
                }
                throw new APIException($"Coursed by: Cannot fetch specified course.\n\nTarget courseId: {courseId}");
            }

            /// <summary>
            /// 枚举类的信息和属性等。
            /// </summary>
            /// <returns>类的名称、所属命名空间、所有属性列表。</returns>
            public override string ToString()
            {
                Type type = this.GetType();
                string className = type.Name;
                string namespaceName = type.Namespace ?? string.Empty;

                PropertyInfo[] properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
                var propertiesWithGet = properties.Where(p => p.GetGetMethod() != null);
                var propertyValues = propertiesWithGet.Select(p => $"{p.Name}: {p.GetValue(this)}");

                return $"Class: {className}\n   Namespace: {namespaceName}\n    Properties: \n      {string.Join("\n      ", propertyValues)}";
            }
        }

        /// <summary>
        /// 一个懂你平台考试实例。
        /// </summary>
        public class DongniExam
        {
            /// <summary>
            /// 考试所属的角色实例
            /// </summary>
            public DongniRole Role { get; }
            /// <summary>
            /// 考试 ID
            /// </summary>
            public string ExamId { get; }
            /// <summary>
            /// 考试名称
            /// </summary>
            public string ExamName { get; }
            /// <summary>
            /// 考试类型 ID
            /// </summary>
            public string ExamType { get; }
            /// <summary>
            /// 开始时间，为13位北京时间时间戳
            /// </summary>
            public string StartDate { get; }
            /// <summary>
            /// 结束时间，为13位北京时间时间戳
            /// </summary>
            public string EndDate { get; }

            /// <summary>
            /// <see cref="DongniExam"/> 的构造函数。通常不需要手动调用，但假如遇到无网情况可以通过这个方法从缓存中构造对象。
            /// </summary>
            /// <param name="role">该考试所属的角色</param>
            /// <param name="examId"></param>
            /// <param name="examName"></param>
            /// <param name="examType">考试类型 ID</param>
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

            private (string FullMark, string TotalScore) ReadScore(JObject json, string response, bool fromArray)
            {
                JToken scoreNode = fromArray
                    ? RequireObject(json["data"]?[0], "data[0]", response)
                    : RequireObject(json["data"], "data", response);

                return (
                    RequireString(scoreNode["fullMark"], "fullMark", response),
                    RequireString(scoreNode["totalScore"], "totalScore", response)
                );
            }

            private string ReadRanking(JObject json, string response, string rankingPath, string fieldName)
            {
                var rankingToken = json.SelectToken(rankingPath);
                return RequireString(rankingToken, fieldName, response);
            }

            /// <summary>
            /// 获取默认科目、默认 statId 的考试分数。
            /// </summary>
            /// <returns>(满分, 考生得分)</returns>
            public async Task<(string, string)> GetScore()
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/view/monitor/exam/school/scoreSection?clientType=1&courseId=&examId={ExamId}&statId={await GetDefaultStatId()}&classId={Role.ClassId}&schoolId={Role.SchoolId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetScore | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetScore: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadScore(json, response, fromArray: false);
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
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
                throw new APIException("Coursed by: Failed to retrieve score.");
            }

            /// <summary>
            /// 获取默认科目、指定 <paramref name="statId"/> 的考试分数。
            /// </summary>
            /// <param name="statId">字符串类型的 statId</param>
            /// <returns>(满分, 考生得分)</returns>
            public async Task<(string, string)> GetScore(string statId)
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/view/monitor/exam/school/scoreSection?clientType=1&courseId=&examId={ExamId}&statId={statId}&classId={Role.ClassId}&schoolId={Role.SchoolId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetScore | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetScore: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadScore(json, response, fromArray: false);
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
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
                throw new APIException("Coursed by: Failed to retrieve score.");
            }

            /// <summary>
            /// 获取指定科目、默认 statId 的考试分数。
            /// </summary>
            /// <param name="courseId">已转换为整数类型的 courseId</param>
            /// <returns>(满分, 考生得分)</returns>
            public async Task<(string, string)> GetScore(int courseId)
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/view/monitor/exam/school/course/scoreSection?clientType=1&courseId={courseId}&examId={ExamId}&statId={await GetDefaultStatId()}&classId={Role.ClassId}&schoolId={Role.SchoolId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    // 指定courseId 必须走这个接口URL
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetScore | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetScore: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadScore(json, response, fromArray: true);
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
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
                throw new APIException("Coursed by: Failed to retrieve score.");
            }

            /// <summary>
            /// 获取指定科目、指定 <paramref name="statId"/> 的考试分数。
            /// </summary>
            /// <param name="statId">字符串类型的 statId</param>
            /// <param name="courseId">已转换为整数类型的 courseId</param>
            /// <returns>(满分, 考生得分)</returns>
            public async Task<(string, string)> GetScore(string statId, int courseId)
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/view/monitor/exam/school/course/scoreSection?clientType=1&courseId={courseId}&examId={ExamId}&statId={statId}&classId={Role.ClassId}&schoolId={Role.SchoolId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetScore | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetScore: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadScore(json, response, fromArray: true);
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
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
                throw new APIException("Coursed by: Failed to retrieve score.");
            }

            /// <summary>
            /// 获取默认科目、默认 statId 的考试(年段)排名。
            /// </summary>
            /// <returns>examRanking 值，通常是年段排名</returns>
            public async Task<string> GetExamRanking()
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/data/exam/student/weChat/scoreLevel?clientType=1&schoolId={Role.SchoolId}&statId={await GetDefaultStatId()}&courseId=&examId={ExamId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetExamRanking | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetExamRanking: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadRanking(json, response, "data.list[0].examRanking", "examRanking");
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.GetExamRanking Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.GetExamRanking Method.", ex));
                }
                throw new APIException("Coursed by: Failed to retrieve exam ranking.");
            }

            /// <summary>
            /// 获取默认科目、指定 <paramref name="statId"/> 的考试(年段)排名。
            /// </summary>
            /// <param name="statId">字符串类型的 statId</param>
            /// <returns>examRanking 值，通常是年段排名</returns>
            public async Task<string> GetExamRanking(string statId)
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/data/exam/student/weChat/scoreLevel?clientType=1&schoolId={Role.SchoolId}&statId={statId}&courseId=&examId={ExamId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetExamRanking | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetExamRanking: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadRanking(json, response, "data.list[0].examRanking", "examRanking");
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.GetExamRanking Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.GetExamRanking Method.", ex));
                }
                throw new APIException("Coursed by: Failed to retrieve exam ranking.");
            }

            /// <summary>
            /// 获取指定科目、默认 statId 的考试(年段)排名。
            /// </summary>
            /// <param name="courseId">已转换为整数类型的 courseId</param>
            /// <returns>examRanking 值，通常是年段排名</returns>
            public async Task<string> GetExamRanking(int courseId)
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/data/exam/student/weChat/scoreLevel?clientType=1&schoolId={Role.SchoolId}&statId={await GetDefaultStatId()}&courseId={courseId}&examId={ExamId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetExamRanking | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetExamRanking: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadRanking(json, response, "data.list[0].examRanking", "examRanking");
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.GetExamRanking Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.GetExamRanking Method.", ex));
                }
                throw new APIException("Coursed by: Failed to retrieve exam ranking.");
            }

            /// <summary>
            /// 获取指定科目、指定 <paramref name="statId"/> 的考试(年段)排名。
            /// </summary>
            /// <param name="statId">字符串类型的 statId</param>
            /// <param name="courseId">已转换为整数类型的 courseId</param>
            /// <returns>examRanking 值，通常是年段排名</returns>
            public async Task<string> GetExamRanking(string statId, int courseId)
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/data/exam/student/weChat/scoreLevel?clientType=1&schoolId={Role.SchoolId}&statId={statId}&courseId={courseId}&examId={ExamId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetExamRanking | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetExamRanking: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadRanking(json, response, "data.list[0].examRanking", "examRanking");
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.GetExamRanking Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.GetExamRanking Method.", ex));
                }
                throw new APIException("Coursed by: Failed to retrieve exam ranking.");
            }

            /// <summary>
            /// 获取默认科目、默认 statId 的班级排名。
            /// </summary>
            /// <returns>classRanking 值，通常是班级排名</returns>
            public async Task<string> GetClassRanking()
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/data/exam/student/weChat/scoreLevel?clientType=1&schoolId={Role.SchoolId}&statId={await GetDefaultStatId()}&courseId=&examId={ExamId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetClassRanking | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetClassRanking: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadRanking(json, response, "data.list[0].classRanking", "classRanking");
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.GetClassRanking Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.GetClassRanking Method.", ex));
                }
                throw new APIException("Coursed by: Failed to retrieve class ranking.");
            }

            /// <summary>
            /// 获取默认科目、指定 <paramref name="statId"/> 的班级排名。
            /// </summary>
            /// <param name="statId">字符串类型的 statId</param>
            /// <returns>classRanking 值，通常是班级排名</returns>
            public async Task<string> GetClassRanking(string statId)
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/data/exam/student/weChat/scoreLevel?clientType=1&schoolId={Role.SchoolId}&statId={statId}&courseId=&examId={ExamId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetClassRanking | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetClassRanking: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadRanking(json, response, "data.list[0].classRanking", "classRanking");
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.GetClassRanking Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.GetClassRanking Method.", ex));
                }
                throw new APIException("Coursed by: Failed to retrieve class ranking.");
            }

            /// <summary>
            /// 获取指定科目、默认 statId 的班级排名。
            /// </summary>
            /// <param name="courseId">已转换为整数类型的 courseId</param>
            /// <returns>classRanking 值，通常是班级排名</returns>
            public async Task<string> GetClassRanking(int courseId)
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/data/exam/student/weChat/scoreLevel?clientType=1&schoolId={Role.SchoolId}&statId={await GetDefaultStatId()}&courseId={courseId}&examId={ExamId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetClassRanking | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetClassRanking: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadRanking(json, response, "data.list[0].classRanking", "classRanking");
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.GetClassRanking Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.GetClassRanking Method.", ex));
                }
                throw new APIException("Coursed by: Failed to retrieve class ranking.");
            }

            /// <summary>
            /// 获取默认科目、默认 <paramref name="statId"/> 的班级排名。
            /// </summary>
            /// <param name="statId">字符串类型的 statId</param>
            /// <param name="courseId">已转换为整数类型的 courseId</param>
            /// <returns>classRanking 值，通常是班级排名</returns>
            public async Task<string> GetClassRanking(string statId, int courseId)
            {
                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/data/exam/student/weChat/scoreLevel?clientType=1&schoolId={Role.SchoolId}&statId={statId}&courseId={courseId}&examId={ExamId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetClassRanking | RSRR: " + response, isDebug: true);
                    WriteLog("DongniExam.GetClassRanking: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        return ReadRanking(json, response, "data.list[0].classRanking", "classRanking");
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.GetClassRanking Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.GetClassRanking Method.", ex));
                }
                throw new APIException("Coursed by: Failed to retrieve class ranking.");
            }

            /// <summary>
            /// 利用 <paramref name="courseId"/> 以及默认的 statId 获得 courseName。
            /// 该方法只会请求 API 枚举当前考试下的所有科目，针对性较强，因此对于已知考试对象的查询，该方法相对 <see cref="DongniRole.CourseIdToName"/> 方法效率更高。
            /// </summary>
            /// <param name="courseId">已转换为整数类型的 courseId</param>
            /// <returns>对应科目的中文名称</returns>
            public async Task<string> CourseIdToName(int courseId)
            {
                try
                {
                    if (courseId == 0)
                    {
                        return "默认";
                    }
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/data/exam/student/weChat/courseInfo?clientType=1&examId={ExamId}&statId={await GetDefaultStatId()}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.CourseIdToName | RSRR: " + response, isDebug: true);

                    WriteLog("DongniExam.CourseIdToName: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        JArray courseList = RequireArray(json["data"], "data", response);
                        foreach (JObject course in courseList.Cast<JObject>())
                        {
                            if (RequireString(course["courseId"], "courseId", response) == courseId.ToString())
                            {
                                return RequireString(course["courseName"], "courseName", response);
                            }

                        }
                        throw new APIException("Coursed by: Cannot fetch specified course.\n\nRemote server responded: " + response + "\n\nTarget courseId: " + courseId);
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.CourseIdToName Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.CourseIdToName Method.", ex));
                }
                throw new APIException($"Coursed by: Cannot fetch specified course.\n\nTarget courseId: {courseId}");
            }

            /// <summary>
            /// 利用 <paramref name="courseId"/> 以及指定的 <paramref name="statId"/> 获得 courseName。
            /// 该方法只会请求 API 枚举当前考试下的所有科目，针对性较强，因此对于已知考试对象的查询，该方法相对 <see cref="DongniRole.CourseIdToName"/> 方法效率更高。
            /// </summary>
            /// <param name="courseId">已转换为整数类型的 courseId</param>
            /// <param name="statId">字符串类型的 statId</param>
            /// <returns>对应科目的中文名称</returns>
            public async Task<string> CourseIdToName(int courseId, string statId)
            {
                try
                {
                    if (courseId == 0)
                    {
                        return "默认";
                    }
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/data/exam/student/weChat/courseInfo?clientType=1&examId={ExamId}&statId={statId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.CourseIdToName | RSRR: " + response, isDebug: true);

                    WriteLog("DongniExam.CourseIdToName: Trying to parse...", isDebug: true);
                    JObject json = JObject.Parse(response);
                    if (json["status"]?.ToString() == "0")
                    {
                        JArray courseList = RequireArray(json["data"], "data", response);
                        foreach (JObject course in courseList.Cast<JObject>())
                        {
                            if (RequireString(course["courseId"], "courseId", response) == courseId.ToString())
                            {
                                return RequireString(course["courseName"], "courseName", response);
                            }

                        }
                        throw new APIException("Coursed by: Cannot fetch specified course.\n\nRemote server responded: " + response + "\n\nTarget courseId: " + courseId);
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);
                    }
                }
                catch (APIException ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An API exception occurred at DongniExam.CourseIdToName Method.", ex));
                }
                catch (Exception ex)
                {
                    ErrorOccurred?.Invoke(null, new ErrorEventArgs("An program exception occurred at DongniExam.CourseIdToName Method.", ex));
                }
                throw new APIException($"Coursed by: Cannot fetch specified course.\n\nTarget courseId: {courseId}");
            }

            /// <summary>
            /// 获取该考试默认的 statId。该值将在一些未指定 statId 参数的方法中替代缺省的 statId 来拼接接口 URL。
            /// </summary>
            /// <returns>字符串类型的 statId</returns>
            private async Task<string> GetDefaultStatId()
            {

                try
                {
                    string url = $"{Role.User.ApiEndpoint}/api/analysis/data/exam/student/weChat/all/examStatId?clientType=1&examId={ExamId}&schoolId={Role.SchoolId}&userId={Role.User.UserId}&studentId={Role.StudentId}";
                    string response = await GetResponse(url, Role.User.Token);
                    WriteLog("DongniExam.GetDeafultStatId | RSRR: " + response, isDebug: true);

                    WriteLog("DongniExam.GetDeafultStatId: Trying to parse... ", isDebug: true);
                    JObject json = JObject.Parse(response);

                    if (json["status"]?.ToString() == "0")
                    {
                        return RequireString(json["data"]?["statId"], "data.statId", response);
                    }
                    else
                    {
                        throw new APIException("Coursed by: Status value is not 0.\n\nRemote server responded: " + response);

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
                throw new APIException("Coursed by: Failed to retrieve default statId.");
            }

            /// <summary>
            /// 枚举类的信息和属性等。
            /// </summary>
            /// <returns>类的名称、所属命名空间、所有属性列表。</returns>
            public override string ToString()
            {
                Type type = this.GetType();
                string className = type.Name;
                string namespaceName = type.Namespace ?? string.Empty;

                PropertyInfo[] properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
                var propertiesWithGet = properties.Where(p => p.GetGetMethod() != null);
                var propertyValues = propertiesWithGet.Select(p => $"{p.Name}: {p.GetValue(this)}");

                return $"Class: {className}\n   Namespace: {namespaceName}\n    Properties: \n      {string.Join("\n      ", propertyValues)}";
            }
        }

        /// <summary>
        /// 懂你平台的科目对应信息记录。
        /// </summary>
        /// <param name="CourseId">整数型 courseId</param>
        /// <param name="CourseName">对应的科目中文名称</param>

        public record DongniCourse(int CourseId, string CourseName);


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
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0");
                client.DefaultRequestHeaders.Add("Dongni-Login", token);
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
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0");
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
        /// <param name="headers">可选的请求头列表</param>
        /// <returns>返回服务器的Response。</returns>
        private static async Task<string> PostRequest(string url, string postContent, string contentType, Dictionary<string, string>? headers = null)
        {
            using (HttpClient client = new HttpClient())
            {
                StringContent content = new StringContent(postContent, Encoding.UTF8, contentType);
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0");
                if (headers is not null)
                {
                    foreach (var header in headers)
                    {
                        client.DefaultRequestHeaders.Add(header.Key, header.Value);
                    }
                }
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
        /// <param name="isDebug">是否是Debug类型。如果为 true，则仅在全局 debugging == true时输出。默认为 false。</param>
        private static void WriteLog(string message, string eventType = "INFO", bool isDebug = false)
        {
            if (CustomLogHandler is not null)
            {
                CustomLogHandler(message, eventType, isDebug);
            }
            else
            {
                if (isDebug && debugging)
                {
                    Debug.WriteLine($"[{DateTime.Now} | Debug / {eventType}] " + message);
                }
                else if (!isDebug)
                {
                    Debug.WriteLine($"[{DateTime.Now} | {eventType}]" + message);
                }
            }


        }
        /// <summary>
        /// 设置在 dongniSDK 中是否输出调试信息。
        /// </summary>
        /// <param name="debug">true为全局输出调试日志，反之不输出。</param>
        public static void SetDebug(bool debug)
        {
            debugging = debug;
        }


        /// <summary>
        /// 定义处理错误事件的委托方法。
        /// </summary>
        /// <param name="sender">事件源</param>
        /// <param name="e">包含事件数据的 <see cref="ErrorEventArgs"/> 实例。</param>
        public delegate void ErrorHandler(object? sender, ErrorEventArgs e);

        /// <summary>
        /// 当发生错误时触发的事件。
        /// </summary>
        public static event ErrorHandler? ErrorOccurred;

        /// <summary>
        /// 提供错误事件数据的类。
        /// </summary>
        public class ErrorEventArgs : EventArgs
        {
            /// <summary>
            /// 错误消息。
            /// </summary>
            public string Message { get; set; }

            /// <summary>
            /// 与错误关联的异常。
            /// </summary>
            public Exception Exception { get; set; }

            /// <summary>
            /// 构造 <see cref="ErrorEventArgs"/> 类的新实例。
            /// </summary>
            /// <param name="message">错误消息。</param>
            /// <param name="exception">与错误关联的异常。</param>
            public ErrorEventArgs(string message, Exception exception)
            {
                Message = message;
                Exception = exception;
            }
        }

        /// <summary>
        /// 表示API调用过程中发生的错误。
        /// </summary>
        public class APIException : Exception
        {
            /// <summary>
            /// 构造 <see cref="APIException"/> 类的新实例。
            /// </summary>
            public APIException()
            {
            }

            /// <summary>
            /// 使用指定错误消息构造 <see cref="APIException"/> 类的新实例。
            /// </summary>
            /// <param name="message">描述错误的消息。</param>
            public APIException(string message)
                : base(message)
            {
            }

            /// <summary>
            /// 使用指定错误消息和对作为此异常原因的内部异常的引用来构造 <see cref="APIException"/> 类的新实例。
            /// </summary>
            /// <param name="message">描述错误的消息。</param>
            /// <param name="inner">导致当前异常的异常。</param>
            public APIException(string message, Exception inner)
                : base(message, inner)
            {
            }
        }


        /// <summary>
        /// 提供RSA加密相关的实用方法。
        /// </summary>
        internal class RSAUtils
        {
            /// <summary>
            /// 从PEM格式的公钥字符串获取RSA公钥参数。
            /// </summary>
            /// <param name="publicKeyPem">PEM格式的公钥字符串。</param>
            /// <returns>包含公钥参数的 <see cref="RSAParameters"/> 实例。</returns>
            public static RSAParameters GetPublicKeyParameters(string publicKeyPem)
            {
                // 使用BouncyCastle库解析PEM格式的公钥
                PemReader pemReader = new PemReader(new System.IO.StringReader(publicKeyPem));
                AsymmetricKeyParameter publicKeyParam = (AsymmetricKeyParameter)pemReader.ReadObject();

                // 将BouncyCastle的公钥参数转换为.NET的RSAParameters类型
                RSAParameters publicKeyParameters = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKeyParam);

                return publicKeyParameters;
            }

            /// <summary>
            /// 使用RSA公钥加密数据并将结果转换为Base64字符串。
            /// </summary>
            /// <param name="publicKey">用于加密的RSA公钥参数。</param>
            /// <param name="data">要加密的字节数组。</param>
            /// <returns>加密后的Base64字符串。</returns>
            public static string EncryptToBase64(RSAParameters publicKey, byte[] data)
            {
                using (var rsa = RSA.Create())
                {
                    rsa.ImportParameters(publicKey);

                    // 使用公钥加密数据
                    byte[] encryptedData = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);

                    // 将加密结果转换为Base64字符串
                    string base64String = Convert.ToBase64String(encryptedData);

                    return base64String;
                }
            }
        }


    }
}
