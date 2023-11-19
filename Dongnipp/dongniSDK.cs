using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Net;
using System.IO;
using System.Net.Http;

namespace Dongnipp
{
    internal class dongniSDK
    {
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
