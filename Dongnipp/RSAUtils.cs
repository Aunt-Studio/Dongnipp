using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace top.nuozhen.Dongnipp
{
    internal class RSAUtils
    {
        //感谢伟大的GPT (
        public static RSAParameters GetPublicKeyParameters(string publicKeyPem)
        {
            // 使用BouncyCastle库解析PEM格式的公钥
            PemReader pemReader = new PemReader(new System.IO.StringReader(publicKeyPem));
            AsymmetricKeyParameter publicKeyParam = (AsymmetricKeyParameter)pemReader.ReadObject();

            // 将BouncyCastle的公钥参数转换为.NET的RSAParameters类型
            RSAParameters publicKeyParameters = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKeyParam);

            return publicKeyParameters;
        }

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
