using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Cryptography;
using System.Text;

namespace Loginauth.Models
{
    public class Encrypt
    {
        public static string Hash(string value)
        {
            return Convert.ToBase64String(SHA256.Create()
                .ComputeHash(Encoding.UTF8.GetBytes(value)));
        }
    }
}