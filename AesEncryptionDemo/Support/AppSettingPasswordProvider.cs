using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// ADDITIONAL NAMESPACES
using System.Configuration;

namespace AesEncryptionDemo
{
    class AppSettingPasswordProvider : IPasswordProvider
    {
        public static string AppSettingName = "EncryptionPassword";

        public string GetPassword()
        {
            return ConfigurationManager.AppSettings.Get(AppSettingPasswordProvider.AppSettingName);

        }
    }
}
