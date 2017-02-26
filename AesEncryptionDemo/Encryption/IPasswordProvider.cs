using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AesEncryptionDemo
{
    /// <summary>
    /// Interface used to provide passwords to the AesEncryptionProvider.
    /// </summary>
    public interface IPasswordProvider
    {
        string GetPassword();
    }
}
