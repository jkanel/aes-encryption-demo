using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// ADDITIONAL NAMESPACES
using System.IO;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;

namespace AesEncryptionDemo
{
    /// <summary>
    /// Performs best practice AES 256-bit encryption with advanced salt and IV generation.
    /// </summary>
    public static class Aes256EncryptionProvider
    {
        #region References

        // https://msdn.microsoft.com/en-us/library/ms229741(v=vs.110).aspx
        // http://stackoverflow.com/questions/967773/how-to-use-system-security-cryptography-aesmanaged-to-encrypt-a-byte
        // http://crypto.stackexchange.com/questions/16410/some-questions-about-encrypting-aes-a-file-with-password
        // http://stackoverflow.com/questions/18808391/using-aes-encryption-with-binary-filestream-read-write

        #endregion References

        #region Static Properties

        /// <summary>
        /// Default size of the salt in bytes.
        /// </summary>
        public static int DEFAULT_SALT_SIZE_BYTES = 64;

        /// <summary>
        /// Default iterations of passwords hashing used to generate an initialization vector (IV)
        /// </summary>
        public static int DEFAULT_ITERATIONS = 10000;

        /// <summary>
        /// Iterations of password hashing applied when not provied explicitly as a function parameter.
        /// </summary>
        public static int Iterations = DEFAULT_ITERATIONS;

        /// <summary>
        /// Size of the salt in bytes applied when not provided explicitly as a function parameter.
        /// Note that this must be a factor of two (2^N).  Lower than 32 bytes is not recommended.
        /// </summary>
        public static int SaltSize = DEFAULT_SALT_SIZE_BYTES;

        /// <summary>
        /// Block cipher mode used to generate the encryption.
        /// </summary>
        public static CipherMode CipherMode = CipherMode.CBC;

        /// <summary>
        /// Padding method used to fill the message so that it meets the mandatory block size.
        /// </summary>
        public static PaddingMode PaddingMode = PaddingMode.PKCS7;

        /// <summary>
        /// PasswordProvider applied when not provided explicitly as a function parameter.
        /// </summary>
        public static IPasswordProvider PasswordProvider;

        #endregion Static Properties

        #region Encrypt String

        /// <summary>
        /// Encrypts a secret string, returning an auto-generated salt.
        /// Static PasswordProvider, Iterations and SaltSize are internally applied.
        /// </summary>
        /// <param name="PlainText">String containing the text to be encrypted.</param>
        /// <param name="SaltText">SaltText converted to a string.  This value is generated in the function and passed out.</param>
        /// <returns>Encrypted cipher converted to a string.</returns>
        public static string Encrypt(string PlainText, out string SaltText)
        {
            // ValidateStaticInitialization();

            return Aes256EncryptionProvider.Encrypt(PlainText, out SaltText, 
                Aes256EncryptionProvider.PasswordProvider.GetPassword(), 
                Aes256EncryptionProvider.Iterations, 
                Aes256EncryptionProvider.SaltSize);
        }

        /// <summary>
        /// Encrypts a secret string, returning an auto-generated salt.
        /// </summary>
        /// <param name="PlainText">String containing the text to be encrypted.</param>
        /// <param name="SaltText">SaltText converted to a string.  This value is generated in the function and passed out.</param>
        /// <param name="Password">Password used to generate the encryption key and initialization vector.</param>
        /// <param name="Iterations">Numbrer of iterations of hashing applied to the password.</param>
        /// <param name="SaltSize">Size of the salt in bytes to be generated.</param>
        /// <returns>Encrypted cipher converted to a string.</returns>
        public static string Encrypt(string PlainText, out string SaltText, string Password, int Iterations, int SaltSize)
        {
            byte[] PlainTextBytes = Encoding.UTF8.GetBytes(PlainText);
            byte[] SaltBytes;

            byte[] CipherBytes = Encrypt(PlainTextBytes, out SaltBytes, Password, Iterations, SaltSize);

            SaltText = Convert.ToBase64String(SaltBytes);
            return Convert.ToBase64String(CipherBytes, 0, CipherBytes.Length);
        }

        private static byte[] Encrypt(byte[] PlainTextBytes, out byte[] SaltBytes)
        {
            // ValidateStaticInitialization();();

            return Encrypt(PlainTextBytes, out SaltBytes,
                Aes256EncryptionProvider.PasswordProvider.GetPassword(),
                Aes256EncryptionProvider.Iterations,
                Aes256EncryptionProvider.SaltSize);
        }

        private static byte[] Encrypt(byte[] PlainTextBytes, out byte[] SaltBytes, string Password, int Iterations, int SaltSize)
        {
            // randomly specify the salt size...at least 64
            byte[] CipherBytes;

            using (Rfc2898DeriveBytes rbg = new Rfc2898DeriveBytes(Password, SaltSize, Iterations))
            {
                // read the generated salt
                SaltBytes = rbg.Salt;

                if (SaltBytes.Length != SaltSize)
                {
                    throw new Exception("Invalid salt size");
                }

                using (AesManaged aes = new AesManaged())
                {

                    // IMPORTANT SETTINGS
                    aes.Mode = Aes256EncryptionProvider.CipherMode;
                    aes.Padding = Aes256EncryptionProvider.PaddingMode;

                    byte[] key = rbg.GetBytes(aes.KeySize >> 3);
                    byte[] iv = rbg.GetBytes(aes.BlockSize >> 3);

                    using (ICryptoTransform cryptoTransform = aes.CreateEncryptor(key, iv))
                    using (MemoryStream memoryStream = new MemoryStream())
                    using (CryptoStream cs = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                    {

                        cs.Write(PlainTextBytes, 0, PlainTextBytes.Length);
                        cs.Close();
                        CipherBytes = memoryStream.ToArray();

                    }

                }
            }

            return CipherBytes;
        }

        #endregion Enrypt String

        #region Decrypt String

        public static string Decrypt(string CipherText, string SaltText)
        {
            // ValidateStaticInitialization();();

            return Aes256EncryptionProvider.Decrypt(CipherText, SaltText,
                Aes256EncryptionProvider.PasswordProvider.GetPassword(),
                Aes256EncryptionProvider.Iterations,
                Aes256EncryptionProvider.SaltSize);
        }

        public static string Decrypt(string CipherText, string SaltText, string Password, int Iterations, int SaltSize)
        {

            byte[] CipherBytes = Convert.FromBase64String(CipherText);
            byte[] SaltBytes = Convert.FromBase64String(SaltText);

            byte[] PlainTextBytes = Decrypt(CipherBytes, SaltBytes, Password, Iterations, SaltSize);

            return Encoding.UTF8.GetString(PlainTextBytes);
        }

        public static byte[] Decrypt(byte[] CipherBytes, byte[] SaltBytes)
        {
            // ValidateStaticInitialization();();

            return Decrypt(CipherBytes, SaltBytes,
                Aes256EncryptionProvider.PasswordProvider.GetPassword(),
                Aes256EncryptionProvider.Iterations,
                Aes256EncryptionProvider.SaltSize);
        }

        public static byte[] Decrypt(byte[] CipherBytes, byte[] SaltBytes, string Password, int Iterations, int SaltSize)
        {
            byte[] PlainTextBytes;

            using (Rfc2898DeriveBytes rbg = new Rfc2898DeriveBytes(Password, SaltBytes, Iterations))
            {

                using (AesManaged aes = new AesManaged())
                {

                    // IMPORTANT SETTINGS
                    aes.Mode = Aes256EncryptionProvider.CipherMode;
                    aes.Padding = Aes256EncryptionProvider.PaddingMode;

                    byte[] key = rbg.GetBytes(aes.KeySize >> 3);
                    byte[] iv = rbg.GetBytes(aes.BlockSize >> 3);

                    using (ICryptoTransform cryptoTransform = aes.CreateDecryptor(key, iv))
                    using (MemoryStream sourceStream = new MemoryStream(CipherBytes, 0, CipherBytes.Length))
                    using (CryptoStream cryptoStream = new CryptoStream(sourceStream, cryptoTransform, CryptoStreamMode.Read))
                    using (MemoryStream decryptedStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(decryptedStream);
                        PlainTextBytes = decryptedStream.ToArray();
                    }
                }
            }

            return PlainTextBytes;

        }

        #endregion Decrypt String

        #region Encrypt Object To Stream

        public static void EncryptObject(Stream CipherStream, object PlainObject, out string SaltText)
        {
            // ValidateStaticInitialization();();

            EncryptObject(CipherStream, PlainObject, out SaltText,
                Aes256EncryptionProvider.PasswordProvider.GetPassword(),
                Aes256EncryptionProvider.Iterations,
                Aes256EncryptionProvider.SaltSize);

        }

        public static void EncryptObject(Stream CipherStream, object PlainObject, out string SaltText, string Password, int Iterations, int SaltSize)
        {
            byte[] SaltBytes;

            EncryptObject(CipherStream, PlainObject, out SaltBytes, Password, Iterations, SaltSize);
            SaltText = Convert.ToBase64String(SaltBytes);
        }

        private static void EncryptObject(Stream CipherStream, object PlainObject, out byte[] SaltBytes)
        {
            // ValidateStaticInitialization();();

            EncryptObject(CipherStream, PlainObject, out SaltBytes,
                Aes256EncryptionProvider.PasswordProvider.GetPassword(),
                Aes256EncryptionProvider.Iterations,
                Aes256EncryptionProvider.SaltSize);
        }

        private static void EncryptObject(Stream CipherStream, object PlainObject, out byte[] SaltBytes, string Password, int Iterations, int SaltSize)
        {
            using (Rfc2898DeriveBytes rbg = new Rfc2898DeriveBytes(Password, SaltSize, Iterations))
            {
                // read the generated salt
                SaltBytes = rbg.Salt;

                if (SaltBytes.Length != SaltSize)
                {
                    throw new Exception("Invalid salt size");
                }

                using (AesManaged aes = new AesManaged())
                {
                    // IMPORTANT SETTINGS
                    aes.Mode = Aes256EncryptionProvider.CipherMode;
                    aes.Padding = Aes256EncryptionProvider.PaddingMode;

                    byte[] key = rbg.GetBytes(aes.KeySize >> 3);
                    byte[] iv = rbg.GetBytes(aes.BlockSize >> 3);

                    using (ICryptoTransform cryptoTransform = aes.CreateEncryptor(key, iv))
                    using (CipherStream)
                    {
                        CryptoStream cryptoStream = new CryptoStream(CipherStream, cryptoTransform, CryptoStreamMode.Write);

                        BinaryFormatter serializer = new BinaryFormatter();
                        serializer.Serialize(cryptoStream, PlainObject);

                        cryptoStream.FlushFinalBlock();

                    }

                }
            }
        }

        #endregion Encrypt Object To Stream

        #region Decrypt Object From Stream

        public static object DecryptObject(Stream CipherStream, string SaltText)
        {
            // ValidateStaticInitialization();();

            return DecryptObject(CipherStream, SaltText,
                Aes256EncryptionProvider.PasswordProvider.GetPassword(),
                Aes256EncryptionProvider.Iterations,
                Aes256EncryptionProvider.SaltSize);
        }

        public static object DecryptObject(Stream CipherStream, string SaltText, string Password, int Iterations, int SaltSize)
        {

            byte[] SaltBytes = Convert.FromBase64String(SaltText);
            object obj = DecryptObject(CipherStream, SaltBytes, Password, Iterations, SaltSize);

            return obj;
        }

        public static object DecryptObject(Stream CipherStream, byte[] SaltBytes)
        {
            // ValidateStaticInitialization();();

            return DecryptObject(CipherStream, SaltBytes,
                Aes256EncryptionProvider.PasswordProvider.GetPassword(),
                Aes256EncryptionProvider.Iterations,
                Aes256EncryptionProvider.SaltSize);
        }

        public static object DecryptObject(Stream CipherStream, byte[] SaltBytes, string Password, int Iterations, int SaltSize)
        {

            using (Rfc2898DeriveBytes rbg = new Rfc2898DeriveBytes(Password, SaltBytes, Iterations))
            {
                using (AesManaged aes = new AesManaged())
                {
                    // IMPORTANT SETTINGS
                    aes.Mode = Aes256EncryptionProvider.CipherMode;
                    aes.Padding = Aes256EncryptionProvider.PaddingMode;

                    byte[] key = rbg.GetBytes(aes.KeySize >> 3);
                    byte[] iv = rbg.GetBytes(aes.BlockSize >> 3);

                    using (ICryptoTransform cryptoTransform = aes.CreateDecryptor(key, iv))
                    using (CryptoStream cryptoStream = new CryptoStream(CipherStream, cryptoTransform, CryptoStreamMode.Read))
                    {

                        BinaryFormatter serializer = new BinaryFormatter();
                        object obj = serializer.Deserialize(cryptoStream);

                        return obj;
                    }

                }
            }
        }

        #endregion Decrypt Object From Stream

    }
}
