﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// ADDITIONAL NAMESPACES
using System.IO;
using System.Configuration;
using System.Web.Script.Serialization;

namespace AesEncryptionDemo
{

    class Program
    {
        static void Main(string[] args)
        {
            
            Console.WindowHeight = (int)(Console.LargestWindowHeight/1.25);
            Console.WindowWidth= (int)(Console.LargestWindowWidth/1.25);

            Console.WriteLine("STATIC VARIABLES");
            Console.WriteLine("=======================");
            Console.WriteLine("Static Iterations: {0}", Aes256EncryptionProvider.Iterations.ToString("G"));
            Console.WriteLine("Static SaltSize: {0}", Aes256EncryptionProvider.SaltSize.ToString("G"));
            Console.WriteLine("Static PaddingMode: {0}", Aes256EncryptionProvider.PaddingMode.ToString());
            Console.WriteLine("Static CipherMode: {0}", Aes256EncryptionProvider.CipherMode.ToString());
            Console.WriteLine();

            Demo1();
            // Demo2();
            // Demo3();
            // Demo4();
            
            Console.WriteLine("Press enter key to continue.");
            string x = Console.ReadLine();
        }

        static void Demo1()
        {
            // SUMMARY: encrypt and decrypt string with explicit settings
          
            // create the plain text to be encrypted
            string PlainText = "The quick brown fox jumped over the lazy dog.";

            // create a password, iterations and salt size
            string Password = "This is my very tricky passwords!";
            int Iterations = 11202;
            int SaltSize = 128;

            // empty salt to hold the value generated by encryption
            string SaltText;

            // encrypt the plain texd to cipher text, returning the generated salt
            string CipherText = Aes256EncryptionProvider.Encrypt(PlainText, out SaltText, Password, Iterations, SaltSize);

            // decrypt the cipher texdt back into plain text
            string PlainText2 = Aes256EncryptionProvider.Decrypt(CipherText, SaltText, Password, Iterations, SaltSize);

            Console.WriteLine("DEMO #1");
            Console.WriteLine("=======================");
            Console.WriteLine("\nPlainText: {0}", PlainText);
            Console.WriteLine("\nIterations: {0}", Iterations.ToString("G"));
            Console.WriteLine("\nSaltSize: {0}", SaltSize.ToString("G"));
            Console.WriteLine("\nSalt: {0}", SaltText);
            Console.WriteLine("\nCipherText: {0}", CipherText);
            Console.WriteLine("\nPlainText2: {0}", PlainText2);
            Console.WriteLine();
            
        }

        static void Demo2()
        {
            // SUMMARY: encrypt and decrypt string with a static parameters

            // create the plain text to be encrypted
            string PlainText = "The quick brown fox jumped over the lazy dog.";

            // empty salt to hold the value generated by encryption
            string SaltText;

            // need to assign a static password provider implemntation
            Aes256EncryptionProvider.PasswordProvider = new AppSettingPasswordProvider();
            
            // encrypt the plain texd to cipher text, returning the generated salt
            string CipherText = Aes256EncryptionProvider.Encrypt(PlainText, out SaltText);

            // decrypt the cipher texdt back into plain text
            string PlainText2 = Aes256EncryptionProvider.Decrypt(CipherText, SaltText);

            Console.WriteLine("DEMO #2");
            Console.WriteLine("=======================");
            Console.WriteLine("\nPlainText: {0}", PlainText);
            Console.WriteLine("\nSalt: {0}", SaltText);
            Console.WriteLine("\nCipherText: {0}", CipherText);
            Console.WriteLine("\nPlainText2: {0}", PlainText2);
            Console.WriteLine();

        }


        static void Demo3()
        {

            // SUMMARY: encrypt and decrypt object using a memory stream

            // create and populate a serializable demo object
            DemoObject DemoObject = new DemoObject()
            {

                SomeName = "Test Name",
                SomeInteger = 99999
            };

            DemoObject.SomeDictionary.Add("Test1", 1);   
            DemoObject.SomeDictionary.Add("Test2", 2);
            DemoObject.SomeDictionary.Add("Test3", 3);


            // empty salt will be generated by encryption
            string SaltText;
            
            // need to assign a static password provider implemntation
            Aes256EncryptionProvider.PasswordProvider = new AppSettingPasswordProvider();

            // create a stream to hold the cipher generated by encryption
            MemoryStream TargetCipherStream = new MemoryStream();

            // encrypt the demo object into the stream.  return the generated salt.
            Aes256EncryptionProvider.EncryptObject(TargetCipherStream, DemoObject, out SaltText);

            // convert the cipher to a string (not really needed, but good for visuaization
            string CipherText = Convert.ToBase64String(TargetCipherStream.ToArray());

            // create a new stream and load the cipher
            MemoryStream SourceCipherStream = new MemoryStream(Convert.FromBase64String(CipherText));

            // decrypt the stream to an object and cast as a demo object
            // we'll compare the serializations of original and decrypted demo objects, below
            DemoObject DecryptedDemoObject = (DemoObject)Aes256EncryptionProvider.DecryptObject(SourceCipherStream, SaltText);

            Console.WriteLine("DEMO #3");
            Console.WriteLine("=======================");
            Console.WriteLine("\nDemoObject: {0}", new JavaScriptSerializer().Serialize(DemoObject));
            Console.WriteLine("\nSalt: {0}", SaltText);
            Console.WriteLine("\nCipherText: {0}", CipherText);
            Console.WriteLine("\nDemoObject2: {0}", new JavaScriptSerializer().Serialize(DecryptedDemoObject));
            Console.WriteLine();
            
        }

        static void Demo4()
        {
            // SUMMARY: encrypt and decrypt object to file
            
            // create and populate a serializable demo object
            DemoObject DemoObject = new DemoObject()
            {

                SomeName = "Test Name",
                SomeInteger = 99999
            };

            DemoObject.SomeDictionary.Add("Test1", 1);
            DemoObject.SomeDictionary.Add("Test2", 2);
            DemoObject.SomeDictionary.Add("Test3", 3);

            // set the file path where the encrypted binary data will be stored
            string FilePath = @"C:\Temporary\cipher.bin";

            // empty salt will be generated by encryption
            string SaltText;
            
            // need to assign a static password provider implemntation
            Aes256EncryptionProvider.PasswordProvider = new AppSettingPasswordProvider();

            // create the file stream
            FileStream TargetCipherStream = new FileStream(FilePath, FileMode.Create);

            // encrypt the demo object into the file stream.  return the generated salt.
            Aes256EncryptionProvider.EncryptObject(TargetCipherStream, DemoObject, out SaltText);

            // create another file stream (same path) as the source of the cipher
            FileStream SourceCipherStream = new FileStream(FilePath, FileMode.Open);
            
            // decrypt the stream to an object and cast as a demo object
            // we'll compare the serializations of the original and decrypted demo objects, below
            DemoObject DecryptedDemoObject = (DemoObject)Aes256EncryptionProvider.DecryptObject(SourceCipherStream, SaltText);

            Console.WriteLine("DEMO #4");
            Console.WriteLine("=======================");
            Console.WriteLine("\nDemoObject: {0}", new JavaScriptSerializer().Serialize(DemoObject));
            Console.WriteLine("\nSalt: {0}", SaltText);
            Console.WriteLine("\nCipherText: Look in the file \"{0}\"", FilePath);
            Console.WriteLine("\nDemoObject2: {0}", new JavaScriptSerializer().Serialize(DecryptedDemoObject));
            Console.WriteLine();



        }
    }
}
