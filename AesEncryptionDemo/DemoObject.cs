using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AesEncryptionDemo
{

    /// <summary>
    /// Object used to demonstrate object encryption to a stream.
    /// </summary>
    [Serializable()]
    public class DemoObject
    {
        public string SomeName;
        public int SomeInteger;

        public Dictionary<string, int> SomeDictionary = new Dictionary<string, int>();

    }
}
