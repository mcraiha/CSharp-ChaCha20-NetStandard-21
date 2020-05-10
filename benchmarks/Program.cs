using System;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using CSChaCha20;
using CSChaCha20_NS21;
using ChaCha20Cipher;

namespace benchmarks
{
    [MemoryDiagnoser]
    public class Original_Vs_NS20_Vs_NS21
    {
        private const int dataLength1 = 64;
        private const int dataLength2 = 1024;
        private const int dataLength3 = 1024*1024;

        private readonly byte[] data1;
        private readonly byte[] data2;
        private readonly byte[] data3;

        private readonly ChaCha20Cipher.ChaCha20Cipher original1 = null;
        private readonly ChaCha20Cipher.ChaCha20Cipher original2 = null;
        private readonly ChaCha20Cipher.ChaCha20Cipher original3 = null;

        private readonly CSChaCha20.ChaCha20 ns_20_1 = null;
        private readonly CSChaCha20.ChaCha20 ns_20_2 = null;
        private readonly CSChaCha20.ChaCha20 ns_20_3 = null;

        private readonly CSChaCha20_NS21.ChaCha20 ns_21_1 = null;
        private readonly CSChaCha20_NS21.ChaCha20 ns_21_2 = null;
        private readonly CSChaCha20_NS21.ChaCha20 ns_21_3 = null;



        private static readonly byte[] key = new byte[32] { 
                                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
														0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
														0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
														0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
                                                        };
        
        private static readonly byte[] nonce = new byte[12] { 0x00, 0x09, 0x00, 0x00, 0xFF, 0x20, 0x12, 0x00, 0x00, 0x8b, 0x00, 0x02 };
        private static readonly uint counter = 13;

        private byte[] outputForOriginal1;
        private byte[] outputForOriginal2;
        private byte[] outputForOriginal3;

        private byte[] outputForNS_20_1;
        private byte[] outputForNS_20_2;
        private byte[] outputForNS_20_3;

        private byte[] outputForNS_21_1;
        private byte[] outputForNS_21_2;
        private byte[] outputForNS_21_3;

        public Original_Vs_NS20_Vs_NS21()
        {
            // Arrays for outputs
            this.outputForOriginal1 = new byte[dataLength1];
            this.outputForOriginal2 = new byte[dataLength2];
            this.outputForOriginal3 = new byte[dataLength3];

            this.outputForNS_20_1 = new byte[dataLength1];
            this.outputForNS_20_2 = new byte[dataLength2];
            this.outputForNS_20_3 = new byte[dataLength3];

            this.outputForNS_21_1 = new byte[dataLength1];
            this.outputForNS_21_2 = new byte[dataLength2];
            this.outputForNS_21_3 = new byte[dataLength3];

            // Generate inputs
            Random rng = new Random(Seed: 1337);

            this.data1 = new byte[dataLength1];
            rng.NextBytes(this.data1);

            this.data2 = new byte[dataLength2];
            rng.NextBytes(this.data2);

            this.data3 = new byte[dataLength3];
            rng.NextBytes(this.data3);

            // Set encrypters
            this.original1 = new ChaCha20Cipher.ChaCha20Cipher(key, nonce, counter);
            this.original2 = new ChaCha20Cipher.ChaCha20Cipher(key, nonce, counter);
            this.original3 = new ChaCha20Cipher.ChaCha20Cipher(key, nonce, counter);

            this.ns_20_1 = new CSChaCha20.ChaCha20(key, nonce, counter);
            this.ns_20_2 = new CSChaCha20.ChaCha20(key, nonce, counter);
            this.ns_20_3 = new CSChaCha20.ChaCha20(key, nonce, counter);

            this.ns_21_1 = new CSChaCha20_NS21.ChaCha20(key, nonce, counter);
            this.ns_21_2 = new CSChaCha20_NS21.ChaCha20(key, nonce, counter);
            this.ns_21_3 = new CSChaCha20_NS21.ChaCha20(key, nonce, counter);
        }

    #region 64 bytes
        [Benchmark]
        public void Original_64_Bytes() => this.original1.EncryptBytes(this.outputForOriginal1, this.data1, dataLength1);

        [Benchmark]
        public void NS20_64_Bytes() => this.ns_20_1.EncryptBytes(this.outputForNS_20_1, this.data1, dataLength1);

        [Benchmark]
        public void NS21_64_Bytes() => this.ns_21_1.EncryptBytes(this.outputForNS_21_1, this.data1, dataLength1);

    #endregion // 64 bytes

    #region 1024 bytes
        [Benchmark]
        public void Original_1024_Bytes() => this.original2.EncryptBytes(this.outputForOriginal2, this.data2, dataLength2);

        [Benchmark]
        public void NS20_1024_Bytes() => this.ns_20_2.EncryptBytes(this.outputForNS_20_2, this.data2, dataLength2);

        [Benchmark]
        public void NS21_1024_Bytes() => this.ns_21_2.EncryptBytes(this.outputForNS_21_2, this.data2, dataLength2);

    #endregion // 1024 bytes

    #region 1 MiB
        [Benchmark]
        public void Original_1MiB_Bytes() => this.original3.EncryptBytes(this.outputForOriginal3, this.data3, dataLength3);

        [Benchmark]
        public void NS20_1Mib_Bytes() => this.ns_20_3.EncryptBytes(this.outputForNS_20_3, this.data3, dataLength3);

        [Benchmark]
        public void NS21_1Mib_Bytes() => this.ns_21_3.EncryptBytes(this.outputForNS_21_3, this.data3, dataLength3);

    #endregion // 1 MiB
    }

    class Program
    {
        static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<Original_Vs_NS20_Vs_NS21>();
        }
    }
}
