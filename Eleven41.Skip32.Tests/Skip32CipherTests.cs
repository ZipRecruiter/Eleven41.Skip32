using System;
using Xunit;

namespace Eleven41.Skip32.UnitTests
{
	public class Skip32CipherTests
	{
		// This test takes a few minutes to execute
        [Fact]
		public void null_byte_array_key()
		{
			byte[] key = null;
            Assert.Throws<ArgumentNullException>(() => new Skip32Cipher(key));
		}

		[Fact]
		public void incorrect_byte_array_key_length()
		{
			byte[] key = new byte[1];
            Assert.Throws<ArgumentOutOfRangeException>(() => new Skip32Cipher(key));
		}

		[Fact]
		public void null_hex_key()
		{
			string key = null;
            Assert.Throws<ArgumentNullException>(() => new Skip32Cipher(key, Skip32CipherKeyFormat.HexString));
		}

		[Fact]
		public void null_base64_key()
		{
			string key = null;
            Assert.Throws<ArgumentNullException>(() => new Skip32Cipher(key, Skip32CipherKeyFormat.Base64));
		}

		[Fact]
		public void empty_hex_key()
		{
			string key = "";
            Assert.Throws<ArgumentNullException>(() => new Skip32Cipher(key, Skip32CipherKeyFormat.HexString));
		}

		[Fact]
		public void empty_base64_key()
		{
			string key = "";
            Assert.Throws<ArgumentNullException>(() => new Skip32Cipher(key, Skip32CipherKeyFormat.Base64));
		}

        [Fact]
		public void incorrect_hex_key_length()
		{
			string key = "abc";
            Assert.Throws<ArgumentOutOfRangeException>(() => new Skip32Cipher(key, Skip32CipherKeyFormat.HexString));
		}

        [Fact]
		public void incorrect_base64_key_length()
		{
			string key = "abcd";
            Assert.Throws<ArgumentOutOfRangeException>(() => new Skip32Cipher(key, Skip32CipherKeyFormat.Base64));
		}

        [Fact]
		public void invalid_base64_key_length()
		{
			string key = "abcde";
            Assert.Throws<FormatException>(() => new Skip32Cipher(key, Skip32CipherKeyFormat.Base64));
		}

		// This test takes a few minutes to execute
		[Fact]
		public void test_0()
		{
			Skip32Cipher cipher = new Skip32Cipher("1234567890abcdef0123", Skip32CipherKeyFormat.HexString);

			int value0 = 0;
			int value1 = cipher.Encrypt(value0);
			int value2 = cipher.Decrypt(value1);

			// Ensure that the encryption is reversible
			Assert.Equal(value0, value2);

			// Ensure the encryption is not an identity function
			Assert.NotEqual(value0, value1);
		}

		[Fact]
		public void test_1()
		{
            Skip32Cipher cipher = new Skip32Cipher("1234567890abcdef0123", Skip32CipherKeyFormat.HexString);

			int value0 = 0;
			int value1 = cipher.Encrypt(value0);
			int value2 = cipher.Decrypt(value1);

			// Ensure that the encryption is reversible
			Assert.Equal(value0, value2);

			// Ensure the encryption is not an identity function
			Assert.NotEqual(value0, value1);
		}

		[Fact]
		public void test_random()
		{
            Skip32Cipher cipher = new Skip32Cipher("1234567890abcdef0123", Skip32CipherKeyFormat.HexString);

			Random r = new Random();
			int value0 = r.Next();
			int value1 = cipher.Encrypt(value0);
			int value2 = cipher.Decrypt(value1);

			// Ensure that the encryption is reversible
			Assert.Equal(value0, value2);

			// Ensure the encryption is not an identity function
			Assert.NotEqual(value0, value1);
		}

		[Fact]
		public void test_MinValue()
		{
            Skip32Cipher cipher = new Skip32Cipher("1234567890abcdef0123", Skip32CipherKeyFormat.HexString);

			int value0 = int.MinValue;
			int value1 = cipher.Encrypt(value0);
			int value2 = cipher.Decrypt(value1);

			// Ensure that the encryption is reversible
			Assert.Equal(value0, value2);

			// Ensure the encryption is not an identity function
			Assert.NotEqual(value0, value1);
		}

		[Fact]
		public void test_MaxValue()
		{
            Skip32Cipher cipher = new Skip32Cipher("1234567890abcdef0123", Skip32CipherKeyFormat.HexString);

			int value0 = int.MaxValue;
			int value1 = cipher.Encrypt(value0);
			int value2 = cipher.Decrypt(value1);

			// Ensure that the encryption is reversible
			Assert.Equal(value0, value2);

			// Ensure the encryption is not an identity function
			Assert.NotEqual(value0, value1);
		}
	}
}
