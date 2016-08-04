#ifndef _SHA2TEST_BLAKETEST_H
#define _SHA2TEST_BLAKETEST_H

#include "ITest.h"
#include "../SHA2/IDigest.h"

namespace TestSHA2
{
	/// <summary>
	/// Tests the SHA-2 digest implementation using vector comparisons.
	/// <para>Using vectors from NIST SHA2 Documentation:
	/// <para><see href="http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf"/></para>
	/// </summary>
	class SHA2Test : public ITest
	{
	private:
		const std::string DESCRIPTION = "Tests SHA-2 256/512 with NIST KAT vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All SHA-2 tests have executed succesfully.";

		std::vector<std::vector<byte>> m_shaExpected256;
		std::vector<std::vector<byte>> m_shaExpected512;
		std::vector<std::vector<byte>> m_shaMessage;
		std::vector<std::vector<byte>> m_mac256;
		std::vector<std::vector<byte>> m_mac512;
		std::vector<std::vector<byte>> m_macKeys;
		std::vector<std::vector<byte>> m_macInput;
		std::vector<std::vector<byte>> m_hkdfIkm;
		std::vector<std::vector<byte>> m_hkdfInfo;
		std::vector<std::vector<byte>> m_hkdfOutput;
		std::vector<std::vector<byte>> m_hkdfSalt;
		TestEventHandler m_progressEvent;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return m_progressEvent; }

		/// <summary>
		/// Known answer tests using the NIST SHA-2 KAT vectors
		/// </summary>
		SHA2Test()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~SHA2Test()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareHkdf(int Size, std::vector<byte> &Salt, std::vector<byte> &Key, std::vector<byte> &Info, std::vector<byte> &Output);
		void CompareIntrinsics();
		void CompareMac256(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Expected);
		void CompareMac512(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Expected);
		void CompareSHA(SHA2::IDigest *Digest, std::vector<byte> Input, std::vector<byte> Expected);
		void Initialize();
		void OnProgress(char* Data);
	};
}
#endif
