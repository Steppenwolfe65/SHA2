#include "SHA2Test.h"
#include "HexConverter.h"
#include "../SHA2/SHA256.h"
#include "../SHA2/SHA512.h"
#include "../SHA2/SecureRandom.h"

namespace TestSHA2
{
	using CEX::Digest::SHA256;
	using CEX::Digest::SHA512;

	std::string SHA2Test::Run()
	{
		try
		{
			Initialize();

			SHA256* sha256 = new SHA256();
			CompareVector(sha256, m_shaMessage[0], m_shaExpected256[0]);
			CompareVector(sha256, m_shaMessage[1], m_shaExpected256[1]);
			CompareVector(sha256, m_shaMessage[2], m_shaExpected256[2]);
			CompareVector(sha256, m_shaMessage[3], m_shaExpected256[3]);
			delete sha256;
			OnProgress("Sha2Test: Passed SHA-2 256 bit digest vector tests..");

			SHA512* sha512 = new SHA512();
			CompareVector(sha512, m_shaMessage[0], m_shaExpected512[0]);
			CompareVector(sha512, m_shaMessage[1], m_shaExpected512[1]);
			CompareVector(sha512, m_shaMessage[2], m_shaExpected512[2]);
			CompareVector(sha512, m_shaMessage[3], m_shaExpected512[3]);
			delete sha512;
			OnProgress("Sha2Test: Passed SHA-2 512 bit digest vector tests..");


			/*SHA256* sks2 = new SHA256(true);
			SHA2Params sp1;
			SHA256* sks3 = new SHA256(sp1);
			CompareParallel(sks2, sks3);
			delete sks2;
			delete sks3;
			OnProgress("Passed SHA2-256 parallelization tests..");

			SHA512* skm2 = new SHA512(true);
			SHA2Params sp2;
			SHA512* skm3 = new SHA512(sp2);
			CompareParallel(skm2, skm3);
			delete skm2;
			delete skm3;
			OnProgress("Passed SHA2-512 parallelization tests..");*/


			return SUCCESS;
		}
		catch (std::string const& ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	void SHA2Test::CompareParallel(IDigest* Dgt1, IDigest* Dgt2)
	{
		std::vector<byte> hash1(Dgt1->DigestSize(), 0);
		std::vector<byte> hash2(Dgt1->DigestSize(), 0);
		const size_t PRLBLK = Dgt1->ParallelBlockSize();
		const size_t PRLMIN = Dgt1->ParallelProfile().ParallelMinimumSize();
		CEX::Prng::SecureRandom rnd;
		Dgt1->ParallelProfile().ParallelBlockSize() = PRLBLK;
		Dgt2->ParallelProfile().ParallelBlockSize() = PRLMIN;

		for (size_t i = 0; i < 100; ++i)
		{
			uint32_t prlSze = rnd.NextUInt32(PRLMIN * 2, PRLMIN * 8);
			prlSze -= (prlSze % PRLMIN);
			// set to parallel, but block will be too small.. processed with sequential fallback
			std::vector<byte> input(prlSze);
			rnd.GetBytes(input);

			Dgt1->Update(input, 0, input.size());
			Dgt1->Finalize(hash1, 0);

			// this will run in parallel
			Dgt2->Update(input, 0, input.size());
			Dgt2->Finalize(hash2, 0);

			if (hash1 != hash2)
				throw std::exception("SKein Vector: Expected hash is not equal!");

			// test partial block-size and compute method
			input.resize(input.size() + rnd.NextUInt32(1, 200), (byte)199);
			Dgt1->Compute(input, hash1);

			Dgt2->Update(input, 0, input.size());
			Dgt2->Finalize(hash2, 0);
			Dgt2->Reset();

			if (hash1 != hash2)
				throw std::exception("SKein Vector: Expected hash is not equal!");
		}
	}

	void SHA2Test::CompareVector(IDigest *Digest, std::vector<byte> Input, std::vector<byte> Expected)
	{
		std::vector<byte> hash(Digest->DigestSize(), 0);

		Digest->Update(Input, 0, Input.size());
		Digest->Finalize(hash, 0);

		if (Expected != hash)
			throw std::string("SHA2: Expected hash is not equal!");

		Digest->Compute(Input, hash);
		if (Expected != hash)
			throw std::string("SHA2: Expected hash is not equal!");
	}

	void SHA2Test::Initialize()
	{
		const char* shaMessage[4] =
		{
			("616263"),
			(""),
			("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
			("61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475")
		};
		HexConverter::Decode(shaMessage, 4, m_shaMessage);

		const char* shaExpected256[4] =
		{
			("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
			("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
			("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
		};
		HexConverter::Decode(shaExpected256, 4, m_shaExpected256);

		const char* shaExpected512[4] =
		{
			("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
			("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
			("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"),
			("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
		};
		HexConverter::Decode(shaExpected512, 4, m_shaExpected512);


		const char* macKeys[7] =
		{
			("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
			("4a656665"),
			("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			("0102030405060708090a0b0c0d0e0f10111213141516171819"),
			("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
			("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
				("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		};
		HexConverter::Decode(macKeys, 7, m_macKeys);

		const char* macInput[7] =
		{
			("4869205468657265"),
			("7768617420646f2079612077616e7420666f72206e6f7468696e673f"),
			("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
			("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
			("546573742057697468205472756e636174696f6e"),
			("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"),
			("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074" \
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365" \
				"642062792074686520484d414320616c676f726974686d2e")
		};
		HexConverter::Decode(macInput, 7, m_macInput);

		const char* mac256[7] =
		{
			("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
			("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
			("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
			("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
			("a3b6167473100ee06e0c796c2955552b"),
			("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
			("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")
		};
		HexConverter::Decode(mac256, 7, m_mac256);

		const char* mac512[7] =
		{
			("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
			("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"),
			("fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"),
			("b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"),
			("415fad6271580a531d4179bc891d87a6"),
			("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"),
			("e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58")
		};
		HexConverter::Decode(mac512, 7, m_mac512);


		const char* hkdfSalt[2] =
		{
			("000102030405060708090a0b0c"),
			("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
		};
		HexConverter::Decode(hkdfSalt, 2, m_hkdfSalt);

		const char* hkdfIkm[3] =
		{
			("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
			("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
			("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
		};
		HexConverter::Decode(hkdfIkm, 3, m_hkdfIkm);

		const char* hkdfInfo[3] =
		{
			("f0f1f2f3f4f5f6f7f8f9"),
			("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
			("")
		};
		HexConverter::Decode(hkdfInfo, 3, m_hkdfInfo);

		const char* hkdfOutput[3] =
		{
			("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
			("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
			("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
		};
		HexConverter::Decode(hkdfOutput, 3, m_hkdfOutput);
	}

	void SHA2Test::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}