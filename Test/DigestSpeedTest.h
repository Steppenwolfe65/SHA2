#ifndef _SHA2TEST_DIGESTSPEEDTEST_H
#define _SHA2TEST_DIGESTSPEEDTEST_H

#include "ITest.h"
#include "../SHA2/Digests.h"

namespace Test
{
	using CEX::Enumeration::Digests;

	/// <summary>
	/// SHA2 Digest Speed Tests
	/// </summary>
	class DigestSpeedTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "Digest Speed Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string MESSAGE = "COMPLETE! Speed tests have executed succesfully.";
		static constexpr uint64_t KB1 = 1000;
		static constexpr uint64_t MB1 = KB1 * 1000;
		static constexpr uint64_t MB10 = MB1 * 10;
		static constexpr uint64_t MB100 = MB1 * 100;
		static constexpr uint64_t GB1 = MB1 * 1000;
		static constexpr uint64_t GB10 = GB1 * 10;
		static constexpr uint64_t DEFITER = 10;

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
		/// Test SHA2 for performance
		/// </summary>
		DigestSpeedTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				OnProgress("***The sequential SHA2 256 digest***");
				DigestBlockLoop(Digests::SHA256, MB100, 10, false);
				OnProgress("***The parallel Skein 256 digest***");
				DigestBlockLoop(Digests::SHA256, MB100, 10, true);
				OnProgress("***The sequential SHA2 512 digest***");
				DigestBlockLoop(Digests::SHA512, MB100, 10, false);
				OnProgress("***The parallel SHA2 512 digest***");
				DigestBlockLoop(Digests::SHA512, MB100, 10, true);

				return MESSAGE;
			}
			catch (std::string &ex)
			{
				return FAILURE + " : " + ex;
			}
			catch (...)
			{
				return FAILURE + " : Internal Error";
			}
		}

	private:

		void DigestSpeedTest::DigestBlockLoop(Digests DigestType, size_t SampleSize, size_t Loops, bool Parallel);
		uint64_t GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize);
		void OnProgress(char* Data);
	};
}

#endif