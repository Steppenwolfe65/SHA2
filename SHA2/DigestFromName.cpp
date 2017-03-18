#include "DigestFromName.h"
#include "SHA256.h"
#include "SHA512.h"

NAMESPACE_HELPER

IDigest* DigestFromName::GetInstance(Digests DigestType, bool Parallel)
{
	try
	{
		switch (DigestType)
		{
		case Digests::SHA256:
			return new Digest::SHA256(Parallel);
		case Digests::SHA512:
			return new Digest::SHA512(Parallel);
		default:
			throw;
		}
	}
	catch (const std::exception)
	{
		throw;
	}
}

size_t DigestFromName::GetBlockSize(Digests DigestType)
{
	try
	{
		switch (DigestType)
		{
		case Digests::SHA256:
			return 64;
		case Digests::SHA512:
			return 128;
		case Digests::None:
			return 0;
		default:
			throw;
		}
	}
	catch (const std::exception)
	{
		throw;
	}
}

size_t DigestFromName::GetDigestSize(Digests DigestType)
{
	try
	{
		switch (DigestType)
		{
		case Digests::SHA256:
			return 32;
		case Digests::SHA512:
			return 64;
		case Digests::None:
			return 0;
		default:
			throw;
		}
	}
	catch (const std::exception)
	{
		throw;
	}
}

size_t DigestFromName::GetPaddingSize(Digests DigestType)
{
	try
	{
		switch (DigestType)
		{
		case Digests::SHA256:
			return 9;
		case Digests::SHA512:
			return 17;
		default:
			throw;
		}
	}
	catch (const std::exception)
	{
		throw;
	}
}

NAMESPACE_HELPEREND