#ifndef _SHA2_INTUTILS_H
#define _SHA2_INTUTILS_H

#include "Common.h"

namespace SHA2
{
	class IntUtils
	{
	public:

		static inline void Be32ToBytes(const uint Value, std::vector<byte> &Output, const size_t OutOffset)
		{
#if defined IS_BIG_ENDIAN
			memcpy(&Output[OutOffset], &Value, sizeof(uint));
#else
			Output[OutOffset + 3] = static_cast<byte>(Value);
			Output[OutOffset + 2] = static_cast<byte>(Value >> 8);
			Output[OutOffset + 1] = static_cast<byte>(Value >> 16);
			Output[OutOffset] = static_cast<byte>(Value >> 24);
#endif
		}

		static inline void Be64ToBytes(const ulong Value, std::vector<byte> &Output, const size_t OutOffset)
		{
#if defined(IS_BIG_ENDIAN)
			memcpy(&Output[OutOffset], &Value, sizeof(ulong));
#else
			Output[OutOffset + 7] = static_cast<byte>(Value);
			Output[OutOffset + 6] = static_cast<byte>(Value >> 8);
			Output[OutOffset + 5] = static_cast<byte>(Value >> 16);
			Output[OutOffset + 4] = static_cast<byte>(Value >> 24);
			Output[OutOffset + 3] = static_cast<byte>(Value >> 32);
			Output[OutOffset + 2] = static_cast<byte>(Value >> 40);
			Output[OutOffset + 1] = static_cast<byte>(Value >> 48);
			Output[OutOffset] = static_cast<byte>(Value >> 56);
#endif
		}

		static inline uint BytesToBe32(const std::vector<byte> &Input, const size_t InOffset)
		{
#if defined(IS_BIG_ENDIAN)
			uint value = 0;
			memcpy(&value, &Input[InOffset], sizeof(uint));
			return value;
#else
			return
				(static_cast<uint>(Input[InOffset] << 24)) |
				(static_cast<uint>(Input[InOffset + 1] << 16)) |
				(static_cast<uint>(Input[InOffset + 2] << 8)) |
				(static_cast<uint>(Input[InOffset + 3]));
#endif
		}

		static inline ulong BytesToBe64(const std::vector<byte> &Input, const size_t InOffset)
		{
#if defined(IS_BIG_ENDIAN)
			ulong value = 0;
			memcpy(&value, &Input[InOffset], sizeof(ulong));
			return value;
#else
			return
				((ulong)Input[InOffset] << 56) |
				((ulong)Input[InOffset + 1] << 48) |
				((ulong)Input[InOffset + 2] << 40) |
				((ulong)Input[InOffset + 3] << 32) |
				((ulong)Input[InOffset + 4] << 24) |
				((ulong)Input[InOffset + 5] << 16) |
				((ulong)Input[InOffset + 6] << 8) |
				((ulong)Input[InOffset + 7]);
#endif
		}

		static inline uint32_t BytesToLe32(const std::vector<uint8_t> &Input, const size_t InOffset)
		{
#if defined(IS_LITTLE_ENDIAN)
			uint32_t value = 0;
			memcpy(&value, &Input[InOffset], sizeof(uint32_t));
			return value;
#else
			return
				(static_cast<uint>(Input[InOffset]) |
				(static_cast<uint>(Input[InOffset + 1] << 8)) |
				(static_cast<uint>(Input[InOffset + 2] << 16)) |
				(static_cast<uint>(Input[InOffset + 3] << 24)));
#endif
		}

		static inline uint64_t BytesToLe64(const std::vector<uint8_t> &Input, const size_t InOffset)
		{
#if defined(IS_LITTLE_ENDIAN)
			uint64_t value = 0;
			memcpy(&value, &Input[InOffset], sizeof(uint64_t));
			return value;
#else
			return
				((uint64_t)Input[InOffset]) |
				((uint64_t)Input[InOffset + 1] << 8) |
				((uint64_t)Input[InOffset + 2] << 16) |
				((uint64_t)Input[InOffset + 3] << 24) |
				((uint64_t)Input[InOffset + 4] << 32) |
				((uint64_t)Input[InOffset + 5] << 40) |
				((uint64_t)Input[InOffset + 6] << 48) |
				((uint64_t)Input[InOffset + 7] << 56);
#endif
		}

		static inline void BytesToLeUL512(const std::vector<uint8_t> &Input, const size_t InOffset, std::vector<uint32_t> &Output, const size_t OutOffset)
		{
#if defined(IS_LITTLE_ENDIAN)
			uint32_t value = 0;
			memcpy(&Output[OutOffset], &Input[InOffset], 16 * sizeof(uint32_t));
#else
			Output[OutOffset] = BytesToLe32(Input, InOffset);
			Output[OutOffset + 1] = BytesToLe32(Input, InOffset + 4);
			Output[OutOffset + 2] = BytesToLe32(Input, InOffset + 8);
			Output[OutOffset + 3] = BytesToLe32(Input, InOffset + 12);
			Output[OutOffset + 4] = BytesToLe32(Input, InOffset + 16);
			Output[OutOffset + 5] = BytesToLe32(Input, InOffset + 20);
			Output[OutOffset + 6] = BytesToLe32(Input, InOffset + 24);
			Output[OutOffset + 7] = BytesToLe32(Input, InOffset + 28);
			Output[OutOffset + 8] = BytesToLe32(Input, InOffset + 32);
			Output[OutOffset + 9] = BytesToLe32(Input, InOffset + 36);
			Output[OutOffset + 10] = BytesToLe32(Input, InOffset + 40);
			Output[OutOffset + 11] = BytesToLe32(Input, InOffset + 44);
			Output[OutOffset + 12] = BytesToLe32(Input, InOffset + 48);
			Output[OutOffset + 13] = BytesToLe32(Input, InOffset + 52);
			Output[OutOffset + 14] = BytesToLe32(Input, InOffset + 56);
			Output[OutOffset + 15] = BytesToLe32(Input, InOffset + 60);
#endif
		}

		static inline void BytesToLeULL512(const std::vector<uint8_t> &Input, const size_t InOffset, std::vector<uint64_t> &Output, size_t OutOffset)
		{
#if defined(IS_LITTLE_ENDIAN)
			uint32_t value = 0;
			memcpy(&Output[OutOffset], &Input[InOffset], 16 * sizeof(uint64_t));
#else
			Output[OutOffset] = BytesToLe64(Input, InOffset);
			Output[OutOffset + 1] = BytesToLe64(Input, InOffset + 8);
			Output[OutOffset + 2] = BytesToLe64(Input, InOffset + 16);
			Output[OutOffset + 3] = BytesToLe64(Input, InOffset + 24);
			Output[OutOffset + 4] = BytesToLe64(Input, InOffset + 32);
			Output[OutOffset + 5] = BytesToLe64(Input, InOffset + 40);
			Output[OutOffset + 6] = BytesToLe64(Input, InOffset + 48);
			Output[OutOffset + 7] = BytesToLe64(Input, InOffset + 56);
			Output[OutOffset + 8] = BytesToLe64(Input, InOffset + 64);
			Output[OutOffset + 9] = BytesToLe64(Input, InOffset + 72);
			Output[OutOffset + 10] = BytesToLe64(Input, InOffset + 80);
			Output[OutOffset + 11] = BytesToLe64(Input, InOffset + 88);
			Output[OutOffset + 12] = BytesToLe64(Input, InOffset + 96);
			Output[OutOffset + 13] = BytesToLe64(Input, InOffset + 104);
			Output[OutOffset + 14] = BytesToLe64(Input, InOffset + 112);
			Output[OutOffset + 15] = BytesToLe64(Input, InOffset + 120);
#endif
		}

		template <typename T>
		static inline void ClearVector(std::vector<T> &Obj)
		{
			if (Obj.capacity() == 0)
				return;

			static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
			memset_v(Obj.data(), 0, Obj.size() * sizeof(T));
			Obj.clear();
		}

		static inline void Le32ToBytes(const uint32_t Value, std::vector<uint8_t> &Output, const size_t OutOffset)
		{
#if defined(IS_LITTLE_ENDIAN)
			memcpy(&Output[OutOffset], &Value, sizeof(uint32_t));
#else
			Output[OutOffset] = static_cast<uint8_t>(Value);
			Output[OutOffset + 1] = static_cast<uint8_t>(Value >> 8);
			Output[OutOffset + 2] = static_cast<uint8_t>(Value >> 16);
			Output[OutOffset + 3] = static_cast<uint8_t>(Value >> 24);
#endif
		}

		static inline void Le64ToBytes(const uint64_t Value, std::vector<uint8_t> &Output, const size_t OutOffset)
		{
#if defined(IS_LITTLE_ENDIAN)
			memcpy(&Output[OutOffset], &Value, sizeof(uint64_t));
#else
			Output[OutOffset] = static_cast<uint8_t>(Value);
			Output[OutOffset + 1] = static_cast<uint8_t>(Value >> 8);
			Output[OutOffset + 2] = static_cast<uint8_t>(Value >> 16);
			Output[OutOffset + 3] = static_cast<uint8_t>(Value >> 24);
			Output[OutOffset + 4] = static_cast<uint8_t>(Value >> 32);
			Output[OutOffset + 5] = static_cast<uint8_t>(Value >> 40);
			Output[OutOffset + 6] = static_cast<uint8_t>(Value >> 48);
			Output[OutOffset + 7] = static_cast<uint8_t>(Value >> 56);
#endif
		}

		static inline void Le256ToBlock(std::vector<uint32_t> &Input, std::vector<uint8_t> &Output, size_t OutOffset)
		{
	#if defined(IS_LITTLE_ENDIAN)
			memcpy(&Output[OutOffset], &Input[0], Input.size() * sizeof(uint32_t));
	#else
			Le32ToBytes(Input[0], Output, OutOffset);
			Le32ToBytes(Input[1], Output, OutOffset + 4);
			Le32ToBytes(Input[2], Output, OutOffset + 8);
			Le32ToBytes(Input[3], Output, OutOffset + 12);
			Le32ToBytes(Input[4], Output, OutOffset + 16);
			Le32ToBytes(Input[5], Output, OutOffset + 20);
			Le32ToBytes(Input[6], Output, OutOffset + 24);
			Le32ToBytes(Input[7], Output, OutOffset + 28);
	#endif
		}

		static inline void Le512ToBlock(std::vector<uint64_t> &Input, std::vector<uint8_t> &Output, size_t OutOffset)
		{
#if defined(IS_LITTLE_ENDIAN)
			memcpy(&Output[OutOffset], &Input[0], Input.size() * sizeof(uint64_t));
#else
			Le64ToBytes(Input[0], Output, OutOffset);
			Le64ToBytes(Input[1], Output, OutOffset + 8);
			Le64ToBytes(Input[2], Output, OutOffset + 16);
			Le64ToBytes(Input[3], Output, OutOffset + 24);
			Le64ToBytes(Input[4], Output, OutOffset + 32);
			Le64ToBytes(Input[5], Output, OutOffset + 40);
			Le64ToBytes(Input[6], Output, OutOffset + 48);
			Le64ToBytes(Input[7], Output, OutOffset + 56);
#endif
		}


#if defined(HAS_MINSSE) && defined(FASTROTATE_ENABLED)
#pragma intrinsic(_rotl, _lrotl, _rotl64, _rotr, _lrotr, _rotr64)

		/// <summary>
		/// Rotate shift an unsigned 32 bit integer to the left
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline uint RotL32(uint Value, uint Shift)
		{
			return Shift ? _rotl(Value, Shift) : Value;
		}

		/// <summary>
		/// Rotate shift an unsigned 64 bit integer to the left
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline ulong RotL64(ulong Value, uint Shift)
		{
			return Shift ? _rotl64(Value, Shift) : Value;
		}

		/// <summary>
		/// Rotate shift a 32 bit integer to the right
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The right shifted integer</returns>
		static inline uint RotR32(uint Value, uint Shift)
		{
			return Shift ? _rotr(Value, Shift) : Value;
		}

		/// <summary>
		/// Rotate shift an unsigned 64 bit integer to the right
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The right shifted integer</returns>
		static inline ulong RotR64(ulong Value, uint Shift)
		{
			return Shift ? _rotr64(Value, Shift) : Value;
		}

		/// <summary>
		/// Rotate shift an unsigned 32 bit integer to the left by a positive fixed non-zero increment
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Y">The number of bits to shift, shift can not be zero</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline uint RotFL32(uint Value, uint Shift)
		{
			return _lrotl(Value, Shift);
		}

		/// <summary>
		/// Rotate shift an unsigned 64 bit integer to the left by a positive fixed non-zero increment
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline ulong RotFL64(ulong Value, int Shift)
		{
			return _rotl64(Value, Shift);
		}

		/// <summary>
		/// Rotate shift an unsigned 32 bit integer to the right by a positive fixed non-zero increment
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
		/// 
		/// <returns>The right shifted integer</returns>
		static inline uint RotFR32(uint Value, uint Shift)
		{
			return _lrotr(Value, Shift);
		}

		/// <summary>
		/// Rotate shift an unsigned 64 bit integer to the right by a positive fixed non-zero increment
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift, shift can not be zero</param>
		/// 
		/// <returns>The right shifted 64 bit integer</returns>
		static inline ulong RotFR64(ulong Value, uint Shift)
		{
			return _rotr64(Value, Shift);
		}

#elif defined(PPC_INTRINSICS) && defined(FASTROTATE_ENABLED)
		/// <summary>
		/// Rotate shift an unsigned 32 bit integer to the left
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline uint RotL32(uint Value, uint Shift)
		{
			return Shift ? __rlwinm(Value, Shift, 0, 31) : Value;
		}

		/// <summary>
		/// Rotate shift an unsigned 64 bit integer to the left
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline ulong RotL64(ulong Value, uint Shift)
		{
			return Shift ? __rlwinm(Value, Shift, 0, 63) : Value;
		}

		/// <summary>
		/// Rotate shift a 32 bit integer to the right
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The right shifted integer</returns>
		static inline uint RotR32(uint Value, uint Shift)
		{
			return Shift ? __rlwinm(Value, 32 - Shift, 0, 31) : Value;
		}

		/// <summary>
		/// Rotate shift a 64 bit long integer to the right
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The right shifted integer</returns>
		static inline ulong RotR64(ulong Value, uint Shift)
		{
			return Shift ? __rlwinm(Value, 64 - Shift, 0, 63) : Value;
		}

		/// <summary>
		/// Rotate shift an unsigned 32 bit integer to the left
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline uint RotFL32(uint Value, uint Shift)
		{
			return __rlwinm(Value, Shift, 0, 31);
		}

		/// <summary>
		/// Rotate shift an unsigned 64 bit integer to the left
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline ulong RotFL64(ulong Value, uint Shift)
		{
			return (Value << Shift) | ((long)((ulong)Value >> -Shift));
		}

		/// <summary>
		/// Rotate shift an unsigned 32 bit integer to the right
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The right shifted integer</returns>
		static inline uint RotFR32(uint Value, uint Shift)
		{
			return __rlwinm(Value, 32 - Shift, 0, 31);
		}

		/// <summary>
		/// Rotate shift an unsigned 64 bit integer to the right
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The right shifted 64 bit integer</returns>
		static inline ulong RotFR64(ulong Value, uint Shift)
		{
			return ((Value >> Shift) | (Value << (64 - Shift)));
		}

#else
		/// <summary>
		/// Rotate shift an unsigned 32 bit integer to the left
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline uint RotL32(uint Value, uint Shift)
		{
			return (Value << Shift) | (Value >> (sizeof(uint) * 8 - Shift));
		}

		/// <summary>
		/// Rotate shift an unsigned 64 bit integer to the left
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline ulong RotL64(ulong Value, uint Shift)
		{
			return (Value << Shift) | (Value >> (sizeof(ulong) * 8 - Shift));
		}

		/// <summary>
		/// Rotate shift a 32 bit integer to the right
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The right shifted integer</returns>
		static inline uint RotR32(uint Value, uint Shift)
		{
			return (Value >> Shift) | (Value << (sizeof(uint) * 8 - Shift));
		}

		/// <summary>
		/// Rotate shift a 64 bit long integer to the right
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The right shifted integer</returns>
		static inline ulong RotR64(ulong Value, uint Shift)
		{
			return (Value >> Shift) | (Value << (sizeof(ulong) * 8 - Shift));
		}

		/// <summary>
		/// Rotate shift an unsigned 32 bit integer to the left
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline uint RotFL32(uint Value, uint Shift)
		{
			return (Value << Shift) | (Value >> (32 - Shift));
		}

		/// <summary>
		/// Rotate shift an unsigned 64 bit integer to the left
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The left shifted integer</returns>
		static inline ulong RotFL64(ulong Value, uint Shift)
		{
			return (Value << Shift) | (Value >> (64 - Shift));
		}

		/// <summary>
		/// Rotate shift an unsigned 32 bit integer to the right
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The right shifted integer</returns>
		static inline uint RotFR32(uint Value, uint Shift)
		{
			return (Value >> Shift) | (Value << (32 - Shift));
		}

		/// <summary>
		/// Rotate shift an unsigned 64 bit integer to the right
		/// </summary>
		/// 
		/// <param name="Value">The initial value</param>
		/// <param name="Shift">The number of bits to shift</param>
		/// 
		/// <returns>The right shifted 64 bit integer</returns>
		static inline ulong RotFR64(ulong Value, uint Shift)
		{
			return ((Value >> Shift) | (Value << (64 - Shift)));
		}
#endif

	};
}
#endif