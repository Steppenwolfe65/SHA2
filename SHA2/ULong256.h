#ifndef _CEXENGINE_UINT256_H
#define _CEXENGINE_UINT256_H

#include "Common.h"
#include "Intrinsics.h"

namespace SHA2
{
	/// <summary>
	/// An AVX 256 intrinsics wrapper
	/// </summary>
	class ULong256
	{
	private:
		__m256i Register;

	public:

		/* Constructor */

		/// <summary>
		/// Empty Constructor; register is not initialized
		/// </summary>
		ULong256()
		{
		}

		/// <summary>
		/// Initialize with an __m256i integer
		/// </summary>
		///
		/// <param name="Register">The register to copy</param>
		ULong256(__m256i Input)
		{
			this->Register = Input;
		}

		/// <summary>
		/// Initialize with an 8bit unsigned integer array
		/// </summary>
		///
		/// <param name="Input">The array containing the data; must be at least 16 bytes</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		ULong256(const std::vector<byte> &Input, size_t Offset)
		{
			Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
		}

		/// <summary>
		/// Initialize with a 64bit unsigned integer array
		/// </summary>
		///
		/// <param name="Input">The array containing the data; must be at least 2 * 64bit uints</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		ULong256(const std::vector<ulong> &Input, size_t Offset)
		{
			Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
		}

		/// <summary>
		/// Initialize with 4 * 64bit unsigned integers
		/// </summary>
		///
		/// <param name="X0">ulong 0</param>
		/// <param name="X1">ulong 1</param>
		/// <param name="X2">ulong 2</param>
		/// <param name="X3">ulong 3</param>
		ULong256(ulong X0, ulong X1, ulong X2, ulong X3)
		{
			Register = _mm256_set_epi64x(X0, X1, X2, X3);
		}

		/// <summary>
		/// Initialize with 1 * 64bit unsigned integer
		/// </summary>
		///
		/// <param name="X">The uint to add</param>
		ULong256(ulong X)
		{
			Register = _mm256_set1_epi64x(X);
		}

		/* Load and Store */

		/// <summary>
		/// Load an array into a register in Big Endian format
		/// </summary>
		///
		/// <param name="Input">The array containing the data; must be at least 256 bits in length</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		template <typename T>
		void LoadBE(const std::vector<T> &Input, size_t Offset)
		{
			Swap().LoadLE(Input, Offset);
		}

		/// <summary>
		/// Initialize with 4 * 64bit unsigned integers in Big Endian format
		/// </summary>
		///
		/// <param name="X0">uint64 0</param>
		/// <param name="X1">uint64 1</param>
		/// <param name="X2">uint64 2</param>
		/// <param name="X3">uint64 3</param>
		void LoadBE(ulong X0, ulong X1, ulong X2, ulong X3)
		{
			Swap().LoadLE(X0, X1, X2, X3);
		}

		/// <summary>
		/// Load an array into a register in Little Endian format
		/// </summary>
		///
		/// <param name="Input">The array containing the data; must be at least 256 bits in length</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		template <typename T>
		void LoadLE(const std::vector<T> &Input, size_t Offset)
		{
			Register = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&Input[Offset]));
		}

		/// <summary>
		/// Load with 4 * 64bit unsigned integers in Little Endian format
		/// </summary>
		///
		/// <param name="X0">uint64 0</param>
		/// <param name="X1">uint64 1</param>
		/// <param name="X2">uint64 2</param>
		/// <param name="X3">uint64 3</param>
		void LoadLE(ulong X0, ulong X1, ulong X2, ulong X3)
		{
			Register = _mm256_set_epi64x(X0, X1, X2, X3);
		}

		/// <summary>
		/// Store register in an integer array in Big Endian format
		/// </summary>
		///
		/// <param name="Input">The array containing the data; must be at least 256 bits in length</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		template <typename T>
		void StoreBE(std::vector<T> &Output, size_t Offset) const
		{
			Swap().StoreLE(Output, Offset);
		}

		/// <summary>
		/// Store register in an integer array in Little Endian format
		/// </summary>
		///
		/// <param name="Input">The array containing the data; must be at least 256 bits in length</param>
		/// <param name="Offset">The starting offset within the Input array</param>
		template <typename T>
		void StoreLE(std::vector<T> &Output, size_t Offset) const
		{
			_mm256_storeu_si256(reinterpret_cast<__m256i*>(&Output[Offset]), Register);
		}

		/* Methods */

		/// <summary>
		/// Computes the bitwise AND of the 256-bit value in *this* and the bitwise NOT of the 256-bit value in Value
		/// </summary>
		///
		/// <param name="Value">The comparison integer</param>
		/// 
		/// <returns>The processed ULong256</returns>
		ULong256 AndNot(const ULong256 &Value)
		{
			return ULong256(_mm256_andnot_si256(Register, Value.Register));
		}

		/// <summary>
		/// Returns the length of the register in bytes
		/// </summary>
		///
		/// <returns>The registers size</returns>
		static inline const size_t Length()
		{
			return 32;
		}

		/// <summary>
		/// Computes the 64 bit left rotation of four unsigned integers
		/// </summary>
		///
		/// <param name="Shift">The shift degree; maximum is 64</param>
		void Rotl64(const int Shift)
		{
			Register = _mm256_or_si256(_mm256_slli_epi64(Register, static_cast<int>(Shift)), _mm256_srli_epi64(Register, static_cast<int>(64 - Shift)));
		}

		/// <summary>
		/// Computes the 64 bit left rotation of four unsigned integers
		/// </summary>
		///
		/// <param name="Value">The integer to rotate</param>
		/// <param name="Shift">The shift degree; maximum is 64</param>
		/// 
		/// <returns>The rotated ULong256</returns>
		static inline ULong256 Rotl64(const ULong256 &Value, const int Shift)
		{
			return ULong256(_mm256_or_si256(_mm256_slli_epi64(Value.Register, static_cast<int>(Shift)), _mm256_srli_epi64(Value.Register, static_cast<int>(64 - Shift))));
		}

		/// <summary>
		/// Computes the 64 bit right rotation of four unsigned integers
		/// </summary>
		///
		/// <param name="Shift">The shift degree; maximum is 64</param>
		void Rotr64(const int Shift)
		{
			Rotl64(64 - Shift);
		}

		/// <summary>
		/// Computes the 64 bit right rotation of four unsigned integers
		/// </summary>
		///
		/// <param name="Value">The integer to rotate</param>
		/// <param name="Shift">The shift degree; maximum is 64</param>
		/// 
		/// <returns>The rotated ULong256</returns>
		static inline ULong256 Rotr64(const ULong256 &Value, const int Shift)
		{
			return Rotl64(Value, 64 - Shift);
		}

		/// <summary>
		/// Load a Uint256 in Big Endian format using uint staggered at multiples of the shift factor
		/// </summary>
		///
		/// <param name="Input">The input byte array</param>
		/// <param name="Offset">The starting offset within the input array</param>
		/// <param name="Shift">The shift factor</param>
		/// 
		/// <returns>A populated UInt128</returns>
		static inline ULong256 ShuffleLoadBE(const std::vector<byte> &Input, size_t Offset, size_t Shift)
		{
			return ULong256(
				((ulong)Input[Offset] << 56) |
				((ulong)Input[Offset + 1] << 48) | 
				((ulong)Input[Offset + 2] << 40) | 
				((ulong)Input[Offset + 3] << 32) | 
				((ulong)Input[Offset + 4] << 24) | 
				((ulong)Input[Offset + 5] << 16) | 
				((ulong)Input[Offset + 6] << 8) | 
				((ulong)Input[Offset + 7]),
				((ulong)Input[Offset + Shift] << 56) | 
				((ulong)Input[Offset + Shift + 1] << 48) | 
				((ulong)Input[Offset + Shift + 2] << 40) | 
				((ulong)Input[Offset + Shift + 3] << 32) | 
				((ulong)Input[Offset + Shift + 4] << 24) | 
				((ulong)Input[Offset + Shift + 5] << 16) | 
				((ulong)Input[Offset + Shift + 6] << 8) | 
				((ulong)Input[Offset + Shift + 7]),
				((ulong)Input[Offset + Shift * 2] << 56) | 
				((ulong)Input[Offset + Shift * 2 + 1] << 48) | 
				((ulong)Input[Offset + Shift * 2 + 2] << 40) | 
				((ulong)Input[Offset + Shift * 2 + 3] << 32) | 
				((ulong)Input[Offset + Shift * 2 + 4] << 24) | 
				((ulong)Input[Offset + Shift * 2 + 5] << 16) | 
				((ulong)Input[Offset + Shift * 2 + 6] << 8) | 
				((ulong)Input[Offset + Shift * 2 + 7]),
				((ulong)Input[Offset + Shift * 3] << 56) | 
				((ulong)Input[Offset + Shift * 3 + 1] << 48) | 
				((ulong)Input[Offset + Shift * 3 + 2] << 40) | 
				((ulong)Input[Offset + Shift * 3 + 3] << 32) | 
				((ulong)Input[Offset + Shift * 3 + 4] << 24) | 
				((ulong)Input[Offset + Shift * 3 + 5] << 16) | 
				((ulong)Input[Offset + Shift * 3 + 6] << 8) | 
				((ulong)Input[Offset + Shift * 3 + 7])
			);
		}

		/// <summary>
		/// Load a Uint256 in Little Endian format using uint staggered at multiples of the shift factor
		/// </summary>
		///
		/// <param name="Input">The input byte array</param>
		/// <param name="Offset">The starting offset within the input array</param>
		/// <param name="Shift">The shift factor</param>
		/// 
		/// <returns>A populated UInt128</returns>
		static inline ULong256 ShuffleLoadLE(const std::vector<byte> &Input, size_t Offset, size_t Shift)
		{
			return ULong256(
				((ulong)Input[Offset]) |
				((ulong)Input[Offset + 1] << 8) |
				((ulong)Input[Offset + 2] << 16) |
				((ulong)Input[Offset + 3] << 24) |
				((ulong)Input[Offset + 4] << 32) |
				((ulong)Input[Offset + 5] << 40) |
				((ulong)Input[Offset + 6] << 48) |
				((ulong)Input[Offset + 7] << 56),
				((ulong)Input[Offset + Shift]) |
				((ulong)Input[Offset + Shift + 1] << 8) |
				((ulong)Input[Offset + Shift + 2] << 16) |
				((ulong)Input[Offset + Shift + 3] << 24) |
				((ulong)Input[Offset + Shift + 4] << 32) |
				((ulong)Input[Offset + Shift + 5] << 40) |
				((ulong)Input[Offset + Shift + 6] << 48) |
				((ulong)Input[Offset + Shift + 7] << 56),
				((ulong)Input[Offset + Shift * 2]) |
				((ulong)Input[Offset + Shift * 2 + 1] << 8) |
				((ulong)Input[Offset + Shift * 2 + 2] << 16) |
				((ulong)Input[Offset + Shift * 2 + 3] << 24) |
				((ulong)Input[Offset + Shift * 2 + 4] << 32) |
				((ulong)Input[Offset + Shift * 2 + 5] << 40) |
				((ulong)Input[Offset + Shift * 2 + 6] << 48) |
				((ulong)Input[Offset + Shift * 2 + 7] << 56),
				((ulong)Input[Offset + Shift * 3]) |
				((ulong)Input[Offset + Shift * 3 + 1] << 8) |
				((ulong)Input[Offset + Shift * 3 + 2] << 16) |
				((ulong)Input[Offset + Shift * 3 + 3] << 24) |
				((ulong)Input[Offset + Shift * 3 + 4] << 32) |
				((ulong)Input[Offset + Shift * 3 + 5] << 40) |
				((ulong)Input[Offset + Shift * 3 + 6] << 48) |
				((ulong)Input[Offset + Shift * 3 + 7] << 56)
			);
		}

		/// <summary>
		/// Performs a byte swap on 4 unsigned integers
		/// </summary>
		/// 
		/// <returns>The byte swapped ULong256</returns>
		ULong256 Swap() const
		{
			__m256i T = Register;

			T = _mm256_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
			T = _mm256_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

			return ULong256(_mm256_or_si256(_mm256_srli_epi16(T, 8), _mm256_slli_epi16(T, 8)));
		}

		/// <summary>
		/// Performs a byte swap on 4 unsigned integers
		/// </summary>
		/// 		
		/// <param name="R">The ULong256 to process</param>
		/// 
		/// <returns>The byte swapped ULong256</returns>
		static inline ULong256 Swap(ULong256 &R)
		{
			__m256i T = R.Register;

			T = _mm256_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
			T = _mm256_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

			return ULong256(_mm256_or_si256(_mm256_srli_epi16(T, 8), _mm256_slli_epi16(T, 8)));
		}

		/// <summary>
		/// Copies the register uint8 array to an output array
		/// </summary>
		///
		/// <param name="Input">The output byte array</param>
		/// <param name="Offset">The starting offset within the output array</param>
		void ToUint8(std::vector<byte> &Output, size_t OutOffset)
		{
			memcpy(&Output[OutOffset], &Register.m256i_u8[0], 32);
		}

		/// <summary>
		/// Copies the register uint16 array to an output array
		/// </summary>
		///
		/// <param name="Input">The output byte array</param>
		/// <param name="Offset">The starting offset within the output array</param>
		void ToUint16(std::vector<ushort> &Output, size_t OutOffset)
		{
			memcpy(&Output[OutOffset], &Register.m256i_u16[0], 32);
		}

		/// <summary>
		/// Copies the register uint32 array to an output array
		/// </summary>
		///
		/// <param name="Input">The output byte array</param>
		/// <param name="Offset">The starting offset within the output array</param>
		void ToUint32(std::vector<uint> &Output, size_t OutOffset)
		{
			memcpy(&Output[OutOffset], &Register.m256i_u32[0], 32);
		}

		/// <summary>
		/// Copies the register uint64 array to an output array
		/// </summary>
		///
		/// <param name="Input">The output byte array</param>
		/// <param name="Offset">The starting offset within the output array</param>
		void ToUint64(std::vector<ulong> &Output, size_t OutOffset)
		{
			memcpy(&Output[OutOffset], &Register.m256i_u64[0], 32);
		}

		/* Operators */

		void operator += (const ULong256 &Value)
		{
			Register = _mm256_add_epi64(Register, Value.Register);
		}

		ULong256 operator + (const ULong256 &Value) const
		{
			return ULong256(_mm256_add_epi64(Register, Value.Register));
		}

		void operator -= (const ULong256 &Value)
		{
			Register = _mm256_sub_epi64(Register, Value.Register);
		}

		ULong256 operator - (const ULong256 &Value) const
		{
			return ULong256(_mm256_sub_epi64(Register, Value.Register));
		}

		void operator *= (const ULong256 &Value)
		{
			__m256i tmp1 = _mm256_mul_epu32(Register, Value.Register);
			__m256i tmp2 = _mm256_mul_epu32(_mm256_srli_si256(Register, 4), _mm256_srli_si256(Value.Register, 4));
			Register = _mm256_unpacklo_epi32(_mm256_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm256_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0)));
		}

		ULong256 operator * (const ULong256 &Value) const
		{
			__m256i tmp1 = _mm256_mul_epu32(Register, Value.Register);
			__m256i tmp2 = _mm256_mul_epu32(_mm256_srli_si256(Register, 4), _mm256_srli_si256(Value.Register, 4));
			return ULong256(_mm256_unpacklo_epi32(_mm256_shuffle_epi32(tmp1, _MM_SHUFFLE(0, 0, 2, 0)), _mm256_shuffle_epi32(tmp2, _MM_SHUFFLE(0, 0, 2, 0))));
		}

		void operator /= (const ULong256 &Value)
		{
			//ToDo: finish
			Register.m256i_u64[0] /= Value.Register.m256i_u64[0];
			Register.m256i_u64[1] /= Value.Register.m256i_u64[1];
			Register.m256i_u64[2] /= Value.Register.m256i_u64[2];
			Register.m256i_u64[3] /= Value.Register.m256i_u64[3];

		}

		ULong256 operator / (const ULong256 &Value) const
		{
			//ToDo: finish
			return ULong256(
				Register.m256i_u64[0] / Value.Register.m256i_u64[0],
				Register.m256i_u64[1] / Value.Register.m256i_u64[1],
				Register.m256i_u64[2] / Value.Register.m256i_u64[2],
				Register.m256i_u64[3] / Value.Register.m256i_u64[3]
			);
		}

		void operator %= (const ULong256 &Value)
		{
			//ToDo: finish
			Register.m256i_u64[0] %= Value.Register.m256i_u64[0];
			Register.m256i_u64[1] %= Value.Register.m256i_u64[1];
			Register.m256i_u64[2] %= Value.Register.m256i_u64[2];
			Register.m256i_u64[3] %= Value.Register.m256i_u64[3];
		}

		ULong256 operator % (const ULong256 &Value) const
		{
			//ToDo: finish
			return ULong256(
				Register.m256i_u64[0] % Value.Register.m256i_u64[0],
				Register.m256i_u64[1] % Value.Register.m256i_u64[1],
				Register.m256i_u64[2] % Value.Register.m256i_u64[2],
				Register.m256i_u64[3] % Value.Register.m256i_u64[3]
			);
		}

		void operator ^= (const ULong256 &Value)
		{
			Register = _mm256_xor_si256(Register, Value.Register);
		}

		ULong256 operator ^ (const ULong256 &Value) const
		{
			return ULong256(_mm256_xor_si256(Register, Value.Register));
		}

		void operator |= (const ULong256 &Value)
		{
			Register = _mm256_or_si256(Register, Value.Register);
		}

		ULong256 operator | (const ULong256 &Value)
		{
			return ULong256(_mm256_or_si256(Register, Value.Register));
		}

		void operator &= (const ULong256 &Value)
		{
			Register = _mm256_and_si256(Register, Value.Register);
		}

		ULong256 operator & (const ULong256 &Value)
		{
			return ULong256(_mm256_and_si256(Register, Value.Register));
		}

		void operator <<= (const int Shift)
		{
			Register = _mm256_slli_epi64(Register, Shift);
		}

		ULong256 operator << (const int Shift) const
		{
			return ULong256(_mm256_slli_epi64(Register, Shift));
		}

		void operator >>= (const int Shift)
		{
			Register = _mm256_srli_epi64(Register, Shift);
		}

		ULong256 operator >> (const int Shift) const
		{
			return ULong256(_mm256_srli_epi64(Register, Shift));
		}

		ULong256 operator ~ () const
		{
			return ULong256(_mm256_xor_si256(Register, _mm256_set1_epi32(0xFFFFFFFF)));
		}
	};
}
#endif