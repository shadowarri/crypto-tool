/*
 * CryptoContainer.h
 *
 *  Created on: 2 окт. 2021 г.
 *      Author: shadowarri
 */

#ifndef CRYPTOCONTAINER_H_
#define CRYPTOCONTAINER_H_

#include <cstdint>

namespace crypto {

namespace container {
// MAGIC WORD: P*AA
constexpr uint32_t MAGIC_WORD = 0x00000001 * 'P' + 0x00000100 * '*' + 0x01010000 * 'A';

enum payload_type
{
	RAW = 0,
	KEY_DATA,
	PRIVATE_KEY,
	PUBLIC_KEY,
	ENCRYPTED_DATA,
	DH_PARAMS,
};

constexpr uint32_t HEADER_SIZE = 9;
constexpr uint32_t FILE_METADATA_SIZE = 24;
constexpr uint32_t KEY_METADATA_SIZE = 20;

#pragma pack(push, 1)

struct header {
	uint32_t magic_word;
	uint32_t header_size;
	uint8_t payload;
};
struct metadata_file {
	uint32_t length;
	uint64_t original_length;
	uint64_t block_count;
	uint32_t block_size;
};
struct metadata_key {
	uint64_t length;
	uint64_t block_count;
	uint32_t block_size;
};
#pragma pack(pop)

}

}

#endif /* CRYPTOCONTAINER_H_ */
