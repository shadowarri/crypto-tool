/*
 * main.cc
 *
 *  Created on: 2 окт. 2021 г.
 *      Author: shadowarri
 */

#include <iostream>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <random> // для std::random_device и std::mt19937

#include "CryptoContainer.h"

const char * TEST_FILE_NAME = "test.txt";
const char * TEST_CONTAINER_NAME = "test-container.si";
const char * TEST_CONTAINER_NAME_WITH_CRYPT = "test-container-crypt.si";
const char * TEST_KEY_CONTAINER_NAME = "KeyContainer.si";
constexpr uint32_t BLOCK_SIZE = 32;//БИТЫ

constexpr int t111[16] = {3, 5, 4, 8, 9, 1, 11, 13, 12, 0, 15, 2, 7, 6, 10, 14};

void create_container()
{
	using namespace crypto::container;
	std::ifstream src_file;

	src_file.open(TEST_FILE_NAME, std::ios::binary | std::ios::ate);
	size_t filesize = src_file.tellg();
	src_file.seekg(0);

	std::ofstream dst_file;
	dst_file.open(TEST_CONTAINER_NAME, std::ios::binary);

	header hdr {};
	hdr.magic_word = MAGIC_WORD;
	hdr.header_size = HEADER_SIZE;
	hdr.payload = RAW;

	dst_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE);
	metadata_file mdf {};
	uint32_t name_length = strlen(TEST_FILE_NAME);
	mdf.length = FILE_METADATA_SIZE + name_length + 1;
	mdf.original_length = filesize;
	mdf.block_size = BLOCK_SIZE;
	mdf.block_count = filesize / (BLOCK_SIZE / 8);
	if (filesize % (BLOCK_SIZE / 8) > 0)
	{
		mdf.block_count++;
	}
	dst_file.write(reinterpret_cast<char*>(&mdf), FILE_METADATA_SIZE);
	dst_file.write(TEST_FILE_NAME, name_length + 1);

	for (	uint64_t block = 0;
			block < mdf.block_count;
			++block) {
		uint8_t buffer[BLOCK_SIZE / 8] {};
		src_file.read(reinterpret_cast<char*>(&buffer[0]),
				BLOCK_SIZE /8);
		dst_file.write(reinterpret_cast<char*>(&buffer[0]),
						BLOCK_SIZE /8);
	}

	src_file.close();
	dst_file.close();
}

void create_container_with_crypt()
{
	using namespace crypto::container;
	std::ifstream src_file;

	src_file.open(TEST_FILE_NAME, std::ios::binary | std::ios::ate);
	size_t filesize = src_file.tellg();
	src_file.seekg(0);

	std::ofstream dst_file;
	dst_file.open(TEST_CONTAINER_NAME_WITH_CRYPT, std::ios::binary);

	header hdr {};
	hdr.magic_word = MAGIC_WORD;
	hdr.header_size = HEADER_SIZE;
	hdr.payload = KEY_DATA;

	dst_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE);
	metadata_file mdf {};
	uint32_t name_length = strlen(TEST_FILE_NAME);
	mdf.length = FILE_METADATA_SIZE + name_length + 1;
	mdf.original_length = filesize;
	mdf.block_size = BLOCK_SIZE;
	mdf.block_count = filesize / (BLOCK_SIZE / 8);
	if (filesize % (BLOCK_SIZE / 8) > 0)
	{
		mdf.block_count++;
	}
	dst_file.write(reinterpret_cast<char*>(&mdf), FILE_METADATA_SIZE);
	dst_file.write(TEST_FILE_NAME, name_length + 1);

	std::ifstream key_file;
	key_file.open(TEST_KEY_CONTAINER_NAME, std::ios::binary);
	header key_hdr {};
	key_file.read(reinterpret_cast<char*>(&key_hdr),
			sizeof(header));

	if (key_hdr.magic_word != MAGIC_WORD) {
		std::cerr << "KEY FILE IS WRONG" << std::endl;
		return;
	}

	if (key_hdr.payload != RAW)
	{
		std::cerr <<
				"WRONG DATA IN KEY FILE" << std::endl;
		return;
	}
	key_file.seekg(key_hdr.header_size);

	uint64_t pos_after_key_header = key_file.tellg();

	metadata_file mdk {};
	key_file.read(reinterpret_cast<char*>(&mdk),
			KEY_METADATA_SIZE);
	key_file.seekg(pos_after_key_header + mdk.length);
	uint8_t buffer_key[16] {};
	key_file.read(reinterpret_cast<char*>(&buffer_key[0]),
			16);
	for (	uint64_t block = 0;
			block < mdf.block_count;
			++block) {
		uint8_t buffer[BLOCK_SIZE / 8] {};
		src_file.readsome(reinterpret_cast<char*>(&buffer[0]),
				BLOCK_SIZE / 8);
		uint8_t *forMerge = new uint8_t[2];
		forMerge[0] = buffer[0];
		forMerge[1] = buffer[1];
		uint16_t Li =  *((uint16_t*)forMerge);

		forMerge = new uint8_t[2];
		forMerge[0] = buffer[2];
		forMerge[1] = buffer[3];
		uint16_t Ri = *((uint16_t*)forMerge);

		for (unsigned int lap = 0; lap < 8; lap++)
		{
			uint16_t x = Li;
			uint16_t F = (t111[(x >> 12) & 0x0F] << 12) +  (t111[(x >> 8) & 0x0F] << 8) + (t111[(x >> 4) & 0x0F] << 4) + t111[x & 0x0F];
			forMerge = new uint8_t[2];
			forMerge[0] = buffer_key[lap * 2];
			forMerge[1] = buffer_key[lap * 2 + 1];
			uint16_t key = *((uint16_t*)forMerge);
			F ^= key;
			F = (F << 3) | (F >> (16-3));
			uint16_t oldLi = Li;
			Li = Ri ^ F;
			Ri = oldLi;
		}
		dst_file.write(reinterpret_cast<char*>(&Ri),
						BLOCK_SIZE /16);
		dst_file.write(reinterpret_cast<char*>(&Li),
								BLOCK_SIZE /16);
	}

	src_file.close();
	dst_file.close();
}

void extract_container()
{
	using namespace crypto::container;

	std::ifstream src_file;

	src_file.open(TEST_CONTAINER_NAME, std::ios::binary);
	header hdr {};
	src_file.read(reinterpret_cast<char*>(&hdr),
			sizeof(header));

	if (hdr.magic_word != MAGIC_WORD) {
		std::cerr << "FILE IS WRONG" << std::endl;
		return;
	}

	if (hdr.payload != RAW)
	{
		std::cerr <<
				"WRONG DATA IN FILE" << std::endl;
		return;
	}
	src_file.seekg(hdr.header_size);

	uint64_t pos_after_header = src_file.tellg();

	metadata_file mdf {};
	src_file.read(reinterpret_cast<char*>(&mdf),
			FILE_METADATA_SIZE);
	std::string original_filename = "Extract_";
	char c;
	while ((c = src_file.get()))
	{
		original_filename += c;
	}

	std::ofstream dst_file;
	dst_file.open(original_filename.c_str(), std::ios::binary);
	src_file.seekg(pos_after_header + mdf.length);

	while (mdf.original_length > 0)
	{
		uint8_t buffer[BLOCK_SIZE / 8] {};
		src_file.read(reinterpret_cast<char*>(&buffer[0]),
				BLOCK_SIZE / 8);
		uint64_t bytes_to_write = std::min<unsigned long>(4UL, mdf.original_length);
		dst_file.write(reinterpret_cast<char*>(&buffer[0]),
				bytes_to_write);
		mdf.original_length -= bytes_to_write;
	}

	src_file.close();
	dst_file.close();

}

void extract_container_with_crypt()
{
	using namespace crypto::container;

	std::ifstream src_file;

	src_file.open(TEST_CONTAINER_NAME_WITH_CRYPT, std::ios::binary);
	header hdr {};
	src_file.read(reinterpret_cast<char*>(&hdr),
			sizeof(header));

	if (hdr.magic_word != MAGIC_WORD) {
		std::cerr << "FILE IS WRONG" << std::endl;
		return;
	}

	if (hdr.payload != KEY_DATA)
	{
		std::cerr <<
				"WRONG DATA IN FILE" << std::endl;
		return;
	}
	src_file.seekg(hdr.header_size);

	uint64_t pos_after_header = src_file.tellg();

	metadata_file mdf {};
	src_file.read(reinterpret_cast<char*>(&mdf),
			FILE_METADATA_SIZE);
	std::string original_filename = "Extract_with_encrypt_";
	char c;
	while ((c = src_file.get()))
	{
		original_filename += c;
	}
	src_file.seekg(pos_after_header + mdf.length);

	std::ifstream key_file;
	key_file.open(TEST_KEY_CONTAINER_NAME, std::ios::binary);
	header key_hdr {};
	key_file.read(reinterpret_cast<char*>(&key_hdr),
			sizeof(header));

	if (key_hdr.magic_word != MAGIC_WORD) {
		std::cerr << "KEY FILE IS WRONG" << std::endl;
		return;
	}

	if (key_hdr.payload != RAW)
	{
		std::cerr <<
				"WRONG DATA IN KEY FILE" << std::endl;
		return;
	}
	key_file.seekg(key_hdr.header_size);

	uint64_t pos_after_key_header = key_file.tellg();

	metadata_file mdk {};
	key_file.read(reinterpret_cast<char*>(&mdk),
			KEY_METADATA_SIZE);
	key_file.seekg(pos_after_key_header + mdk.length);
	uint8_t buffer_key[16] {};
	key_file.read(reinterpret_cast<char*>(&buffer_key[0]),
			16);

	std::ofstream dst_file;
	dst_file.open(original_filename.c_str(), std::ios::binary);
	while (mdf.original_length > 0)
	{
		uint8_t buffer[BLOCK_SIZE / 8] {};
		src_file.read(reinterpret_cast<char*>(&buffer[0]),
				BLOCK_SIZE / 8);
		uint8_t *forMerge = new uint8_t[2];
		forMerge[0] = buffer[0];
		forMerge[1] = buffer[1];
		uint16_t Li =  *((uint16_t*)forMerge);
		forMerge = new uint8_t[2];
		forMerge[0] = buffer[2];
		forMerge[1] = buffer[3];
		uint16_t Ri = *((uint16_t*)forMerge);
		for (unsigned int lap = 0; lap < 8; lap++)
		{
			uint16_t x = Li;
			uint16_t F = (t111[(x >> 12) & 0x0F] << 12) +  (t111[(x >> 8) & 0x0F] << 8) + (t111[(x >> 4) & 0x0F] << 4) + t111[x & 0x0F];
			forMerge = new uint8_t[2];
			forMerge[0] = buffer_key[15 - (lap * 2 + 1)];
			forMerge[1] = buffer_key[15 - (lap * 2)];
			uint16_t key = *((uint16_t*)forMerge);
			F ^= key;
			F = (F << 3) | (F >> (16-3));
			uint16_t oldLi = Li;
			Li = Ri ^ F;
			Ri = oldLi;
		}
		uint16_t *forMergePart = new uint16_t[2];
		forMergePart[0] = Ri;
		forMergePart[1] = Li;
		uint32_t encryptPart = *((uint32_t*)forMergePart);
		uint64_t bytes_to_write = std::min<unsigned long>(4UL, mdf.original_length);
		dst_file.write(reinterpret_cast<char*>(&encryptPart),
				bytes_to_write);
		mdf.original_length -= bytes_to_write;
	}

	src_file.close();
	dst_file.close();

}

void generate_key(uint32_t size_key)
{
	using namespace crypto::container;
	std::random_device rd;
	std::mt19937 mersenne(rd());
	std::ofstream dst_file;
	dst_file.open("KeyContainer.si", std::ios::binary);

	header hdr {};
	hdr.magic_word = MAGIC_WORD;
	hdr.header_size = HEADER_SIZE;
	hdr.payload = RAW;
	dst_file.write(reinterpret_cast<char*>(&hdr), HEADER_SIZE);

	metadata_file mdf {};
	mdf.length = KEY_METADATA_SIZE +  1;
	mdf.block_size = BLOCK_SIZE;
	mdf.block_count = size_key / (BLOCK_SIZE / 8);
	if (size_key % (BLOCK_SIZE / 8) > 0)
	{
		mdf.block_count++;
	}
	dst_file.write(reinterpret_cast<char*>(&mdf), KEY_METADATA_SIZE + 1);

	for (	uint64_t block = 0;
			block < mdf.block_count;
			++block)
	{
		uint32_t number = mersenne();
		uint8_t buffer[BLOCK_SIZE / 8] {};
		for (unsigned int i =0; i < BLOCK_SIZE / 8; i++) {
			buffer[i] = (number >> (8 * i)) & 0xFF;
		}
		dst_file.write(reinterpret_cast<char*>(&buffer[0]),
						BLOCK_SIZE / 8);
	}
	dst_file.close();
}

int main(int argc, char ** argv)
{
//	generate_key(16);
//	create_container_with_crypt();
	extract_container_with_crypt();
//	create_container();
//	extract_container();

	return 0;
}
