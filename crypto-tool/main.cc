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
#include <iomanip>
#include <random> // для std::random_device и std::mt19937

#include "CryptoContainer.h"

namespace crypto
{
namespace utils
{

void generarate_crc32_lut(uint32_t * table)
{
	using crypto::container::CRC32_POLY;
	for (unsigned i = 0; i < 256; ++i)
	{
		uint32_t b = i;
		for (unsigned j = 0; j < 8; ++j)
		{
			if (b & 1)
			{
				b = (b >> 1) ^ CRC32_POLY;
			}
			else
			{
				b = (b >> 1);
			}
			table[i] = b;
		}
	}
}
uint32_t update_crc32(uint32_t *table, uint8_t b, uint32_t crc)
{
	crc = table[(crc ^ b) & 0xff];
	return crc;
}
}
}

const char * TEST_FILE_NAME = "test.txt";
const char * TEST_CONTAINER_NAME = "test-container.si";
const char * TEST_KEY_CONTAINER_NAME = "KeyContainer.si";
constexpr uint32_t BLOCK_SIZE = 32;//БИТЫ

constexpr int t111[16] = {	3, 5, 4, 8, 9, 1, 11, 13, 12, 0, 15, 2, 7, 6, 10, 14 };
const char * CRYPT_NAME[4] = {"", "ECB_", "CBC_", "CTR_"};
const char * IV = "abcd";

enum crypt_types
{
	RAW_CRYPT = 0,
	ECB_CRYPT,
	CBC_CRYPT,
	CTR_CRYPT
};

int crypt_type = 1;

int get_int(const char *question) {
	int result;
	std::string inp;
	re: std::cout << question;
	std::getline(std::cin, inp);
	{
		std::stringstream inps { inp };
		inps >> result;
		{
			if (inps.fail()) {
				if (std::cin.eof()) {
					std::cout << "Ошибка ввода/вывода" << std::endl;
					exit(1);
				}
				std::cout << "Некорректный ввод" << std::endl;
				goto re;
			} else if (not inps.eof()) {
				std::cout << "Некорректный ввод" << std::endl;
				goto re;
			}
		}
	}

	return result;
}

int getAndCheckInRange(const char *question, int min, int max) {
	for (;;) {
		int returnInt = get_int(question);
		if (returnInt >= min && returnInt <= max) {
			return returnInt;
		}
		std::cout << "Введите подходящее число!" << std::endl;
		continue;
	}
	return 0;
}

int setCryptType() {
	std::cout << "Выберите режим шифрования(Сейчас выбран под п. " << (crypt_type + 1) << ") \n"
				"1. Без шифрования \n"
				"2. Сеть Фейстеля(ECB) \n"
				"3. Сеть Фейстеля(CBC) \n"
				"4. Сеть Фейстеля(CTR) \n"
			<< std::endl;
	crypt_type = getAndCheckInRange("Выберите пункт меню", 1, 4) - 1;

	return 0;
}

void cryptFeistelNetwork(uint16_t &Li, uint16_t &Ri, bool uncrypt)
{
	using namespace crypto::container;
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

	for (unsigned int lap = 0; lap < 8; lap++)
	{
		uint16_t x = Li;
		uint16_t F = (t111[(x >> 12) & 0x0F] << 12) +  (t111[(x >> 8) & 0x0F] << 8) + (t111[(x >> 4) & 0x0F] << 4) + t111[x & 0x0F];
		int positionKey0 = lap * 2;
		int positionKey1 = lap * 2 + 1;
		if (uncrypt)
		{
			positionKey0 = 15 - (lap * 2 + 1);
			positionKey1 = 15 - (lap * 2);
		}
		uint16_t key = (buffer_key[positionKey1] << 8) + buffer_key[positionKey0];
		F ^= key;
		F = (F << 3) | (F >> (16-3));
		uint16_t oldLi = Li;
		Li = Ri ^ F;
		Ri = oldLi;
	}
	std::swap (Li, Ri);
}

void create_buffer_for_crc32(uint8_t * buffer, uint32_t word_result)
{
	for (unsigned k = 0; k < BLOCK_SIZE / 8; ++k) {
		buffer[k] = (word_result >> (8 * k)) & 0xFF;
	}
}

void increment_block(uint8_t * block, size_t sz)
{
	unsigned current_byte = 0;
	while(current_byte < sz)
	{
		uint8_t old_value = block[current_byte];
		uint8_t new_value = old_value + 1;
		block[current_byte] = new_value;
		if (new_value > old_value) return;
		++current_byte;
	}
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

void create_container()
{
	std::cout << "Convert" << std::endl;
	using namespace crypto::container;
	std::ifstream src_file;

	src_file.open(TEST_FILE_NAME, std::ios::binary | std::ios::ate);
	size_t filesize = src_file.tellg();
	src_file.seekg(0);

	std::ofstream dst_file;

	dst_file.open(std::string(CRYPT_NAME[crypt_type]) + TEST_CONTAINER_NAME, std::ios::binary);

	header hdr {};
	hdr.magic_word = MAGIC_WORD;
	hdr.header_size = HEADER_SIZE;
	hdr.payload = crypt_type;

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
	auto file_header_pos = dst_file.tellp();
	dst_file.write(reinterpret_cast<char*>(&mdf), FILE_METADATA_SIZE);
	dst_file.write(TEST_FILE_NAME, name_length + 1);

	uint32_t crypto_word = *((uint32_t*)IV);

	uint32_t crc32 = 0;
	uint32_t crc32_table[256];
	crypto::utils::generarate_crc32_lut(crc32_table);
	for (	uint64_t block = 0;
			block < mdf.block_count;
			++block) {
		uint8_t buffer[BLOCK_SIZE / 8] {};
		src_file.readsome(reinterpret_cast<char*>(&buffer[0]),
				BLOCK_SIZE / 8);
		for (unsigned k = 0; k < BLOCK_SIZE /8; ++k)
		{
			crc32 = crypto::utils::update_crc32(crc32_table, buffer[k], crc32);
		}
		switch(crypt_type)
		{
		case ECB_CRYPT:{
			uint16_t Li = (buffer[3] << 8) + buffer[2];
			uint16_t Ri = (buffer[1] << 8) + buffer[0];
			cryptFeistelNetwork(Li, Ri, false);
			uint32_t cryptedParts = (Li << 16) + Ri;
			dst_file.write(reinterpret_cast<char*>(&cryptedParts),
									BLOCK_SIZE / 8);
			break;
		}
		case CBC_CRYPT:{
			uint32_t word = (buffer[3] << 24) + (buffer[2] << 16) + (buffer[1] << 8) + buffer[0];
			word = word ^ crypto_word;
			uint16_t Li = word >> 16 & 0xFFFF;
			uint16_t Ri = word & 0xFFFF;
			cryptFeistelNetwork(Li, Ri, false);
			crypto_word = (Li << 16) + Ri;
			dst_file.write(reinterpret_cast<char*>(&crypto_word),
									BLOCK_SIZE /8);
			break;
		}
		case CTR_CRYPT:{
			uint16_t Li = crypto_word >> 16 & 0xFFFF;
			uint16_t Ri = crypto_word & 0xFFFF;
			cryptFeistelNetwork(Li, Ri, false);
			uint32_t result_crypto_word = (Li << 16) + Ri;
			uint32_t word = (buffer[3] << 24) + (buffer[2] << 16) + (buffer[1] << 8) + buffer[0];
			uint32_t result = word ^ result_crypto_word;
			dst_file.write(reinterpret_cast<char*>(&result),
												BLOCK_SIZE /8);
			uint8_t * crypto_word_to_blocks = new uint8_t[4];
			crypto_word_to_blocks[3] = crypto_word&0xFF;
			crypto_word_to_blocks[2] = (crypto_word >> 8)&0xFF;
			crypto_word_to_blocks[1] = (crypto_word >> 16)&0xFF;
			crypto_word_to_blocks[0] = (crypto_word >> 24)&0xFF;
			increment_block(&crypto_word_to_blocks[0], BLOCK_SIZE);
			crypto_word = (crypto_word_to_blocks[3] << 24) + (crypto_word_to_blocks[2] << 16) + (crypto_word_to_blocks[1] << 8) + crypto_word_to_blocks[0];
			break;
		}
		case RAW_CRYPT:
		default:{
			dst_file.write(reinterpret_cast<char*>(&buffer[0]),
									BLOCK_SIZE /8);
			break;
		}
		}

	}
	mdf.crc32 = crc32;
	dst_file.seekp(file_header_pos);
	dst_file.write(reinterpret_cast<char*>(&mdf), FILE_METADATA_SIZE);

	src_file.close();
	dst_file.close();
}

void extract_container()
{
	std::cout << "Extract" << std::endl;
	using namespace crypto::container;

	std::ifstream src_file;

	src_file.open(std::string(CRYPT_NAME[crypt_type]) + TEST_CONTAINER_NAME, std::ios::binary);
	header hdr {};
	src_file.read(reinterpret_cast<char*>(&hdr),
			sizeof(header));

	if (hdr.magic_word != MAGIC_WORD) {
		std::cerr << "FILE IS WRONG" << std::endl;
		return;
	}

	if (hdr.payload != crypt_type)
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
	std::string original_filename = "Extract_with_encrypt_" + std::string(CRYPT_NAME[crypt_type]);
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

	uint32_t crypto_word = *((uint32_t*)IV);

	uint32_t crc32 = 0;
	uint32_t crc32_table[256];
	crypto::utils::generarate_crc32_lut(crc32_table);
	while (mdf.original_length > 0)
	{
		uint8_t buffer[BLOCK_SIZE / 8] {};
		src_file.read(reinterpret_cast<char*>(&buffer[0]),
				BLOCK_SIZE / 8);
		uint64_t bytes_to_write = std::min<unsigned long>(4UL, mdf.original_length);


		uint8_t buffer_for_crc32[BLOCK_SIZE / 8] {};
		switch(crypt_type)
		{
		case ECB_CRYPT:{
			uint16_t Li = (buffer[3] << 8) + buffer[2];
			uint16_t Ri = (buffer[1] << 8) + buffer[0];
			cryptFeistelNetwork(Li, Ri, true);
			uint32_t encryptPart = (Li << 16) + Ri;
			create_buffer_for_crc32(buffer_for_crc32, encryptPart);
			dst_file.write(reinterpret_cast<char*>(&encryptPart),
							bytes_to_write);
			break;
		}
		case CBC_CRYPT:{
			uint16_t Li = (buffer[3] << 8) + buffer[2];
			uint16_t Ri = (buffer[1] << 8) + buffer[0];
			uint32_t crypto_word_save = (Li << 16) + Ri;
			cryptFeistelNetwork(Li, Ri, true);
			uint32_t word = (Li << 16) + Ri;
			word = word ^ crypto_word;
			crypto_word = crypto_word_save;
			create_buffer_for_crc32(buffer_for_crc32, word);
			dst_file.write(reinterpret_cast<char*>(&word),
							bytes_to_write);
			break;
		}
		case CTR_CRYPT:{
			uint16_t Li = crypto_word >> 16 & 0xFFFF;
			uint16_t Ri = crypto_word & 0xFFFF;
			cryptFeistelNetwork(Li, Ri, false);
			uint32_t result_crypto_word = (Li << 16) + Ri;
			uint32_t word = (buffer[3] << 24) + (buffer[2] << 16) + (buffer[1] << 8) + buffer[0];
			uint32_t result = word ^ result_crypto_word;
			create_buffer_for_crc32(buffer_for_crc32, result);
			dst_file.write(reinterpret_cast<char*>(&result),
							bytes_to_write);
			uint8_t * crypto_word_to_blocks = new uint8_t[4];
			crypto_word_to_blocks[3] = crypto_word&0xFF;
			crypto_word_to_blocks[2] = (crypto_word >> 8)&0xFF;
			crypto_word_to_blocks[1] = (crypto_word >> 16)&0xFF;
			crypto_word_to_blocks[0] = (crypto_word >> 24)&0xFF;
			increment_block(&crypto_word_to_blocks[0], BLOCK_SIZE);
			crypto_word = (crypto_word_to_blocks[3] << 24) + (crypto_word_to_blocks[2] << 16) + (crypto_word_to_blocks[1] << 8) + crypto_word_to_blocks[0];
			break;
		}
			break;
		case RAW_CRYPT:
		default:{
			for (unsigned k = 0; k < BLOCK_SIZE /8; ++k)
			{
				buffer_for_crc32[k] = buffer[k];
			}
			dst_file.write(reinterpret_cast<char*>(&buffer[0]),
							bytes_to_write);
			break;
		}
		}
		for (unsigned k = 0; k < BLOCK_SIZE /8; ++k)
		{
			crc32 = crypto::utils::update_crc32(crc32_table, buffer_for_crc32[k], crc32);
		}

		mdf.original_length -= bytes_to_write;
	}

	if (crc32 != mdf.crc32) {
		std::cout << "WARNING! CRC mismatch" << std::endl;
	}

	src_file.close();
	dst_file.close();

}

int main(int argc, char ** argv)
{
	for (;;) {
		std::cout << "Меню \n"
				"1. Зашифровать  \n"
				"2. Расшифровать \n"
				"3. Создать ключ \n"
				"4. Метод шифрования \n"
				"5. Выход" << std::endl;
		int intForSwitch = getAndCheckInRange("Выберите пункт меню", 1, 5);
		switch (intForSwitch) {
		case 1:
			create_container();
			break;
		case 2:
			extract_container();
			break;
		case 3:
			generate_key(16);
			break;
		case 4:
			setCryptType();
			break;
		case 5:
			exit(0);
			break;
		}
	}
	return 0;
}
