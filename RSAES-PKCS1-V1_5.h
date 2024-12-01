#ifndef RSAES_PKCS1_V1_5_H
#define RSAES_PKCS1_V1_5_H
#include <gmp.h>
#include <iostream>
#include <vector>
#include <string>
#include <random>
//生成随机字节
std::vector<unsigned char> generate_random_bytes(size_t length);

//PKCS1 v1.5填充
std::vector<unsigned char> pkcs1_v1_5_pad(const std::string &message,size_t k);

//PKCS1 v1.5去填充
std::string pkcs1_v1_5_unpad(const std::vector<unsigned char> &padded_message);

//转换填充后的消息为gmp整数
void pad_message_to_mpz(mpz_t padded_mpz, const std::vector<unsigned char> & padded_message);

//gmp整数转化为字节
std::vector<unsigned char> mpz_to_padded_message(const mpz_t &padded_mpz, size_t expected_size);

#endif 

