#ifndef RSAES_OAEP_H
#define RSAES_OAEP_H
#include <gmp.h>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <algorithm>
#include "RSAES-PKCS1-V1_5.h"

//计算sha256
std::vector<unsigned char> compute_sha256(const std::vector<unsigned char> &data) ;

// MGF1 掩码生成函数
std::vector<unsigned char> MGF1(const std::vector<unsigned char> &seed, size_t mask_len) ;

// OAEP填充函数
std::vector<unsigned char> oaep_pad(const std::string &message, size_t k);

//OAEP去除填充函数
std::string oaep_unpad(const std::vector<unsigned char> &padded_message);


#endif 