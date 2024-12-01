#ifndef ENCRYPTION_RSA_H
#define ENCRYPTION_RSA_H

#include <gmp.h>
#include <iostream>
#include <string>

#include "generatePrimeNumber.h"
#include "generateKey.h"

//------------------------------------大整数------------------------------------
// RSA加密函数：使用公钥(n, e)加密明文消息plaintext，并将结果存储在ciphertext中
void rsa_encrypt(mpz_t ciphertext, const mpz_t plaintext, const mpz_t n, const mpz_t e);


// RSA解密函数：使用私钥(n, d)解密密文
void rsa_decrypt(mpz_t plaintext, const mpz_t ciphertext, const mpz_t n, const mpz_t d);

//------------------------------------字符串------------------------------------
// RSA字符串加密：将字符串转为整数后加密
void rsa_encrypt_string(mpz_t ciphertext, const std::string &message, const mpz_t n, const mpz_t e);


// RSA字符串解密：解密后将整数转回字符串
std::string rsa_decrypt_string(const mpz_t ciphertext, const mpz_t n, const mpz_t d);


//基于大整数的加密
void test3();


//基于字符串的加密
void test4();

#endif// ENCRYPTION_RSA_H
 