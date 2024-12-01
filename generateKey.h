#ifndef GENERATE_KEY_H
#define GENERATE_KEY_H

#include <gmp.h>


//生成密钥对
void generate_rsa_key(int bits, mpz_t n, mpz_t e, mpz_t d);

//测试
void test2();

#endif // !GENERATEKEY_H