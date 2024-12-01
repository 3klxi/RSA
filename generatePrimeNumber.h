#ifndef ISPRIMENUMBER_H
#define def ISPRIMENUMBER_H

#include <gmp.h>
#include <iostream>
#include <ctime>

//声明外部变量
extern gmp_randstate_t state;

//初始化随机数状态
void init_random_state();

//判断是否为素数
bool is_prime(mpz_t num, int iterations);

//生成素数
void generate_prime(mpz_t prime, int bits);

//测试函数
void test1();

#endif