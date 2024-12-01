#include "generatePrimeNumber.h"

//初始化随机数状态
void init_random_state(){
    gmp_randinit_default(state);
    gmp_randseed_ui(state,time(nullptr));
}


//MillerRabin素数检验，20轮
bool is_prime(mpz_t num, int iterations = 20){
    return mpz_probab_prime_p(num, iterations) > 0;
}


//生成大随机素数
void generate_prime(mpz_t prime, int bits) {
    do {
        mpz_urandomb(prime, state, bits); // 生成bits位的随机数，赋值给prime
        mpz_setbit(prime, bits - 1);      // 设置最高位为1，确保是bits位的数
        mpz_setbit(prime, 0);             // 设置最低位为1，确保是奇数
    } while (!is_prime(prime, 20));           // 直到通过素性测试
}


//测试
void test1(){
    init_random_state();

    mpz_t p, q, z;
    mpz_inits(p, q, z, nullptr);

    int bits = 1024; // p 和 q 各 1024 位，得到 2048 位的 n
    generate_prime(p, 1024);
    generate_prime(q, 1024);
   

    std::cout << "p: "; mpz_out_str(stdout, 10, p); std::cout << "\n\n";  //十进制输出
    std::cout << "q: "; mpz_out_str(stdout, 10, q); std::cout << std::endl;
    


    mpz_clears(p, q, nullptr);
    gmp_randclear(state);
}