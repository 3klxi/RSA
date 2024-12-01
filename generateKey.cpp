#include "generateKey.h"
#include "generatePrimeNumber.h"

//生成密钥，bits是n的位数

void generate_rsa_key(int bits, mpz_t n, mpz_t e, mpz_t d) {
    mpz_t p, q, phi, gcd;

    mpz_inits(p, q, phi, gcd, nullptr);
    
    // Step 1: 生成两个大素数
    generate_prime(p, bits / 2);
    generate_prime(q, bits / 2);


    // Step 2: 计算 n = p * q
    mpz_mul(n, p, q);

    

    //gmp_printf("p: %Zd\n", p);
    //gmp_printf("q: %Zd\n", q);


    // Step 3: 计算欧拉函数 phi = (p - 1) * (q - 1)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi, p, q);

    //gmp_printf("phi: %Zd\n", phi);

    // Step 4: 选择公钥 e (通常 65537)
    mpz_set_ui(e, 65537);


    // Step 5: 确保最大公约数是 gcd(e, phi) = 1
    mpz_gcd(gcd, e, phi);
    
    if (mpz_cmp_ui(gcd, 1) != 0) {
    // 重新选择一个新的小素数作为 e，直到 gcd(e, phi) = 1
    mpz_set_ui(e, 3);
    while (mpz_cmp(e, phi) < 0) {
        mpz_gcd(gcd, e, phi);
        if (mpz_cmp_ui(gcd, 1) == 0) {
            break;
        }
        // 如果 e 和 phi 不互质，选择下一个素数
        mpz_nextprime(e, e);
    }
}

    // Step 6: 计算私钥 d, d ≡ e^(-1) (mod phi)
    mpz_invert(d, e, phi);

    mpz_clears(p, q, phi, gcd, nullptr);
}


//测试密钥对产生函数
void test2(){
    mpz_t n, e, d;
    mpz_inits(n, e, d, nullptr);

    init_random_state();

    // Generate RSA key pair with 1024-bit modulus
    generate_rsa_key(2048, n, e, d);

    // Output the keys
    gmp_printf("Public Key (n, e): \n(\n%Zd\n%Zd\n)\n", n, e);
    gmp_printf("Private Key (d): \n%Zd\n", d);

    mpz_clears(n, e, d, nullptr);
    gmp_randclear(state);

}