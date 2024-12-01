#include "enAndDecryptionRSA.h"


//-----------------------------------大整数-----------------------------------
//RSA加密函数
void rsa_encrypt(mpz_t ciphertext, const mpz_t plaintext, const mpz_t n, const mpz_t e) {
    // 执行 RSA 加密：ciphertext = plaintext^e mod n
    mpz_powm(ciphertext, plaintext, e, n);
}


void rsa_decrypt(mpz_t plaintext, const mpz_t ciphertext, const mpz_t n, const mpz_t d) {
    // 执行 RSA 解密：plaintext = ciphertext^d mod n
    mpz_powm(plaintext, ciphertext, d, n);
}


//-----------------------------------字符串-----------------------------------
//基于字符串的加密
void rsa_encrypt_string(mpz_t ciphertext, const std::string &message, const mpz_t n, const mpz_t e) {
    // 将字符串转换为整数
    mpz_t plaintext;
    mpz_init(plaintext);

    

    // 加密
    rsa_encrypt(ciphertext, plaintext, n, e);

    mpz_clear(plaintext);
}


//基于字符串的解密
std::string rsa_decrypt_string(const mpz_t ciphertext, const mpz_t n, const mpz_t d) {
    // 解密得到整数形式的明文
    mpz_t plaintext;
    mpz_init(plaintext);

    rsa_decrypt(plaintext, ciphertext, n, d);

    // 将整数转换回字符串
    size_t count;
    unsigned char *buffer = (unsigned char *) mpz_export(nullptr, &count, 1, 1, 0, 0, plaintext);

    // 构造字符串
    std::string message(buffer, buffer + count);
    free(buffer);
    mpz_clear(plaintext);

    return message;
}

//基于大数字的加密
void test3(){
    mpz_t n, e, d, plaintext, ciphertext, decrypted_text;
    mpz_inits(n, e, d, plaintext, ciphertext, decrypted_text, nullptr);

    // 初始化随机状态并生成RSA密钥对
    init_random_state();
    generate_rsa_key(2048, n, e, d);

    // 设置明文 
    mpz_set_str(plaintext, "3klxi20241201", 10);

    // 加密明文
    rsa_encrypt(ciphertext, plaintext, n, e);

    // 解密密文
    rsa_decrypt(decrypted_text, ciphertext, n, d);

    // 输出结果
    gmp_printf("Plaintext: %Zd\n", plaintext);
    gmp_printf("Ciphertext: %Zd\n", ciphertext);
    gmp_printf("Decrypted Text: %Zd\n", decrypted_text);

    // 检查解密结果是否与原始明文一致
    if (mpz_cmp(plaintext, decrypted_text) == 0) {
        std::cout << "Decryption successful? Yes " << std::endl;
    } else {
        std::cout << "Decryption successful? No " << std::endl;
    }

    mpz_clears(n, e, d, plaintext, ciphertext, decrypted_text, nullptr);
}


//基于英文字符串的加密
void test4(){
    mpz_t n, e, d, ciphertext;
    mpz_inits(n, e, d, ciphertext, nullptr);

    init_random_state();
    generate_rsa_key(2048, n, e, d);

    //gmp_printf("Public Key (n, e): \n(\n%Zd\n%Zd\n)\n", n, e);
    //gmp_printf("Private Key (d): \n%Zd\n", d);

    // 要加密的字符串消息
    std::string message = "Hello I'm 3klxi, a student from BeiJing Jiaotong University, cyber safety academy";
    std::cout << "Original Message: " << message << std::endl;

    // 加密字符串
    rsa_encrypt_string(ciphertext, message, n, e);

    //输出密文
    gmp_printf("Cipertest: %Zd\n", ciphertext);

    // 解密字符串
    std::string decrypted_message = rsa_decrypt_string(ciphertext, n, d);

    // 输出结果
    std::cout << "Decrypted Message: " << decrypted_message << std::endl;

    if (message == decrypted_message) {
        std::cout << "Decryption successful? Yes." << std::endl;
    } else {
        std::cout << "Decryption successful: No." << std::endl;
    }

    mpz_clears(n, e, d, ciphertext, nullptr);
}


