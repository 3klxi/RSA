#include <iostream>
#include <iomanip>

#include "generatePrimeNumber.h"
#include "generateKey.h"
#include "enAndDecryptionRSA.h"


#include "RSAES-PKCS1-V1_5.h"
#include "RSAES-OAEP.h"


using namespace std;

void print_title(const std::string &title) ;  //打印标题
void print_hex(const std::string &message) ;  //十六进制打印字符串

//测试PKCS1 v1.5填充
void test5();

//测试OAEP填充
void test6();

gmp_randstate_t state;


int main() {
    
    // 生成大随机素数2048bits
    print_title("Generate random prime number:");
    test1();
    cout << "\n\n\n";

    // 生成RSA密钥（公钥e，n和私钥d）
    print_title("Generate RSA keys:");
    test2();
    cout << "\n\n\n";

    // 基于整数的加密
    print_title("Encryption and decryption based on a big int:");
    test3();
    cout << "\n\n\n";

    // 基于字符串的加密
    print_title("Encryption and decryption based on an English-String:");
    test4();
    cout << "\n\n\n";


    //基于PKCS1 v1.5填充的加解密
    print_title("PKCS1-V1.5 padding:");
    test5();
    cout<<"\n\n\n";


    //基于OAEP填充的加解密
    print_title("OAEP padding:");
    test6();
    cout<<"\n\n\n";


    return 0;
}



//打印标题
void print_title(const std::string &title) {
    int length = title.size();
    
    // 输出上边框
    std::cout << " ";
    for (int i = 0; i < length + 4; ++i) {
        std::cout << "-";
    }
    std::cout << "\n";

    // 输出标题行
    std::cout << "| " << title << " |\n";

    // 输出下边框
    std::cout << " ";
    for (int i = 0; i < length + 4; ++i) {
        std::cout << "-";
    }
    std::cout << "\n";

}


//十六进制打印字符串
void print_hex(const std::string &message) {
    std::cout << "\nMessage in hex: \n";
    for (unsigned char c : message) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
    }
    std::cout << std::endl;
}


// 测试PKCS1 v1.5填充
void test5() {
    mpz_t n, e, d, ciphertext;
    mpz_inits(n, e, d, ciphertext, nullptr);

    init_random_state();
    generate_rsa_key(2048, n, e, d);

    std::string message = "Hello I'm 3klxi, a student from BeiJing Jiaotong University, cyber safety academy";
    std::cout << "Original Message: \n" << message << std::endl;

    std::cout<<endl;
    print_hex(message);

    // PKCS1 v1.5 填充并加密
    auto padded_message_pkcs1 = pkcs1_v1_5_pad(message, 256);

    std::cout << "\nPadded message (PKCS1 v1.5): \n";
    for (unsigned char byte : padded_message_pkcs1) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << std::endl;

    //填充后转化为mpz大整数
    mpz_t padded_mpz_pkcs1;
    mpz_init(padded_mpz_pkcs1);
    pad_message_to_mpz(padded_mpz_pkcs1, padded_message_pkcs1);

    std::cout << "\nTransform to big int(mpz): ";
    gmp_printf("\n%Zd\n\n",padded_mpz_pkcs1);


    //加密
    mpz_powm(ciphertext, padded_mpz_pkcs1, e, n);
    std::cout << "\n";
    gmp_printf("\nCiphertext (PKCS1 v1.5): \n%Zd\n", ciphertext);

    
    //将解密，存入decrypted_message_mpz
    mpz_t decrypted_message_mpz;
    mpz_init(decrypted_message_mpz);
    mpz_powm(decrypted_message_mpz, ciphertext, d, n);

    std::cout << "\n";
    gmp_printf("\nDecryptiontext (PKCS1 v1.5): \n%Zd\n", decrypted_message_mpz);


    // 将解密后的 mpz_t 转换为字节数组并输出
    std::vector<unsigned char> decrypted_padded_message = mpz_to_padded_message(decrypted_message_mpz, 256);

    std::cout << "\nDecrypted padded message: \n";
    for (unsigned char byte : decrypted_padded_message) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << "\n\n";


    // 去除 PKCS1 v1.5 填充
    std::string final_decrypted_message;
    try {
        final_decrypted_message = pkcs1_v1_5_unpad(decrypted_padded_message);
        std::cout << "\nDecrypted Message (PKCS1 v1.5): \n" << final_decrypted_message << std::endl;

        if (message == final_decrypted_message) {
            std::cout << "Decryption successful: Yes.\n" << std::endl;
        } else {
            std::cout << "Decryption successful: No.\n" << std::endl;
        }
    } catch (const std::runtime_error &e) {
        std::cout << "Error during padding removal: " << e.what() << std::endl;
    }

    mpz_clears(n, e, d, ciphertext, padded_mpz_pkcs1, decrypted_message_mpz, nullptr);
}


//测试OAEP填充
void test6() {
    mpz_t n, e, d, ciphertext;
    mpz_inits(n, e, d, ciphertext, nullptr);
    generate_rsa_key(2048, n, e, d);

    std::string message = "Hello I'm 3klxi, a student from BeiJing Jiaotong University, cyber safety academy";
    std::cout << "Original Message: \n" << message << std::endl;

    std::cout << "\nOriginal Message in Hex: ";
    for (char ch : message) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)ch << " ";
    }
    std::cout << std::endl;

    // OAEP 填充
    auto padded_message = oaep_pad(message, 256);
    std::cout << "\nOAEP Padded Message: \n";
    for (unsigned char byte : padded_message) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << std::endl;

    // 填充后转化为 mpz_t
    mpz_t padded_mpz;
    mpz_init(padded_mpz);
    pad_message_to_mpz(padded_mpz, padded_message);

    std::cout << "\nTransform to big int (mpz): ";
    gmp_printf("\n%Zd\n\n", padded_mpz);

    // 加密
    mpz_powm(ciphertext, padded_mpz, e, n);
    std::cout << "\nCiphertext (OAEP): ";
    gmp_printf("\n%Zd\n", ciphertext);

    // 解密，存入 decrypted_message_mpz
    mpz_t decrypted_message_mpz;
    mpz_init(decrypted_message_mpz);
    mpz_powm(decrypted_message_mpz, ciphertext, d, n);

    std::cout << "\nDecrypted Ciphertext to Big Int (OAEP): ";
    gmp_printf("\n%Zd\n", decrypted_message_mpz);

    // 将解密后的 mpz 转换为字节数组
    auto decrypted_padded_message = mpz_to_padded_message(decrypted_message_mpz, 256);
    std::cout << "\nDecrypted Padded Message: \n";
    for (unsigned char byte : decrypted_padded_message) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << std::endl;

    // 去除 OAEP 填充
    try {
        std::string decrypted_message = oaep_unpad(decrypted_padded_message);
        std::cout << "\nDecrypted Message (OAEP): \n" << decrypted_message << std::endl;

        if (message == decrypted_message) {
            std::cout << "\nDecryption successful: Yes.\n" << std::endl;
        } else {
            std::cout << "\nDecryption successful: No.\n" << std::endl;
        }
    } catch (const std::runtime_error &e) {
        std::cout << "Error during OAEP unpadding: " << e.what() << std::endl;
    }

    mpz_clears(n, e, d, ciphertext, padded_mpz, decrypted_message_mpz, nullptr);
}