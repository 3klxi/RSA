#include "RSAES-PKCS1-V1_5.h"


//生成随机字节
std::vector<unsigned char> generate_random_bytes(size_t length) {
    std::vector<unsigned char> random_bytes(length);   
    std::random_device rd;                      //使用随机设备，提供种子
    std::mt19937 gen(rd());                     //使用Mersenne Twister随机数生成器，初始化为rd的随机种子
    std::uniform_int_distribution<> dis(1, 255); //均匀分布，1-255，不存在0x00 0xFF
    for (size_t i = 0; i < length; i++) {
        random_bytes[i] = dis(gen);
    }

    return random_bytes;
}



//PKCS1 v1.5填充
std::vector<unsigned char> pkcs1_v1_5_pad(const std::string &message, size_t k) {
    size_t mlen = message.size();
    if (mlen > k - 11) {
        throw std::runtime_error("Message too long for PKCS1 v1.5 padding.");
    }

    std::vector<unsigned char> padded_message(k, 0);
    padded_message[0] = 0x00;
    padded_message[1] = 0x02;

    auto random_bytes = generate_random_bytes(k - mlen - 3);
    std::copy(random_bytes.begin(), random_bytes.end(), padded_message.begin() + 2);

    padded_message[k - mlen - 1] = 0x00;
    std::copy(message.begin(), message.end(), padded_message.end() - mlen);

    return padded_message;
}



// 去除 PKCS1 v1.5 填充
std::string pkcs1_v1_5_unpad(const std::vector<unsigned char> &padded_message) {
    // 确认填充长度
    if (padded_message.size() < 11) {
        throw std::runtime_error("Invalid PKCS1 v1.5 padding: message too short.");
    }

    // 检查开头的 0x00 和 0x02
    if (padded_message[0] != 0x00 || padded_message[1] != 0x02) {
        throw std::runtime_error("Invalid PKCS1 v1.5 padding: incorrect header.");
    }

    // 寻找填充的结束位置（0x00 分隔符）
    size_t separator_pos = 2;
    while (separator_pos < padded_message.size() && padded_message[separator_pos] != 0x00) {
        // 检查填充字节是否是有效的非零字节
        if (padded_message[separator_pos] == 0x00) {
            throw std::runtime_error("Invalid PKCS1 v1.5 padding: unexpected 0x00 in padding.");
        }
        separator_pos++;
    }

    // 确保分隔符位置有效
    if (separator_pos >= padded_message.size() - 1) {
        throw std::runtime_error("Invalid PKCS1 v1.5 padding: no separator found.");
    }

    // 提取原始消息
    return std::string(padded_message.begin() + separator_pos + 1, padded_message.end());
}


// 将gmp整数转换回字节数组
std::vector<unsigned char> mpz_to_padded_message(const mpz_t &padded_mpz, size_t expected_size) {
    std::vector<unsigned char> padded_message(expected_size, 0); // 用 0 填充整个数组

    size_t count = 0; // 实际导出的字节数

    // 直接从 padded_message 的起始位置填充
    unsigned char *data_ptr = padded_message.data();

    // 导出数据
    mpz_export(data_ptr, &count, 1, 1, 0, 0, padded_mpz);
    
    // 如果导出的字节数少于预期大小，调整数组，将数据放到数组末尾
    if (count < expected_size) {
        std::vector<unsigned char> aligned_message(expected_size, 0);
        std::copy(padded_message.begin(), padded_message.begin() + count, aligned_message.end() - count);
        return aligned_message;
    }

    return padded_message;
}



//转换填充后的消息为gmp整数
void pad_message_to_mpz(mpz_t padded_mpz, const std::vector<unsigned char> & padded_message){
    mpz_import(padded_mpz,padded_message.size(),1,1,0,0,padded_message.data());  //大端序，每个元素1字节，字节填充方向，跳过参数
}



