#include "RSAES-OAEP.h"

/*  
    compute_sha256(data)
    参数：
    data: 用于计算的数据，一个unsigned char类型的数组

    初始化配置
    1 配置为计算SHA-256哈希，EVP_sha256()返回算法所需的EVP_MD结构
    2 向mdctx添加数据data
    3 计算data的哈希值，存储在hash中
    4 释放mdcdx上下文
    5 捕获错误
    6 返回hash值
*/

//计算sha256
std::vector<unsigned char> compute_sha256(const std::vector<unsigned char> &data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);     //256位——32字节 

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();                    //创建EVP_MD_CTX创建上下文，存储用于哈希运算的状态
    if (mdctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||  
        EVP_DigestUpdate(mdctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash.data(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx); 
        throw std::runtime_error("Failed to compute SHA256 hash");
    }

    EVP_MD_CTX_free(mdctx);
    return hash;
}


/*  MGF1(seed, mask_len)
    参数
    seed：输入的种子-->掩码
    mask_len：生成掩码的字节长度

    1 counter 每次循环加1，用于确保每次生成的哈希值不同
    2 data.insert 将seed和counter合并成一个新数据，生成新一轮的hash
    3 for循环将生成的哈希值拷贝到mask的相应位置
    4 返回 mask
*/

// MGF1 掩码生成函数
std::vector<unsigned char> MGF1(const std::vector<unsigned char> &seed, size_t mask_len) {
    std::vector<unsigned char> mask(mask_len);             //掩码
    size_t hash_len = SHA256_DIGEST_LENGTH;                //hash长度：32字节
    unsigned char counter[4] = {0};                        //计数的4字节数组 0x00000000

    for (size_t i = 0; i < mask_len / hash_len + 1; ++i) {
        counter[3] = i;
        
        std::vector<unsigned char> data(seed);
        data.insert(data.end(), counter, counter + 4);

        std::vector<unsigned char> hash = compute_sha256(data);
        
        //掩码
        for (size_t j = 0; j < hash_len && (i * hash_len + j) < mask_len; ++j) {
            mask[i * hash_len + j] = hash[j];
        }
    }
    return mask;
}


/*  opea_pad(message, k)
    参数 message填充的消息
         k 填充后的结果

    1 seed填充中用于掩码生成器的种子，长度h_len
    2 db 数据块，包含lhash，0x01和message
    3 空字符的hash，填充db的前面，0x01用于填充和消息的分隔符号，消息填充db
    4 用seed作为种子，生成db的掩码，生成db'
    5 用db'作为种子，生成seed的掩码，生成seed'
    6 合并成填充消息 0x00 + seed' + db'
*/

// OAEP填充函数
std::vector<unsigned char> oaep_pad(const std::string &message, size_t k) {
    size_t m_len = message.size();
    size_t h_len = SHA256_DIGEST_LENGTH;

    //检查消息的最大长度
    if (m_len > k - 2 * h_len - 2) { 
        throw std::runtime_error("Message too long for OAEP padding.");
    }

    std::vector<unsigned char> padded_message(k, 0);
    std::vector<unsigned char> seed(h_len), db(k - h_len - 1);

    //初始化seed
    seed  = generate_random_bytes(h_len);


    // 生成DB块
    std::vector<unsigned char> lHash = compute_sha256({});
    std::copy(lHash.begin(), lHash.end(), db.begin());
    db[k - h_len - m_len - 2] = 0x01;
    std::copy(message.begin(), message.end(), db.end() - m_len);

    // 生成seed掩码，应用到DB块
    auto db_mask = MGF1(seed, db.size());
    for (size_t i = 0; i < db.size(); ++i) {
        db[i] ^= db_mask[i];
    }

    //生成DB掩码和应用到seed块
    auto seed_mask = MGF1(db, seed.size());
    for (size_t i = 0; i < seed.size(); ++i) {
        seed[i] ^= seed_mask[i];
    }

    //拼接
    padded_message[0] = 0x00;
    std::copy(seed.begin(), seed.end(), padded_message.begin() + 1);
    std::copy(db.begin(), db.end(), padded_message.begin() + 1 + h_len);

    return padded_message;
}



/*  opea_unpad(message)
    参数 message已填充的消息
        
    1 判断是否是标准的OAEP填充消息，k是消息长度
    2 分别取出seed'和 db'
    3 用db'为种子，生成seed'的掩码seed_mask，恢复出seed
    4 用seed作为种子，生成db'的掩码db_mask，恢复出db
    5 对db进行hash验证，先验证前l_hash个字节是否被篡改
    6 查找分割符号0x01，最后再取出来消息message
*/

// OAEP 去填充函数
std::string oaep_unpad(const std::vector<unsigned char> &padded_message) {
    size_t h_len = SHA256_DIGEST_LENGTH;
    size_t k = padded_message.size();

    //判断是否是标准的OAEP填充块
    if (k < 2 * h_len + 2 || padded_message[0] != 0x00) {
        throw std::runtime_error("Invalid OAEP padding");
    }

    //分别取出seed' 和 db'
    std::vector<unsigned char> seed(padded_message.begin() + 1, padded_message.begin() + 1 + h_len);
    std::vector<unsigned char> db(padded_message.begin() + 1 + h_len, padded_message.end());

    //用db'生成种子掩码，恢复种子
    auto seed_mask = MGF1(db, h_len);
    for (size_t i = 0; i < h_len; ++i) {
        seed[i] ^= seed_mask[i];
    }

    //用seed生成数据块掩码，恢复数据快
    auto db_mask = MGF1(seed, db.size());
    for (size_t i = 0; i < db.size(); ++i) {
        db[i] ^= db_mask[i];
    }

    //检查空字串的lhash是否被改变，检查消息是否被篡改
    std::vector<unsigned char> lhash = compute_sha256({});
    if (!std::equal(db.begin(), db.begin() + h_len, lhash.begin())) {
        throw std::runtime_error("Invalid OAEP padding: hash mismatch");
    }

    //寻找标志位0x01，提取后面的消息，返回message
    auto it = std::find(db.begin() + h_len, db.end(), 0x01);
    if (it == db.end() || ++it == db.end()) {
        throw std::runtime_error("Invalid OAEP padding: no 0x01 byte found");
    }

    return std::string(it, db.end());
}