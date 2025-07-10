> 🌐 中文版 [English Version](./README.en.md)
# 🔐 RSA 算法实验（基于 C++ 与 GMP 库）
这是一个使用 C++ 实现的 RSA 加密算法实验项目，基于 GMP 多精度整数库。实现了常见的 RSA 加解密流程，包括密钥生成、填充方案（如 OAEP、PKCS#1 v1.5）以及支持的分离模块。

---

## 📁 项目结构

| 文件名                     | 说明                        |
| ----------------------- | ------------------------- |
| `main.cpp`              | 主函数入口，用于运行整体流程            |
| `generateKey.*`         | 密钥对生成（包括生成素数）             |
| `generatePrimeNumber.*` | 大素数生成工具函数                 |
| `enAndDecryptionRSA.*`  | RSA 加解密逻辑                 |
| `RSAES-OAEP.*`          | 支持 RSAES-OAEP 填充方案        |
| `RSAES-PKCS1-V1_5.*`    | 支持 RSAES-PKCS#1 v1.5 填充方案 |

---

## ⚙️ 编译说明

### 🧰 依赖

* C++ 编译器（支持 C++11 以上）
* [GMP Library](https://gmplib.org/)（多精度整数运算）

### 🔧 编译命令

```bash
make
```

> 如果你没有 `make` 工具，也可以手动用 `g++` 编译每个 `.cpp` 文件并链接 `-lgmp -lgmpxx`。

---

## 🚀 示例运行

```bash
./rsa
```

程序会执行如下过程：

1. 生成一对 RSA 公钥与私钥；
2. 用户输入一段明文；
3. 程序加密该明文，输出密文；
4. 再将密文解密为明文，验证正确性。

---

## 📌 TODO（后续可扩展功能）

* ✅ 支持 OAEP、PKCS#1 v1.5 填充方案（已完成）
* ⏳ 添加更多攻击模拟：如 e 太小攻击、共模攻击
* ⏳ 添加数字签名模块

---

## 👤 作者

* GitHub: [3klxi](https://github.com/3klxi)
* 邮箱（可选）：[karenxindongle@126.com](mailto:karenxindongle@126.com)

---

## 📄 License

MIT License.


