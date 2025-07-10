> 🌐 English Version [中文版](./README.md)
# 🔐 RSA Algorithm Experiment (Based on C++ & GMP)

This is a C++ implementation of the RSA encryption and decryption algorithm, built using the GMP library for handling large integers. It supports basic RSA operations, modular encryption/decryption, and padding schemes such as OAEP and PKCS#1 v1.5.

---

## 📁 Project Structure

| File                    | Description                        |
| ----------------------- | ---------------------------------- |
| `main.cpp`              | Entry point                        |
| `generateKey.*`         | Key generation logic               |
| `generatePrimeNumber.*` | Large prime number generator       |
| `enAndDecryptionRSA.*`  | RSA encrypt/decrypt functions      |
| `RSAES-OAEP.*`          | OAEP padding scheme support        |
| `RSAES-PKCS1-V1_5.*`    | PKCS#1 v1.5 padding scheme support |

---

## ⚙️ Build Instructions

### Dependencies

* C++ compiler (supporting C++11 or later)
* [GMP Library](https://gmplib.org/)

### Compile

```bash
make
```

Or manually with:

```bash
g++ *.cpp -lgmp -lgmpxx -o rsa
```

---

## 🚀 Run Example

```bash
./rsa
```

The program will:

1. Generate RSA key pair;
2. Prompt user for input;
3. Encrypt the input;
4. Decrypt the ciphertext and verify correctness.

---

## 📌 TODO

* ✅ Padding schemes (OAEP, PKCS#1 v1.5)
* ⏳ Attack simulation (low exponent, common modulus, etc.)
* ⏳ Digital signature support

---

## 👤 Author

* GitHub: [3klxi](https://github.com/3klxi)

---

需要我直接为你生成 `README.md` 文件并添加到项目中，也可以告诉我！
