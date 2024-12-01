CXX = g++
CXXFLAGS = -lgmp -lgmpxx -lssl -lcrypto
TARGET = main
SRCS = main.cpp  generatePrimeNumber.cpp generateKey.cpp enAndDecryptionRSA.cpp RSAES-PKCS1-V1_5.cpp RSAES-OAEP.cpp

$(TARGET): $(SRCS)
	$(CXX) -o $(TARGET) $(SRCS) $(CXXFLAGS)

clean:
	rm -f $(TARGET)
