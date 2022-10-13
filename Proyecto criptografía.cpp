#include <stdio.h>
#include <winsock2.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <fstream>
#include <cstdlib>
#include <sodium.h>
#include <iomanip>
#include <cstdio>


using namespace std;
using std::cout; using std::cerr;
using std::endl; using std::string;

string readFileIntoString(const string& path);

int encrypt(const char* original, const char* destiny, unsigned char key[crypto_stream_chacha20_KEYBYTES]);

int writeSecret(const char* file, const unsigned char key[crypto_stream_chacha20_KEYBYTES]);
int writeKeys(const char* publicFile, const char* privateFile, const unsigned char publicKeys[crypto_stream_chacha20_KEYBYTES], const unsigned char privateKeys[crypto_stream_chacha20_KEYBYTES]);
int extractSecret(const char* file, unsigned char key[crypto_stream_chacha20_KEYBYTES]);
int extractPublic(const char* file, unsigned char key[crypto_stream_chacha20_KEYBYTES]);
int extractPrivate(const char* file, unsigned char key[crypto_stream_chacha20_KEYBYTES]);

int main(int argc, char const* argv[])
{
    if (sodium_init() == -1) {
        return 1;
    }

    //creacion de llaves y asignacion de los valores.
    unsigned char secretKey[crypto_stream_chacha20_KEYBYTES];
    unsigned char publicKey[crypto_stream_chacha20_KEYBYTES];
    unsigned char privateKey[crypto_stream_chacha20_KEYBYTES];

    crypto_secretstream_xchacha20poly1305_keygen(secretKey);
    crypto_secretstream_xchacha20poly1305_keygen(publicKey);
    
    //se crea el keypair de las llaves generadas anteriormente
    crypto_sign_keypair(publicKey, secretKey);
    
    //strings para guardar las rutas
    string a, b, c;
    char origin[256], destiny[256];

    
    cout << "Generar las claves\n";
    cout << "Escriba la ruta deseada para guardar el archivo que contendrá la llave secreta\n";
    cin >> a;
    strcpy(origin, a.c_str());
    if (writeSecret(origin, secretKey) != 0) {
        return 1;
    }
    
    cout << "Escriba la ruta deseada para guardar el archivo que contendrá la llave publica\n";
    cin >> a;

    cout << "Escriba la ruta deseada para guardar el archivo que contendrá la llave privada\n";
    cin >> b;
    strcpy(origin, a.c_str());
    strcpy(destiny, b.c_str());
    if (writeKeys(origin, destiny, publicKey, privateKey) != 0) {
        return 1;
    }

    string filename("input.txt");
    string file_contents;

    file_contents = readFileIntoString(filename);
    cout << file_contents << endl;
	return 0;
}


string readFileIntoString(const string& path) {
    ifstream input_file(path);
    if (!input_file.is_open()) {
        cerr << "Could not open the file - '"
            << path << "'" << endl;
        exit(EXIT_FAILURE);
    }
    return string((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
}
/***********************************************************************************************************/
//Functions
/***********************************************************************************************************/

int extractSecret(const char* file, unsigned char key[crypto_stream_chacha20_KEYBYTES]) {
    string file_contents;
    file_contents = readFileIntoString(file);
    std::copy(file_contents.begin(), file_contents.end(), key);
    key[file_contents.length()] = 0;
    return 0;
}

int extractPublic(const char* file, unsigned char publicKey[crypto_stream_chacha20_KEYBYTES]) {
    string file_contents;
    file_contents = readFileIntoString(file);
    std::copy(file_contents.begin(), file_contents.end(), publicKey);
    publicKey[file_contents.length()] = 0;
    return 0;
}

int extractPrivate(const char* file, unsigned char privateKey[crypto_stream_chacha20_KEYBYTES]) {
    string file_contents;
    file_contents = readFileIntoString(file);
    std::copy(file_contents.begin(), file_contents.end(), privateKey);
    privateKey[file_contents.length()] = 0;
    return 0;
}


int encrypt(const char* original, const char* destiny, unsigned char key[crypto_stream_chacha20_KEYBYTES]) {
    unsigned char buf[128];

    if (sodium_init() == -1) {
        return 1;
    }

    std::cout << sizeof(buf) << std::endl;
    std::cout << std::setfill('0') << std::setw(2);
    std::cout.setf(std::ios::hex, std::ios::basefield);

    unsigned char* plaintext = NULL;
    unsigned char* ciphertext = NULL;
    unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
    //unsigned char key[crypto_stream_chacha20_KEYBYTES];
    char* buffer = NULL;
    unsigned long long clen;
    unsigned char* plaintext2 = NULL;

    std::ifstream plaintextfile("test.txt", std::ifstream::binary);
    if (plaintextfile) {

        // get length of file:
        plaintextfile.seekg(0, plaintextfile.end);
        clen = plaintextfile.tellg();
        plaintextfile.seekg(0, plaintextfile.beg);

        buffer = new char[clen];
        ciphertext = new unsigned char[clen];
        plaintext2 = new unsigned char[clen];

        std::cout << "Reading " << clen << " characters... ";
        plaintextfile.read(buffer, clen);

        if (plaintextfile)
            std::cout << "all characters read successfully.";
        else
            std::cout << "error: only " << plaintextfile.gcount() << " could be read";
        plaintextfile.close();
        std::cout << std::endl;
    }
    std::cout << "---" << std::endl;
    plaintext = (unsigned char*)buffer;
    for (int i = 0; i < clen; i++)
        std::cout << plaintext[i];
    std::cout << std::endl;
    std::cout << "---" << std::endl;

    randombytes_buf(nonce, sizeof(nonce));
    randombytes_buf(key, sizeof(key));

    int result = crypto_stream_chacha20_xor_ic(ciphertext, plaintext, clen, nonce, 0, key);
    int result2 = crypto_stream_chacha20_xor_ic(plaintext2, ciphertext, clen, nonce, 0, key);
    for (int i = 0; i < clen; i++)
        std::cout << (unsigned int)ciphertext[i];
    std::cout << std::endl;
    std::cout << "---" << std::endl;
    for (int i = 0; i < clen; i++)
        std::cout << plaintext2[i];
    std::cout << std::endl;
    std::cout << "---" << std::endl;
    std::cout << "Error Enc = " << result << std::endl;
    std::cout << "Error Dec = " << result2 << std::endl;

    delete[] plaintext2;
    delete[] ciphertext;
    delete[] buffer;
}

int writeSecret(const char* file, const unsigned char key[crypto_stream_chacha20_KEYBYTES]) {
    FILE * keyFile;
    keyFile = fopen(file, "w");
    if (keyFile != NULL) {
        fputs(reinterpret_cast <const char*> (key), keyFile);
    }
    else {
        return 1;
    }
    return 0;
}
int writeKeys(const char* publicFile, const char* privateFile, const unsigned char publicKey[crypto_stream_chacha20_KEYBYTES], const unsigned char privateKey[crypto_stream_chacha20_KEYBYTES]) {
    FILE* publicKeyFile;
    publicKeyFile = fopen(publicFile, "w");
    if (publicKeyFile != NULL) {
        fputs(reinterpret_cast <const char*> (publicKey), publicKeyFile);
        fclose(publicKeyFile);
    }
    else {
        return 1;
    }

    FILE* privateKeyFile;
    privateKeyFile = fopen(publicFile, "w");
    if (privateKeyFile != NULL) {
        fputs(reinterpret_cast <const char*> (privateKey), privateKeyFile);
        fclose(privateKeyFile);
    }
    else {
        return 1;
    }
}