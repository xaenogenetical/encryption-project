#include <string>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <vector>
#include <queue>
#include <gmpxx.h>
#include <random>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iomanip>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#endif
#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>
#endif
#include <stack>

std::string bit_flip(std::string);
std::string byte_flip(std::string);
std::string huge_flip(std::string);
std::string mask(std::string);
std::string reverse(std::string);
std::string encrypt(std::string &);
std::string decrypt(std::string &);
std::string passwordHash(const std::string &);

typedef std::string (*functionpointer)(std::string);
// bit_flip, byte_flip, huge_flip, mask, reverse
functionpointer techniques[] = {bit_flip, byte_flip, reverse, mask};
#define NUM_TECHS (sizeof(techniques) / sizeof(techniques[0]))

std::string pass;
std::mt19937 *generator = nullptr;
#ifdef _WIN32
mpz_class gcd(mpz_class a, mpz_class b)
{ // find GDC, for ensuring coprime-ness
    while (b != 0)
    {
        mpz_class temp = b;
        b % a;
        a = temp;
    }
    return a;
}

mpz_class modular_inv(mpz_class a, mpz_class m)
{
    mpz_class r;
    if (mpz_invert(r.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()))
    {
        return r;
    }
    else
    {
        std::cerr << "MI Error." << std::endl;
        exit(1);
    }
}
#endif
int main(int argc, char const *argv[])
{
    // generator = new std::mt19937();
    // std::cout << "Testing?? :)\n";
    // std::cout << "Text to test: ";
    // std::string buffah;
    // std::getline(std::cin, buffah);
    // std::string encrypted = encrypt(buffah);
    // std::cout << "Encrypted string: " << encrypted << "\n";
    // std::cout << "Decrypting the result: \n"
    //           << decrypt(encrypted) << std::endl;
    // exit(0);

    auto hasArg = [argc, argv](char *target)
    {
        for (int i = 0; i < argc; i++)
        {
            if (strcmp(target, argv[i]) == 0)
            {
                return i;
            }
        }
        return 0;
    };

    int index_of_e = hasArg("-e");
    int index_of_d = hasArg("-d");

    if (argc < 3 || (!index_of_e && !index_of_d))
    {
        std::cerr << "Improper Args. Usage: -e '<message-to-encrypt>' AND/OR -d '<message-to-decrypt>' (Use single quotes around the strings to prevent shell issues)" << std::endl;
    }
    int randomP;
    int randomQ;
    uint32_t seed;
#ifdef __linux__
    ssize_t result = getrandom(&seed, sizeof(seed), GRND_RANDOM);
    if (result == -1 && errno == ENOSYS) // some older linux systems don't support the getrandom() syscall, this is the fallback
    {
        std::ifstream rando("/dev/random", std::ios::in | std::ios::binary);
        if (!rando)
        {
            std::cerr << "Failed to securely generate, aborting" << std::endl;
            exit(1);
        }
        rando.read(reinterpret_cast<char *>(&seed), sizeof(seed));
    }

#elif defined(_WIN32)
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContext(&hProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        return 1;
    }
    BOOL result = CryptGenRandom(hProvider, sizeof(seed), reinterpret_cast<BYTE *>(&seed));
    CryptReleaseContext(hProvider, 0);
    if (result != TRUE)
    {
        std::cerr << "Secure RNG failed, aborting" << std::endl;
        exit(1);
    }
#else
    std::cerr << "Operating System not supported" << std::endl;
    exit(1);
#endif
    generator = new std::mt19937(seed);

    if (index_of_e != argc - 1 && strcmp(argv[index_of_e + 1], "-d"))
    {
        std::string message = argv[index_of_e + 1];
        std::string msgg = encrypt(message);
        std::cout << "||START OF DATA||" << msgg << "||END OF DATA||" << std::endl;
    }
    if (index_of_d != argc - 1 && strcmp(argv[index_of_d + 1], "-e"))
    {
        std::string message = argv[index_of_d + 1];
        std::cout << decrypt(message) << std::endl;
    }
    delete generator;
    return 0;
}

std::string bit_flip(std::string msg)
{
    std::string encrypting;
    for (char &c : msg)
    {
        char ch = '\0';
        int bit0 = c & 1;
        int bit1 = (c >> 1) & 1;
        int bit2 = (c >> 2) & 1;
        int bit3 = (c >> 3) & 1;

        ch |= (bit2 << 3); // ch = bit2 0 0 0
        ch |= (bit3 << 2); // bit2 bit3 0 0
        ch |= (bit0 << 1); // bit2 bit3 bit0 0
        ch |= (bit1);      // bit2 bit3 bit0 bit1
        ch |= ((c >> 4) & 1) << 4;
        ch |= ((c >> 5) & 1) << 5;
        ch |= ((c >> 6) & 1) << 6;
        ch |= ((c >> 7) & 1) << 7;
        encrypting += ch;
    }
    return encrypting;
}

std::string byte_flip(std::string msg)
{
    std::string ret = msg;
    int i = 0;
    int j = 1;
    while (j < ret.length())
    {
        char temp = ret.at(i);
        ret.at(i) = ret.at(j);
        ret.at(j) = temp;
        i += 2;
        j += 2;
        // std::cout << "Instep: " << ret << std::endl;
    }
    return ret;
}

std::string reverse(std::string msg)
{
    std::string a = msg;
    std::reverse(a.begin(), a.end());
    return a;
}

std::string mask(std::string msg)
{
    int passIdx = 0;
    std::string passWrd = passwordHash(pass); // adds extra runtime work, but more secure
    // std::cout << "passWrd State: " << passWrd << std::endl;
    std::string maskable = msg;
    unsigned char key = 0;
    for (char &c : passWrd)
    {
        key += c;
    }
    // std::cout << key << std::endl;
    for (char &ch : maskable)
    {
        unsigned char c = static_cast<unsigned char>(ch);
        // std::cout << "XORing " << c << " with " << passWrd.at(passIdx) << " which returns " << (char)(c ^ passWrd.at(passIdx)) << std::endl;
        c ^= (char)10;
    }
    return maskable;
}

std::string passwordHash(const std::string &pass)
{

    std::vector<unsigned char> constants = {0x64, 0x79, 0x6C, 0x61, 0x6E, 0x6B, 0x72, 0x61, 0x68, 0x65, 0x6E, 0x62, 0x75, 0x68, 0x6C};

    for (int i = 0; i < pass.size(); i++)
    {
        unsigned char byte = static_cast<unsigned char>(pass.at(i));
        for (unsigned char &c : constants)
        {
            c ^= byte;
            c ^= static_cast<unsigned char>(i + 1);
        }
    }
    std::ostringstream streamer;
    for (unsigned char &c : constants)
    {
        streamer << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return streamer.str();
}

std::string encrypt(std::string &msg)
{
    std::cout << "Enter the password you want to use to decrypt this data. Required to be an exact character match in order to decrypt. No whitespace characters." << std::endl;
    std::string passB; // passBuffer
    std::getline(std::cin, pass);
    passB = passwordHash(pass);
    // std::cout << "Hashed Password:" << passB << std::endl;
    std::uniform_int_distribution<> dist(0, NUM_TECHS - 1); // will generate random numbers from 0 to NUM_TECHS
    std::string encrypted = msg;
    std::queue<int> order;
    std::vector<bool> alreadyDone(NUM_TECHS, false);
    int i = 0;
    int attempts = 0;
    int choice = -1;
    do
    {
        do
        {
            choice = dist(*generator);
            attempts++;
            if (attempts > 100)
            {
                std::cerr << "Error in generator loop" << std::endl;
                exit(1);
            }
            // std::cout << "trying choice = " << choice << std::endl;
        } while (alreadyDone[choice]); // can't use a technique twice, but still allows them to be done in a random order
        // std::cout << "Doing technique " << choice << std::endl;
        encrypted = techniques[choice](encrypted);
        // std::cout << "Status: ";
        /*for (char &c : encrypted)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }*/
        // std::cout << "\nVisual: " << encrypted << std::endl;
        alreadyDone[choice] = true;
        order.push(choice);
        i++;
    } while (i < NUM_TECHS);
    std::string returner = passB + encrypted;
    // unsigned char miniKey = 0;
    // for (char &c : pass)
    //{
    //     miniKey += c - 'a';
    // }
    while (!order.empty())
    {
        returner = std::string(1, ('!' + ((order.front())))) + returner;
        order.pop();
    }
    return returner;
}
std::string decrypt(std::string &msg)
{
decryption_top:
    std::cout << "Password for decryption:" << std::endl;
    std::getline(std::cin, pass);
    std::string hashedPassAttempt = passwordHash(pass);
    // unsigned char miniKey = 0;
    // for (char &c : pass)
    //{
    //     miniKey += c - 'a';
    // }
    std::stringstream streamer2(msg);
    std::queue<int> todo;
    int i = 0;
    while (i < NUM_TECHS)
    {
        unsigned char item = streamer2.get(); // get byte
        // item ^= pass.length();                // decode
        item -= '!'; // convert back to number
        // std::cout << "Number pulled from front: " << (int)item << std::endl;
        todo.push((int)item); // push to stack
        i++;
    }
    std::string decPass;
    char buffer[30];
    streamer2.read(buffer, 30); // get the next 15 "bytes" (the encoded password but in hex format)
    decPass += buffer;
    int attempts = 0;
    while (++attempts)
    {
        // std::cout << "Hashed Pass Attempt: " << hashedPassAttempt << "\n";
        // std::cout << "decPass:             " << decPass << std::endl;
        if (hashedPassAttempt == decPass)
        {
            break;
        }
        if (attempts > 10) // brute force protection (weak)
        {
            std::cerr << "Too many failed password attempts. Aborting." << std::endl;
            exit(1);
        }
        goto decryption_top;
    }
    std::string decoding;
    char bitten;
    while (1)
    {
        bitten = streamer2.get();
        if (streamer2.eof())
        {
            break;
        }
        decoding += bitten;
    }

    // std::cout << "Decoding this: " << decoding << std::endl;
    // std::cout << "Bytes: ";
    /*for (char &c : decoding)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    std::cout << std::endl;*/

    while (!todo.empty())
    {
        // std::cout << "decoding with tech " << todo.front() << std::endl;
        decoding = techniques[todo.front()](decoding);
        // std::cout << "Status: ";
        /*for (char &c : decoding)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }*/
        // std::cout << "\nVisual: " << decoding << std::endl;
        todo.pop();
    }
    return decoding;
}
