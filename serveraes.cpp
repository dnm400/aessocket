#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h> // for inet_pton
#include <tchar.h> // for _T
#include <thread>
#include "fileaes.h"

#define keyaes "2b7e151628aed2a6abf7158809cf4f3c" // key for encryption and decryption

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

void receiveserver(SOCKET newsocket) {
    uint8_t IV[12]= {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}; // 96-bit IV
    uint8_t counter32[4] = {0x00, 0x00, 0x00, 0x00}; //remaining 32-bit
    uint8_t CTR[sizeof(IV) + sizeof(counter32)]; //16 byte
    memcpy(CTR, IV, sizeof(IV));
    memcpy(CTR + sizeof(IV), counter32, sizeof(counter32));    
    char receivebuf[4096];

    while (true) {
        memset(receivebuf, 0, sizeof(receivebuf));
        int receivelength = recv(newsocket, receivebuf, 4096, 0);

        if (receivelength < 0) {
            cout << "Receive failed" << endl;
            closesocket(newsocket);
            WSACleanup();
            break;
        } else {
            string receivedmessage(receivebuf, receivelength);
            cout << "Received: " << receivedmessage << endl;

            uint8_t currentCTR[16];
            memcpy(currentCTR, CTR, 16); // Copy CTR state for current decryption

            receivedmessage.erase(remove_if(receivedmessage.begin(), receivedmessage.end(), [](char c) { return isspace(static_cast<unsigned char>(c)); }), receivedmessage.end());
            string hexreceive = bintohex(receivedmessage);
            string decryptedmsg = hextobin(crypt(hexreceive, keyaes, currentCTR));
            cout << "Decrypted:   " << decryptedmsg << endl;
        }
    }
}

void sendserver(SOCKET newsocket) {

    uint8_t IV[12]= {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}; // 96-bit IV
    uint8_t counter32[4] = {0x00, 0x00, 0x00, 0x00}; //remaining 32-bit
    uint8_t CTR[sizeof(IV) + sizeof(counter32)]; //16 byte
    memcpy(CTR, IV, sizeof(IV));
    memcpy(CTR + sizeof(IV), counter32, sizeof(counter32));
    string sendbuf;

    while (true) {
        getline(cin, sendbuf);

        uint8_t currentCTR[16];
        memcpy(currentCTR, CTR, 16); // Copy CTR state for current encryption
        sendbuf.erase(remove_if(sendbuf.begin(), sendbuf.end(), [](char c) { return isspace(static_cast<unsigned char>(c)); }), sendbuf.end());
        string encrypted = hextobin(crypt(bintohex(sendbuf), keyaes, currentCTR));
        int sendlength = send(newsocket, encrypted.c_str(), encrypted.size(), 0);

        if (sendlength == SOCKET_ERROR) {
            cout << "Send failed" << endl;
            closesocket(newsocket);
            WSACleanup();
            break;
        } else {
            cout << "Send OK " << endl;
        }
    }
}

int main() {
    WSADATA wsaData;
    int resdll = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (resdll != 0) {
        cout << "WSAStartup failed" << endl;
        return 0;
    }

    SOCKET originalsocket = INVALID_SOCKET;
    originalsocket = socket(AF_INET, SOCK_STREAM, 0);
    if (originalsocket == INVALID_SOCKET) {
        cout << "Creating socket failed" << endl;
        WSACleanup();
        return 0;
    } else {
        cout << "Creating socket OK" << endl;
    }

    int port = 12345;
    sockaddr_in addvar;
    addvar.sin_family = AF_INET;
    addvar.sin_port = htons(port);
    InetPton(AF_INET, _T("127.0.0.1"), &addvar.sin_addr.s_addr);
    if (bind(originalsocket, (SOCKADDR*)&addvar, sizeof(addvar)) == SOCKET_ERROR) {
        cout << "Bind failed" << endl;
        closesocket(originalsocket);
        WSACleanup();
        return 0;
    } else {
        cout << "Bind OK" << endl;
    }

    if (listen(originalsocket, 1) == SOCKET_ERROR) {
        cout << "Listen failed" << endl;
        closesocket(originalsocket);
        WSACleanup();
        return 0;
    } else {
        cout << "Listen OK" << endl;
    }

    SOCKET newsocket = accept(originalsocket, NULL, NULL);
    if (newsocket == INVALID_SOCKET) {
        cout << "New socket and accept failed" << endl;
        WSACleanup();
        return -1;
    }

    thread recT(receiveserver, newsocket); // for simultaneous chat, not one by one
    thread sendT(sendserver, newsocket);
    sendT.join();
    recT.join();

    system("pause");
    closesocket(originalsocket);
    closesocket(newsocket);
    WSACleanup();
    return 0;
}
