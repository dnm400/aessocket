#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h> //for inet_pton
#include <tchar.h> //for _T
#include <thread>
#include "fileaes.h"


#define keyaes "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c" //key for encryption an decryption

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

void sendmsg(SOCKET clientsocket){
    uint8_t CTR[16]= {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x00, 0x00, 0x00, 0x00}; 
    
    char sendbuf[4096];
    while(true){
    memset(sendbuf, 0, sizeof(sendbuf));

    cin.getline(sendbuf, sizeof(sendbuf));

    
    string willbecrypted(sendbuf);
    string encrypted = crypt(willbecrypted, keyaes, CTR);
 
    char cryptbuf[4096];
    strncpy(cryptbuf, encrypted.c_str(), sizeof(cryptbuf) - 1);
    cryptbuf[sizeof(cryptbuf) - 1] = '\0'; // Ensure null-termination

    int sendlength = send(clientsocket, cryptbuf, strlen(cryptbuf), 0);
    if(sendlength == SOCKET_ERROR){
        cout << "Send failed" << endl;
        closesocket(clientsocket);
        WSACleanup();
        break;
    }
    else{
        cout << "Send OK " << endl;
    }
    }
}

void recmsg(SOCKET clientsocket){
    uint8_t CTR[16]= {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x00, 0x00, 0x00, 0x00}; 

    char recbuf[4096];
    while(true){
    memset(recbuf, 0, sizeof(recbuf));

    int reclength = recv(clientsocket, recbuf, 4096, 0);
    if(reclength < 0){
        cout << "Receive failed" << endl;
        closesocket(clientsocket);
        WSACleanup();
        break;
    }
    else{
        string cryptedmessage(recbuf, reclength);
        cout << "Received: " << cryptedmessage << endl;
        cout << "Decrypted:   " << crypt(cryptedmessage, keyaes, CTR) << endl;
    }
    }
}

int main(){

    //Initialize Winsock
    WSADATA wsaData;

    int resdll = WSAStartup(MAKEWORD(2,2), &wsaData);
    if(resdll != 0){
        cout << "WSAStartup failed" << endl;
        return 0;
    }

    //Create a socket
    SOCKET clientsocket = INVALID_SOCKET;
    clientsocket = socket(AF_INET, SOCK_STREAM, 0);
    if(clientsocket == INVALID_SOCKET){
        cout << "Creating socket failed" << endl;
        WSACleanup();
        return 0;
    }
    else {
        cout << "Creating socket OK" << endl;
    }

    //Connect
    int port = 12345;
    sockaddr_in clientadd;
    clientadd.sin_family = AF_INET;
    InetPton(AF_INET, _T("127.0.0.1"), &clientadd.sin_addr.s_addr);
    clientadd.sin_port = htons(port);
    if(connect(clientsocket, (SOCKADDR*)&clientadd, sizeof(clientadd)) == SOCKET_ERROR){
        cout << "Connect failed" << endl;
        closesocket(clientsocket);
        WSACleanup();
        return 0;
    }
    else{
        cout << "Connect OK" << endl;
    }

    thread recT(recmsg, clientsocket); //for simultaneous chat,not one by one
    thread sendT(sendmsg, clientsocket);
    sendT.join();
    recT.join();


    system("pause");    
    closesocket(clientsocket);
    WSACleanup();
    return 0;
}