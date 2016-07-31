Category: Analysis - offensive
Points: 200
This challenge is composed of a simple remote overflow of a global array. The server address is 52.197.128.90 and the vulnerable application listens on TCP port 80-85. Each port has the same behavior so you can select one of them.

The following code contains a bug that can be exploited to read back a flag:


int pwned;
char buffer[1024];

DWORD WINAPI CallBack(LPVOID lpParameter) {
  pwned = 0;
  ZeroMemory(buffer, 1024);
  SOCKET *sock = (SOCKET *)lpParameter;
  SOCKET _sock = *sock;
  send(_sock, "Welcome", 8, 0);
  int ret = 0;
  ret = recv(_sock, buffer, 1028, 0);  
  printf("[x] RET: %d.\n", ret);
  printf("[x] PWNED: 0x%x.\n", pwned);
  Sleep(1);
  if (((pwned >> 16)&0xFFFF ^ 0xc0fe) == 0x7eaf && (((pwned & 0xFFFF)^0x1a1a) == 0xdae4)) {

    send(_sock, "PWNED", 5, 0);
    ReadAndReturn(L"key.txt", _sock);
    closesocket(_sock);
    return 0;
  }
  else {
    send(_sock, "GO AWAY", 7, 0);
    closesocket(_sock);
  }

  return 0;
}


Craft a packet that would return a valid flag. Good luck!
