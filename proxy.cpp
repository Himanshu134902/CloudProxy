#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <unordered_set>

#pragma comment(lib, "ws2_32.lib")

constexpr int PORT = 8888;
constexpr int BUFFER_SIZE = 8192;

// In-memory Zero Trust policy: Blocked domains
const std::unordered_set<std::string> BLOCKED_DOMAINS = {
    "example.com",
    "badsite.com",
    "malicious.org"
};

// Helper: Resolve host name to IP and connect
SOCKET connect_to_remote(const std::string& host, int port) {
    struct hostent* he = gethostbyname(host.c_str());
    if (he == nullptr) {
        return INVALID_SOCKET;
    }

    SOCKET remote_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remote_sock == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }

    sockaddr_in remote_addr{};
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(port);
    remote_addr.sin_addr = *((struct in_addr*)he->h_addr);

    if (connect(remote_sock, (sockaddr*)&remote_addr, sizeof(remote_addr)) == SOCKET_ERROR) {
        closesocket(remote_sock);
        return INVALID_SOCKET;
    }

    return remote_sock;
}

// Handle HTTPS Tunneling via HTTP CONNECT using select()
void handle_connect_tunnel(SOCKET client_sock, SOCKET remote_sock) {
    const char* ok_response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(client_sock, ok_response, (int)strlen(ok_response), 0);

    char buffer[BUFFER_SIZE];

    while (true) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);
        FD_SET(remote_sock, &read_fds);

        timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        int activity = select(0, &read_fds, NULL, NULL, &timeout);
        if (activity <= 0) break;

        // Client -> Remote
        if (FD_ISSET(client_sock, &read_fds)) {
            int bytes = recv(client_sock, buffer, sizeof(buffer), 0);
            if (bytes <= 0) break;
            send(remote_sock, buffer, bytes, 0);
        }

        // Remote -> Client
        if (FD_ISSET(remote_sock, &read_fds)) {
            int bytes = recv(remote_sock, buffer, sizeof(buffer), 0);
            if (bytes <= 0) break;
            send(client_sock, buffer, bytes, 0);
        }
    }
}

// Handle standard HTTP forwarding
void handle_http_forward(SOCKET client_sock, SOCKET remote_sock, const char* initial_buf, int initial_len) {
    send(remote_sock, initial_buf, initial_len, 0);

    char buffer[BUFFER_SIZE];
    while (true) {
        int bytes = recv(remote_sock, buffer, sizeof(buffer), 0);
        if (bytes <= 0) break;
        send(client_sock, buffer, bytes, 0);
    }
}

// Client worker routine
DWORD WINAPI handle_client_thread(LPVOID lpParam) {
    SOCKET client_sock = (SOCKET)lpParam;
    char buffer[BUFFER_SIZE] = {0};

    int bytes_read = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        closesocket(client_sock);
        return 0;
    }

    std::string request(buffer, bytes_read);
    std::istringstream stream(request);
    std::string method, url, version;
    stream >> method >> url >> version;

    std::cout << "[*] Intercepted: " << method << " " << url << std::endl;

    std::string host;
    int port = 80;

    // Parse target host and port
    if (method == "CONNECT") {
        size_t colon_pos = url.find(':');
        if (colon_pos != std::string::npos) {
            host = url.substr(0, colon_pos);
            port = std::stoi(url.substr(colon_pos + 1));
        } else {
            host = url;
            port = 443;
        }
    } else {
        std::string temp = url;
        if (temp.find("http://") == 0) temp = temp.substr(7);
        if (temp.find("https://") == 0) temp = temp.substr(8);

        size_t slash_pos = temp.find('/');
        std::string host_port = (slash_pos == std::string::npos) ? temp : temp.substr(0, slash_pos);

        size_t colon_pos = host_port.find(':');
        if (colon_pos != std::string::npos) {
            host = host_port.substr(0, colon_pos);
            port = std::stoi(host_port.substr(colon_pos + 1));
        } else {
            host = host_port;
            port = 80;
        }
    }

    // Zero Trust Policy Check: In-memory Domain Blacklisting
    if (BLOCKED_DOMAINS.find(host) != BLOCKED_DOMAINS.end()) {
        std::cout << "[!] Access Blocked by Policy: " << host << std::endl;
        std::string response =
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n\r\n"
            "Access Denied: The destination violates CloudProxy zero-trust policy.\n";
        send(client_sock, response.c_str(), (int)response.size(), 0);
        closesocket(client_sock);
        return 0;
    }

    // Connect to external server
    SOCKET remote_sock = connect_to_remote(host, port);
    if (remote_sock == INVALID_SOCKET) {
        std::cerr << "[-] Failed to connect to: " << host << std::endl;
        closesocket(client_sock);
        return 0;
    }

    // Route based on HTTP method
    if (method == "CONNECT") {
        handle_connect_tunnel(client_sock, remote_sock);
    } else {
        handle_http_forward(client_sock, remote_sock, buffer, bytes_read);
    }

    closesocket(remote_sock);
    closesocket(client_sock);
    return 0;
}

int main() {
    // 1. Initialize Winsock
    WSADATA wsaData;
    int wsaInit = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaInit != 0) {
        std::cerr << "WSAStartup failed: " << wsaInit << std::endl;
        return 1;
    }

    // 2. Create listening TCP socket
    SOCKET server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    BOOL opt = TRUE;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // 3. Bind
    if (bind(server_sock, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    // 4. Listen
    if (listen(server_sock, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    std::cout << "[+] CloudProxy Server started on port " << PORT << " (Windows C++)" << std::endl;

    // 5. Connection Accept loop
    while (true) {
        sockaddr_in client_addr{};
        int client_len = sizeof(client_addr);
        SOCKET client_sock = accept(server_sock, (sockaddr*)&client_addr, &client_len);

        if (client_sock == INVALID_SOCKET) {
            std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
            continue;
        }

        HANDLE hThread = CreateThread(
            NULL,
            0,
            handle_client_thread,
            (LPVOID)client_sock,
            0,
            NULL
        );

        if (hThread) {
            CloseHandle(hThread);
        } else {
            closesocket(client_sock);
        }
    }

    closesocket(server_sock);
    WSACleanup();
    return 0;
}