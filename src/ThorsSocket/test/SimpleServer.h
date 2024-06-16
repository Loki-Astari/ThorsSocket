#ifndef THORSANVIL_THORSSOCKET_TEST_SIMPLE_SERVER_H
#define THORSANVIL_THORSSOCKET_TEST_SIMPLE_SERVER_H

#include <thread>
#include "Socket.h"
#include "Connection.h"
#include "ConnectionSSocket.h"

using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocketBase;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLctx;
using ThorsAnvil::ThorsSocket::ConnectionType::CertificateInfo;

class SSocketServer: public SSocketBase
{
    public:
        SSocketServer(int fd, SSLctx const& ctx, CertificateInfo&& info = CertificateInfo{})
            : SSocketBase(fd, ctx, std::move(info))
        {
            /*Do the SSL Handshake*/
            int status;
            do
            {
                status = SSL_accept(ssl);
                if (status != 1)
                {
                    int error = MOCK_FUNC(SSL_get_error)(ssl, status);
                    if (error == SSL_ERROR_WANT_ACCEPT || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                        continue;
                    }
                }
                break;
            }
            while (true);

            /* Check for error in handshake*/
            if (status < 1)
            {
                int saveErrno = MOCK_FUNC(SSL_get_error)(ssl, status);
                MOCK_FUNC(SSL_free)(ssl);
                ThorsLogAndThrow(
                    "ThorsAnvil::ThorsSocket::ConnectionType::SSocketServer",
                    "SSocketServer",
                    " :Failed on SSL_accept.",
                    " errno = ", errno, " ", getSSErrNoStr(saveErrno),
                    " msg >", ERR_error_string(saveErrno, nullptr), "<"
                );
            }

            /* Check for Client authentication error */
            if (SSL_get_verify_result(ssl) != X509_V_OK)
            {
                MOCK_FUNC(SSL_free)(ssl);
                ThorsLogAndThrow(
                    "ThorsAnvil::ThorsSocket::ConnectionType::SSocketServer",
                    "SSocketServer",
                    " :Failed on SSL_get_verify_result."
                );
            }
        }
};

class Server
{
    SOCKET_TYPE     fd;
    bool            bound;

    public:
        Server(int port, Blocking blocking)
            : fd(-1)
            , bound(false)
        {
            fd = ::socket(PF_INET, SOCK_STREAM, 0);
            if (fd == -1) {
                throw std::runtime_error("Failed to create socket: ::socket");
            }

            if (blocking == Blocking::No)
            {
                int result = thorSetSocketNonBlocking(fd);
                if (result != 0) {
                    throw std::runtime_error("Failed to set non-blocking: ::thorSetSocketNonBlocking");
                }
            }
            {
            // During testing
                // we may reuse this socket a lot so allow multiple sockets to bind
                int flag = 1;
                ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&flag), sizeof(int));
            }

            using SocketAddrIn  = struct ::sockaddr_in;
            using SocketAddrIn  = struct ::sockaddr_in;
            using SocketAddr    = struct ::sockaddr;

            SocketAddrIn    serverAddr = {};
            serverAddr.sin_family       = AF_INET;
            serverAddr.sin_port         = htons(port);
            serverAddr.sin_addr.s_addr  = INADDR_ANY;

            int count = 0;
            do
            {
                if (::bind(fd, reinterpret_cast<SocketAddr*>(&serverAddr), sizeof(serverAddr)) != 0)
                {
                    int saveErrorNo = thorGetSocketError();
                    if (saveErrorNo == EADDRINUSE && count < 3)
                    {
                        ++count;
                        PAUSE_AND_WAIT(10);
                        continue;
                    }
                    close();
                    throw std::runtime_error("Failed to Bind: ::bind");
                }
                // Bind worked.
                // Break out of retry loop.
                break;
            }
            while(true);

            bound = true;
            if (::listen(fd, 5) != 0)
            {
                close();
                throw std::runtime_error("Failed to Listen: ::listen");
            }
        }
        ~Server()
        {
            close();
        }
        void close()
        {
            if (fd != -1) {
                thorCloseSocket(fd);
            }
            fd = -1;
        }
        Server(Server const&)               = delete;
        Server& operator=(Server const&)    = delete;

        template<typename T, typename Tuple, std::size_t... Index>
        Socket accept(Tuple&& args, std::index_sequence<Index...>)
        {
            int newSocket = ::accept(fd, nullptr, nullptr);
            if (newSocket == -1)
            {
                throw std::runtime_error("Server:  -> Failed t Accept: ::accept");
            }
            return {std::make_unique<T>(newSocket, std::get<Index>(args)...)};
        }
};

class SocketSetUp
{
#ifdef  __WINNT__
    public:
        SocketSetUp()
        {
            WSADATA wsaData;
            WORD wVersionRequested = MAKEWORD(2, 2);
            int err = WSAStartup(wVersionRequested, &wsaData);
            if (err != 0) {
                printf("WSAStartup failed with error: %d\n", err);
                throw std::runtime_error("Failed to set up Sockets");
            }
        }
        ~SocketSetUp()
        {
            WSACleanup();
        }
#endif
};

class ServerStart
{
    SocketSetUp                     serverSetup;
    std::condition_variable         cond;
    std::mutex                      mutex;
    bool                            serverReady;
    std::function<void(Socket&)>    action;
    std::thread                     serverThread;

    template<typename T, typename Tuple>
    void server(int port, Tuple&& args)
    {
        Server  server(port, Blocking::Yes);
        {
            std::unique_lock<std::mutex> lock(mutex);
            serverReady = true;
            cond.notify_all();
        }

        //Socket  socket = server.accept<T>(std::forward<Args>(args)...);
        Socket  socket = server.accept<T>(std::move(args), std::make_index_sequence<std::tuple_size<Tuple>::value>{});
        action(socket);
    };

    public:
        template<typename T, typename F, typename... Args>
        void run(int port, F&& actionP, Args&&... args)
        {
            serverReady     = false;
            action          = std::move(actionP);
            std::tuple<Args...> data{std::forward<Args>(args)...};

            serverThread    = std::thread(&ServerStart::server<T, std::tuple<Args...>>, this, port, std::move(data));

            std::unique_lock<std::mutex> lock(mutex);
            cond.wait(lock, [&serverReady = this->serverReady](){return serverReady;});
        }
        ~ServerStart()
        {
            serverThread.join();
        }
};

#endif
