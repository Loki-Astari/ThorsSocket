#ifndef THORSANVIL_THORSSOCKET_TEST_SIMPLE_SERVER_H
#define THORSANVIL_THORSSOCKET_TEST_SIMPLE_SERVER_H

#include <thread>
#include "Socket.h"
#include "ConnectionSocket.h"
#include "ConnectionSSocket.h"

using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::SSLctx;
using ThorsAnvil::ThorsSocket::CertificateInfo;
using ThorsAnvil::ThorsSocket::OpenSocketInfo;
using ThorsAnvil::ThorsSocket::OpenSSocketInfo;
using ConSocket = ThorsAnvil::ThorsSocket::ConnectionType::Socket;
using ConSSocket = ThorsAnvil::ThorsSocket::ConnectionType::SSocketBase;

struct SocketServerInfo;
struct SSocketServerInfo;
class SocketServerAccept;
class SSocketServerAccept;

struct SocketAcceptRequest
{
    using ServerInfo   = SocketServerInfo;

    SocketAcceptRequest()
    {}
};
struct SSocketAcceptRequest
{
    using ServerInfo   = SSocketServerInfo;

    SSocketAcceptRequest(SSLctx const& ctx, CertificateInfo&& certificate = CertificateInfo{})
        : ctx(ctx)
        , certificate(std::move(certificate))
    {}
    SSLctx const&        ctx;
    CertificateInfo&&   certificate;
};
struct SocketServerInfo
{
    using Connection = SocketServerAccept;

    SocketServerInfo(SOCKET_TYPE fd, SocketAcceptRequest const& /*request*/)
        : fd(fd)
    {}

    SOCKET_TYPE         fd;
};
struct SSocketServerInfo
{
    using Connection = SSocketServerAccept;

    SSocketServerInfo(SOCKET_TYPE fd, SSocketAcceptRequest const& request)
        : fd(fd)
        , ctx(request.ctx)
        , certificate(std::move(request.certificate))
    {}

    SOCKET_TYPE         fd;
    SSLctx const&       ctx;
    CertificateInfo&&   certificate;
};

class SocketServerAccept: public ConSocket
{
    public:
        SocketServerAccept(SocketServerInfo const& serverInfo)
            : ConSocket(OpenSocketInfo{serverInfo.fd})
        {}
};
class SSocketServerAccept: public ConSSocket
{
    public:
        SSocketServerAccept(SSocketServerInfo const& serverInfo)
            : ConSSocket(OpenSSocketInfo{serverInfo.fd, serverInfo.ctx, std::move(serverInfo.certificate)})
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

        template<typename T>
        Socket accept(T&& serverRequest)
        {
            using ServerInfo = typename T::ServerInfo;
            ServerInfo acceptInfo{::accept(fd, nullptr, nullptr), serverRequest};
            if (acceptInfo.fd == -1)
            {
                throw std::runtime_error("Server:  -> Failed t Accept: ::accept");
            }
            return Socket{ThorsAnvil::ThorsSocket::TestMarker::True, acceptInfo};
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

    template<typename T>
    void server(int port, T&& serverRequest)
    {
        Server  server(port, Blocking::Yes);
        {
            std::unique_lock<std::mutex> lock(mutex);
            serverReady = true;
            cond.notify_all();
        }

        //Socket  socket = server.accept<T>(std::forward<Args>(args)...);
        Socket  socket = server.accept<T>(std::move(serverRequest));
        action(socket);
    }

    public:
        template<typename T, typename F>
        void run(int port, T&& serverRequest, F&& actionP)
        {
            serverReady     = false;
            action          = std::move(actionP);

            serverThread    = std::thread(&ServerStart::server<T>, this, port, std::move(serverRequest));

            std::unique_lock<std::mutex> lock(mutex);
            cond.wait(lock, [&serverReady = this->serverReady](){return serverReady;});
        }
        ~ServerStart()
        {
            serverThread.join();
        }
};

#endif
