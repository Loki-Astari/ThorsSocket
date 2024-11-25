[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/G2G216KZR3)

![ThorSocket](img/socket.jpg)

# Installation

## HomeBrew

Can be installed via brew on Mac and Linux

    brew install thors-mongo

* Mac: https://formulae.brew.sh/formula/thors-mongo
* Linux: https://formulae.brew.sh/formula-linux/thors-mongo

## Header Only

To install header only version

    git clone --single-branch --branch header-only https://github.com/Loki-Astari/ThorsMongo.git

# Interface

## Description:

There are three basic classes you interact with:

* `ThorsAnvil::ThorsSocket::Socket`  
  Read/Write from a socket stream.  
  **#include <ThorsSocket/Socket.h>**  
* `ThorsAnvil::ThorsSocket::Server`  
  Listen on a socket for an incoming connection and creates a Socket.  
  **#include <ThorsSocket/Server.h>**  
* `ThorsAnvil::ThorsSocket::SocketStream`  
  Wraps a Socket so it can be used like a `std::iostream`  
  **#include <ThorsSocket/SocketStream.h>**  

This library is designed to allow you to write code that looks like normal synchronous blocking code, but in the background a blocking read/write operation will result in a thread being able to do other work, thus allowing you to write asynchronous code as if it was normal synchronous code.

## Socket

This class provides a mechanism for reading and writing to a socket (or other file descriptor) stream.

### Constructors:

````
    Socket(<InitObject>, Blocking blocking = Blocking::Yes);
````

The first parameter is an `init` object (described next) and the second parameter indicates if the socket is blocking or not. We default the second parameter to yes. Normally you want to start with the default value, get your normal code working then disable the blocking nature.

The `<InitObjec>` can be one of two types.

* `SocketInfo`: Connect to a normal host/port
* `SSocketInfo`: Connect to a SSL host/port

#### Normal Host/Port Connection
````
struct SocketInfo
{
    std::string_view    host;
    int                 port;
};
````

An example of creating a normal socket:

````
    ThorsAnvil::ThorsSocket::Socket  socket{{"www.google.com", 80}, ThorsAnvil::ThorsSocket::Blocking::No};
````

#### SSL Host/Port Connection
````
struct SSocketInfo
{
    std::string_view    host;
    int                 port;
    SSLctx const&       ctx;
};
````

The main difference is that you need to create an initialize an SSLctx object.  
Details about the `SSLctx` class  is provided below, but a simple example of usage would be:

````
    ThorsAnvil::ThorsSocket::SSLctx  ctx{ThorsAnvil::ThorsSocket::SSLMethodType::Client};
    ThorsAnvil::ThorsSocket::Socket  socket{{"www.google.com", 443, ctx}, ThorsAnvil::ThorsSocket::Blocking::No};
````


### Read/Write Operations:

````
        IOData getMessageData(void* buffer, std::size_t size);
        IOData tryGetMessageData(void* buffer, std::size_t size);
        IOData putMessageData(void const* buffer, std::size_t size);
        IOData tryPutMessageData(void const* buffer, std::size_t size);
````

The `tryGetMessageData()`/`tryPuMessageData()` variants will read/write until the operation would block then return immediately.
The `getMessageData()`/`putMessageData()` variants read/write and don't return until the operation is complete (if the operation does block then thread is re-used for other work).

### Flushing the buffer:

````
        void tryFlushBuffer();
````

The `tryFlushBuffer()` attempts to force the underlying socket to flush anything that is buffered locally.

### Checking/Modifying the State

````
        bool isConnected()                  const;
        int  socketId()                     const;
        void close();
````

* The `isConnected()` returns true if the socket is valid and has not been closed, otherwise false.  
* The `socketId()` returns the underlying file descriptor (or platform equivalent). This is useful for libraries that understand this (LibEvent) but should be used judiciously.  
* The `close()` close the socket and release any resources. Automatically called by the destructor.  

### Asynchronous Help

Asynchronous operations is achieved via the `YieldFunc` that can be registered for read/write operations independently.

Note: You can use this functionality to attempt to do other asynchronous work while a socket is blocked. But this is still non trivial to implement yourself. It is recommended to be used with libraries like boost/CoRoutines.

````
        void setReadYield(YieldFunc&& yield);
        void setWriteYield(YieldFunc&& yield);
````

The `setReadYield()`/`setWriteYield()` functions store a `YieldFunc` lambda that is called with a `getMessageData()`/`putMessageData()` would block.

A `YieldFunc` is a lambda that takes no parameters and returns a bool value. The return value is an indicator if the block should have been resolved. If the `YieldFunc` returns `false` the code will block until the operation is available. If the `YieldFunc` returns `true` the operation will be re-attempted, it is is still blocking the `YieldFunc` will be called again.

## Server

This class provides a mechanism for listening on a port for incoming connections and returning a `Socket` object that can then be used for communication.

### Constructors:

````
    Server(<InitObject>, Blocking blocking = Blocking::Yes);
````

The first parameter is an `init` object (described next) and the second parameter indicates if the server is blocking (on accept) or not. We default the second parameter to yes. Normally you want to start with the default value, get your normal code working then disable the blocking nature.

The `<InitObjec>` can be one of two types.

* `ServerInfo`: Listen on a normal port.
* `SServerInfo`: Listen on an SSL port.

#### Normal Port
````
struct ServerInfo
{
    int                 port;
};
````

An example of creating a normal server:

````
    ThorsAnvil::ThorsSocket::Server server({80}, ThorsAnvil::ThorsSocket::Blocking::No);
````

#### SSL Port
````
struct SServerInfo
{
    int                 port;
    SSLctx const&       ctx;
};
````

The main difference is that you need to create an initialize an SSLctx object.  
Details about the `SSLctx` class  is provided below, but a simple example of usage would be:

````
    ThorsAnvil::ThorsSocket::CertificateInfo certificate{"PathToCertificate-fullchain.pem", "PathToCertificate-privkey.pem"};
    ThorsAnvil::ThorsSocket::SSLctx  ctx{ThorsAnvil::ThorsSocket::SSLMethodType::Server, certificate};
    ThorsAnvil::ThorsSocket::Socket  socket{{443, ctx}, ThorsAnvil::ThorsSocket::Blocking::No};
````

### Accepting a connection
````
        Socket accept(Blocking blocking = Blocking::Yes);
````

The normal use of a server is to call the `accept()` method which will return a `Socket` object that can then be used for communication. The parameter blocking is used on the newly created socket.

### Checking/Modifying the State
````
        bool isConnected()                  const;
        int  socketId()                     const;
        void close();
````

* The `isConnected()` returns true if the server is valid, otherwise false.  
* The `socketId()` returns the underlying file descriptor (or platform equivalent). This is useful for libraries that understand this (LibEvent) but should be used judiciously.  
* The `close()` close the server and release any resources. Automatically called by the destructor.  

### Asynchronous Help

Asynchronous operations is achieved via the `YieldFunc` that is registered for accept operations independently.

Note: You can use this functionality to attempt to do other asynchronous work while the server is blocked. But this is still non trivial to implement yourself. It is recommended to be used with libraries like boost/CoRoutines.

````
        void setYield(YieldFunc&& yield);
````

The `setYield()` functions store a `YieldFunc` lambda that is called with a `accept()` would block (most of the time).

A `YieldFunc` is a lambda that takes no parameters and returns a bool value. The return value is an indicator if the block should have been resolved. If the `YieldFunc` returns `false` the code will block until the operation is available. If the `YieldFunc` returns `true` the operation will be re-attempted, it is is still blocking the `YieldFunc` will be called again.

## SocketStream

The constructor of a `SocketStream` accepts a moved `Socket` object (that it takes ownership of).  
This type inherits from `std::iostream` and can be used by all standard IO operations.  

Internally it will try and use the available data in a buffer (std::iostreambuf). Any registered `YieldFunc` will only be called after the internal buffer is completely used up and an attempt to get more data in-to/out-of the buffer would result in blocking operation.

## SSLctx

This object contains all the information used by the SSL socket.

### Construction:
````
        template<typename... Args>
        SSLctx(SSLMethodType methodType, Args&&... args);
````

The first parameter is the type (Client/Server). For `Socket` initialization use `ThorsAnvil::ThorsSocket::SSLMethodType::Clinet` for Server initialization use `ThorsAnvil::ThorsSocket::SSLMethodType::Server`.

No other parameters are required but any provided will configure the SSLctx object. Note: on the server side you should probably provide a `CertificateInfo` object. The following classes can be used to configure the SSLctx object.

* ProtocolInfo
* CipherInfo
* CertificateInfo
* CertifcateAuthorityInfo
* ClientCAListInfo

#### ProtocolInfo
````
        enum Protocol { TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3 };       // Valid protocols.
        ProtocolInfo()                                              // Limit protocol to TLS_1_2 -> TLS_1_3
        ProtocolInfo(Protocol minProtocol, Protocol maxProtocol)    // Set a specific protocol range.
````

Allows you to limit the protocol used by the SSL connection.

#### CipherInfo
````
struct CipherInfo
{
    std::string         cipherList;
    std::string         cipherSuite;
};
````

Define valid cipher and suit options.
#### CertificateInfo
````
        CertificateInfo(std::string const& certificateFileName, std::string const& keyFileName);
        CertificateInfo(std::string const& certificateFileName, std::string const& keyFileName, GetPasswordFunc&& getPassword);
````

Define where the certificate files are located on the current file system. If the "keyFile" is password protected you can provide a `GetPasswordFunc` to retrieve the password from you password store.

#### CertifcateAuthorityInfo / ClientCAListInfo
Define the CertifcateAuthorityInfo information.

## Contributors

Added the all-contributers bot to generate the table.


