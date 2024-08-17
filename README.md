![ThorSocket](img/socket.jpg)

# ThorsSocket

This library provides a Socket and Secure Socket that implement the `std::iostream` interface.

    #include "ThorsSocket/Socket.h"

    using ThorsAnvil::ThorsSocket::Socket;
    using ThorsAnvil::ThorsSocket::SSLctx;
    using ThorsAnvil::ThorsSocket::SSLMethodType;

    Socket      normalSocket({"google.com"});

    SSLctx      ctx{SSLMethodType::Client};
    Socket      secureSocket({"google.com", 443, ctx});


    // Open a socket to google
    // Print the content out to std::cout.
    std::cout << normalSocket.rdbuf();


## HomeBrew

Can be installed via brew on Mac and Linux

    brew install thors-mongo

* Mac: https://formulae.brew.sh/formula/thors-mongo
* Linux: https://formulae.brew.sh/formula-linux/thors-mongo

## Header Only

To install header only version

    git clone --single-branch --branch header-only https://github.com/Loki-Astari/ThorsMongo.git

## Contributors

Added the all-contributers bot to generate the table.


