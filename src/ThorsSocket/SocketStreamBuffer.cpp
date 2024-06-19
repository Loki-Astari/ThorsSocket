#include "SocketStreamBuffer.h"
using namespace ThorsAnvil::ThorsSocket;


SocketStreamBuffer::SocketStreamBuffer(PipeInfo const& info)
    : std::streambuf{}
    , socket(info, Blocking::No)
    , inputBuffer(4 * 1024)
    , outputBuffer(4 * 1024)
    , inCount(0)
    , outCount(0)
{}

SocketStreamBuffer::SocketStreamBuffer(FileInfo const& info)
    : std::streambuf{}
    , socket(info, Blocking::No)
    , inputBuffer(4 * 1024)
    , outputBuffer(4 * 1024)
    , inCount(0)
    , outCount(0)
{}

SocketStreamBuffer::SocketStreamBuffer(SocketInfo const& info)
    : std::streambuf{}
    , socket(info, Blocking::No)
    , inputBuffer(4 * 1024)
    , outputBuffer(4 * 1024)
    , inCount(0)
    , outCount(0)
{}

SocketStreamBuffer::SocketStreamBuffer(SSocketInfo const& info)
    : std::streambuf{}
    , socket(info, Blocking::No)
    , inputBuffer(4 * 1024)
    , outputBuffer(4 * 1024)
    , inCount(0)
    , outCount(0)
{}

SocketStreamBuffer::SocketStreamBuffer(SocketStreamBuffer&& move) noexcept
    : std::streambuf{std::move(move)}
    , socket(std::move(move.socket))
    , inputBuffer(std::move(move.inputBuffer))
    , outputBuffer(std::move(move.outputBuffer))
    , inCount(move.inCount)
    , outCount(move.outCount)
{}

SocketStreamBuffer::~SocketStreamBuffer()
{
    if (pbase() == nullptr)
    {
        return;
    }
    // Force the buffer to be output to the socket
    try
    {
        overflow();
    }
    // Catch and drop any exceptions.
    // Logging so we know what happened.
    catch (std::exception const& e)
    {
        ThorsCatchMessage("ThorsAnvil::ThorsSocket::SocketStreamBufferBase", "~SocketStreamBufferBase", e.what());
    }
    catch (...)
    {
        ThorsCatchMessage("ThorsAnvil::ThorsSocket::SocketStreamBufferBase", "~SocketStreamBufferBase", "UNKNOWN");
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SocketStreamBuffer::int_type SocketStreamBuffer::underflow()
{
    /*
     * Ensures that at least one character is available in the input area by updating the pointers
     * to the input area (if needed) * and reading more data in from the input sequence
     * (if applicable).
     *
     * Returns the value of that character (converted to int_type with Traits::to_int_type(c)) on success
     * or Traits::eof() on failure.
     *
     * The function may update gptr, egptr and eback pointers to define the location of newly
     * loaded data (if any).
     *
     * On failure, the function ensures that either gptr() == nullptr or gptr() == egptr.
     * The base class version of the function does nothing. The derived classes may override this function
     * to allow updates to the get area in the case of exhaustion.
     */
    if (gptr() == egptr())
    {
        // We have read the whole of this buffer.
        // Add it to the count.
        inCount += (egptr() - eback());

        // Now get more data
        IOData result = socket.tryGetMessageData(&inputBuffer[0], inputBuffer.size());
        if (result.dataSize == 0 && result.stillOpen)
        {
            // Must get at least one byte.
            // So if not data was retrieved read blocking until we have data or there
            // is an error
            result = socket.getMessageData(&inputBuffer[0], 1);
        }
        setg(&inputBuffer[0], &inputBuffer[0], &inputBuffer[result.dataSize]);
    }
    return gptr() == egptr() ? traits::eof() : traits::to_int_type(*gptr());
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
std::streamsize SocketStreamBuffer::xsgetn(char_type* dest, std::streamsize count)
{
    /*
     * Reads count characters from the input sequence and stores them into a character array pointed to by dest.
     *
     * The characters are read as if by repeated calls to sbumpc().
     *
     * That is, if less than count characters are immediately available, the function calls uflow() to
     * provide more until traits::eof() is returned. Classes derived from std::basic_streambuf are permitted
     * to provide more efficient implementations of this function.
     */


    std::streamsize currentBufferSize = egptr() - gptr();
    std::streamsize nextChunkSize    = std::min(count, currentBufferSize);

    // Step 1: Read what is currently in the buffer into the dest.
    std::copy(gptr(), gptr() + nextChunkSize, dest);
    gbump(nextChunkSize);

    std::streamsize       retrieved  = nextChunkSize;
    std::streamsize const bufferSize = static_cast<std::streamsize>(inputBuffer.size());

    if (retrieved != count)
    {
        // There was not enough data in the buffer.
        // So we are going to have to go the socket to get the remaining data.
        nextChunkSize    = count - retrieved;

        if (nextChunkSize > (bufferSize / 2))
        {
            // If we still have to retrieve a significant chunk then read it directly into
            // into the destination object. Note: This is a blocking call and will return
            // only when there is enough data.
            IOData result = socket.getMessageData(dest + retrieved, count - retrieved);
            inCount += result.dataSize;
            retrieved += result.dataSize;
        }
        else
        {
            // There is some data to read but less than a significant chunk.
            // So we are going to use underflow() to try and read a full buffer.
            // Note: underflow() does a `tryGetMessageData()` which may not fill
            // the buffer if the socket would block.
            if (underflow() != traits::eof())
            {
                // We got some data
                // So we will copy what we need from the buffer into the destination.
                nextChunkSize    = std::min(nextChunkSize, egptr() - gptr());
                std::copy(gptr(), gptr() + nextChunkSize, dest + retrieved);
                gbump(nextChunkSize);
                retrieved += nextChunkSize;

                if (retrieved != count)
                {
                    // OK so the underflow() did not read enough
                    // So the stream would block so we are going to call the blocking
                    // version until we get enough data.
                    IOData result = socket.getMessageData(dest + retrieved, count - retrieved);
                    inCount += result.dataSize;
                    retrieved += result.dataSize;
                }
            }
        }
    }
    return retrieved;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SocketStreamBuffer::int_type SocketStreamBuffer::overflow(int_type ch)
{
    /*
     * Ensures that there is space at the put area for at least one character by saving some initial subsequence of
     * characters starting at pbase() to the output sequence and updating the pointers to the put area (if needed).
     *
     * If ch is not Traits::eof() (i.e. Traits::eq_int_type(ch, Traits::eof()) != true),
     * it is either put to the put area or directly saved to the output sequence.
     *
     * The function may update pptr, epptr and pbase pointers to define the location to write more data.
     * On failure, the function ensures that either pptr() == nullptr or pptr() == epptr.
     * The base class version of the function does nothing. The derived classes may override this function to allow
     * updates to the put area in the case of exhaustion.
     */

    if (ch != traits::eof())
    {
        /* Note: When we set the "put" pointers we deliberately leave an extra space that is not buffer.
         * see: sync()
         *
         * When overflow is called the normal buffer is used up, but there is an extra space in the real
         * underlying buffer that we can use.
         *
         * So: *pptr = ch; // will never fail.
         */
        *pptr() = ch;
        pbump(1);
    }

    if (sync() != 0)
    {
        // Failed to write data out.
        // Indicate error by setting buffer appropriately
        setp(&outputBuffer[0], &outputBuffer[0]);
    }
    return int_type(ch);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
std::streamsize SocketStreamBuffer::xsputn(char_type const* source, std::streamsize count)
{
    /*
     * Writes count characters to the output sequence from the character array whose first element is pointed to by source.
     *
     * The characters are written as if by repeated calls to sputc().
     * Writing stops when either count characters are written or a call to sputc() would have returned Traits::eof().
     *
     * If the put area becomes full (pptr() == epptr()), this function may call overflow(),
     * or achieve the effect of calling overflow() by some other, unspecified, means.
     */
    std::streamsize spaceInBuffer = epptr() - pptr();
    if (spaceInBuffer > count)
    {
        // If we have space in the internal buffer then just place it there.
        // We want a lot of little writtes to be buffered so we only talk to the stream
        // chunks of a resonable size.
        //std::copy_n(source, count, pptr());
        std::copy(source, source + count, pptr());
        pbump(count);
        return count;
    }

    // Not enough room in the internal buffer.
    // So write everything to the output stream.
    overflow();

    IOData result = socket.putMessageData(source, count);
    outCount += result.dataSize;

    return result.dataSize;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int SocketStreamBuffer::sync()
{
    std::size_t outputSize = pptr() - pbase();

    IOData result = socket.putMessageData(pbase(), pptr() - pbase());
    outCount += result.dataSize;

    setp(&outputBuffer[0], &outputBuffer[outputBuffer.size() - 1]);
    return result.dataSize == outputSize
              ? 0     // Success. Amount written equals buffer.
              : -1;   // Failure
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
std::streampos SocketStreamBuffer::seekoff(std::streamoff off, std::ios_base::seekdir way, std::ios_base::openmode which)
{
    if (way != std::ios_base::cur)
    {
        return -1;
    }
    if (off != 0)
    {
        return -1;
    }
    return (which == std::ios_base::out)
                ? outCount + (pptr() - pbase())
                : inCount  + (gptr() - eback());
}
