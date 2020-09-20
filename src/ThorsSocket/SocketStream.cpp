#include "SocketStream.h"
#include "ThorsLogging/ThorsLogging.h"
#include <iostream>

using namespace ThorsAnvil::ThorsIO;

SocketStreamBuffer::SocketStreamBuffer(DataSocket& stream,
                                       Notifier noAvailableData, Notifier flushing,
                                       std::vector<char>&& bufData, char const* currentStart, char const* currentEnd)
    : stream(stream)
    , noAvailableData(noAvailableData)
    , flushing(flushing)
    , inBuffer(std::move(bufData))
    , outBuffer(4000)
    , inCount(0)
    , outCount(0)
{
    char* newStart = const_cast<char*>(currentStart);
    char* newEnd   = const_cast<char*>(currentEnd);
    if (newStart == nullptr || newEnd == nullptr)
    {
        newStart = &inBuffer[0];
        newEnd   = &inBuffer[0];
    }

    setg(&inBuffer[0], newStart, newEnd);
    setp(&outBuffer[0], &outBuffer[outBuffer.size() - 1]);
}

SocketStreamBuffer::SocketStreamBuffer(SocketStreamBuffer&& move) noexcept
    : stream(move.stream)
    , noAvailableData(std::move(move.noAvailableData))
    , flushing(std::move(move.flushing))
    , inBuffer(std::move(move.inBuffer))
    , outBuffer(std::move(move.outBuffer))
    , inCount(move.inCount)
    , outCount(move.outCount)
{
    move.setg(nullptr, nullptr, nullptr);
    move.setp(nullptr, nullptr);
}

SocketStreamBuffer::~SocketStreamBuffer()
{
    // Force the buffer to be output to the socket
    try
    {
        overflow();
    }
    // Catch and drop any exceptions.
    // Logging so we know what happened.
    catch (std::exception const& e)
    {
        VLOG_S(5) << "SocketStreamBuffer::~SocketStreamBuffer(). Exception: " << e.what();
    }
    catch (...)
    {
        VLOG_S(5) << "SocketStreamBuffer::~SocketStreamBuffer(). Exception: UNKNOWN.";
    }
}

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
    std::streamsize retrievedData = readFromStream(&inBuffer[0], inBuffer.size(), false);
    return (retrievedData == 0) ? traits::eof() : traits::to_int_type(*gptr());
}

std::streamsize SocketStreamBuffer::xsgetn(char_type* dest, std::streamsize count)
{
    /*
     * Reads count characters from the input sequence and stores them into a character array pointed to by s.
     * The characters are read as if by repeated calls to sbumpc().
     * That is, if less than count characters are immediately available, the function calls uflow() to
     * provide more until traits::eof() is returned. Classes derived from std::basic_streambuf are permitted
     * to provide more efficient implementations of this function.
     */


    std::streamsize currentBufferSize = egptr() - gptr();
    std::streamsize nextChunkSize    = std::min(count, currentBufferSize);
    //std::copy_n(gptr(), nextChunkSize, dest);
    std::copy(gptr(), gptr() + nextChunkSize, dest);
    gbump(nextChunkSize);

    std::streamsize       retrieved  = nextChunkSize;
    std::streamsize const bufferSize = static_cast<std::streamsize>(inBuffer.size());

    while (retrieved != count)
    {
        nextChunkSize    = std::min((count - retrieved), bufferSize);

        // A significant chunk
        if (nextChunkSize > (bufferSize / 2))
        {
            std::streamsize read = readFromStream(dest + retrieved, count - retrieved);
            if (read == 0)
            {
                break;
            }
            retrieved += read;
        }
        else
        {
            if (underflow() == traits::eof())
            {
                break;
            }
            nextChunkSize    = std::min(nextChunkSize, egptr() - gptr());
            // std::copy_n(gptr(), nextChunkSize, dest + retrieved);
            std::copy(gptr(), gptr() + nextChunkSize, dest + retrieved);
            gbump(nextChunkSize);
            retrieved += nextChunkSize;
        }
    }
    return retrieved;
}

SocketStreamBuffer::int_type SocketStreamBuffer::overflow(int_type ch)
{
    /*
     * Ensures that there is space at the put area for at least one character by saving some initial subsequence of
     * characters starting at pbase() to the output sequence and updating the pointers to the put area (if needed).
     * If ch is not Traits::eof() (i.e. Traits::eq_int_type(ch, Traits::eof()) != true),
     *     it is either put to the put area or directly saved to the output sequence.
     * The function may update pptr, epptr and pbase pointers to define the location to write more data.
     * On failure, the function ensures that either pptr() == nullptr or pptr() == epptr.
     * The base class version of the function does nothing. The derived classes may override this function to allow
     * updates to the put area in the case of exhaustion.
     */

    if (ch != traits::eof())
    {
        /* Note: When we set the "put" pointers we deliberately leave an extra space that is not buffer.
         * When overflow is called the normal buffer is used up, but there is an extra space in the real
         * underlying buffer that we can use.
         *
         * So: *pptr = ch; // will never fail.
         */
        *pptr() = ch;
        pbump(1);
    }

    flushing();
    if (sync() != 0)
    {
        // Failed to write data out.
        // Indicate error by setting buffer appropriately
        setp(&outBuffer[0], &outBuffer[0]);
    }
    return int_type(ch);
}

std::streamsize SocketStreamBuffer::xsputn(char_type const* source, std::streamsize count)
{
    /*
     * Writes count characters to the output sequence from the character array whose first element is pointed to by s.
     * The characters are written as if by repeated calls to sputc().
     * Writing stops when either count characters are written or a call to sputc() would have returned Traits::eof().
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

    std::streamsize       exported   = 0;
    std::streamsize const bufferSize = static_cast<std::streamsize>(outBuffer.size());
    while (exported != count)
    {
        std::streamsize nextChunk = count - exported;
        if (nextChunk > (bufferSize / 2))
        {
            std::streamsize written = writeToStream(source + exported, nextChunk);
            exported += written;
        }
        else
        {
            //std::copy_n(source + exported, nextChunk, pptr());
            std::copy(source + exported, source + exported + nextChunk, pptr());
            pbump(nextChunk);
            exported += nextChunk;
        }
    }
    return exported;
}

int SocketStreamBuffer::sync()
{
    std::streamsize written = writeToStream(pbase(), pptr() - pbase());
    int result = (written == (pptr() - pbase()))
                        ? 0     // Success. Amount written equals buffer.
                        : -1;   // Failure
    setp(&outBuffer[0], &outBuffer[outBuffer.size() - 1]);
    return result;
}

std::streamsize SocketStreamBuffer::writeToStream(char_type const* source, std::streamsize count)
{
    std::streamsize written = 0;
    while (written != count)
    {
        bool        moreSpace;
        std::size_t dataWritten;
        std::tie(moreSpace, dataWritten) = stream.putMessageData(source, count, written);
        if (dataWritten != 0)
        {
            written += dataWritten;
        }
        else if (moreSpace)
        {
            noAvailableData();
        }
        else
        {
            break;
        }
    }
    outCount += written;
    return written;
}

std::streamsize SocketStreamBuffer::readFromStream(char_type* dest, std::streamsize count, bool fill)
{
    std::size_t used = (egptr() - &inBuffer[0]);
    inCount += used;

    std::streamsize read = 0;
    while (read != count)
    {
        bool    moreData;
        size_t  dataRead;
        std::tie(moreData, dataRead) = stream.getMessageData(dest, count, read);
        if (dataRead != 0)
        {
            read += dataRead;
            if (!fill)
            {
                break;
            }
        }
        else if (moreData)
        {
            noAvailableData();
        }
        else
        {
            break;
        }
    }
    setg(&inBuffer[0], &inBuffer[0], &inBuffer[read]);
    return read;
}
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
// ------------------------

IOSocketStream::IOSocketStream(DataSocket& stream)
    : std::istream(nullptr)
    , buffer(stream, noActionNotifier, noActionNotifier)
{
    std::istream::rdbuf(&buffer);
}

IOSocketStream::IOSocketStream(DataSocket& stream,
                             Notifier noAvailableData, Notifier flushing)
    : std::istream(nullptr)
    , buffer(stream, noAvailableData, flushing)
{
    std::istream::rdbuf(&buffer);
}

IOSocketStream::IOSocketStream(DataSocket& stream,
                             Notifier noAvailableData, Notifier flushing,
                             std::vector<char>&& bufData, char const* currentStart, char const* currentEnd)
    : std::istream(nullptr)
    , buffer(stream,
             noAvailableData, flushing,
             std::move(bufData), currentStart, currentEnd)
{
    rdbuf(&buffer);
}

IOSocketStream::IOSocketStream(IOSocketStream&& move) noexcept
    : std::istream(nullptr)
    , buffer(std::move(move.buffer))
{
    rdbuf(&buffer);
}
