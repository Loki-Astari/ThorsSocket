#ifndef THORSANVIL_TEST_CONNECTION_FILE_DESCRIPTOR_H
#define THORSANVIL_TEST_CONNECTION_FILE_DESCRIPTOR_H

#include <vector>
#include <string>

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

struct Action
{
    std::string                 action;
    std::vector<std::string>    expectedInit;
    std::vector<std::string>    expectedCode;
    std::vector<std::string>    expectedDest;
    std::vector<std::string>    optional;
};

class MockConnectionFileDescriptor
{
    MOCK_MEMBER(read);
    MOCK_MEMBER(write);

    enum State {Construct, Code, Destruct};

    State                   state;
    bool                    exceptionHappened;
    int                     nextExpected;
    int                     nextInSequence;
    std::vector<Action>     expected;

    public:
        MockConnectionFileDescriptor()
            : state(Construct)
            , exceptionHappened(false)
            , nextExpected(0)
            , nextInSequence(0)
            , MOCK_PARAM(read,            [&](int, void*, ssize_t size)             {checkExpected("read");return size;})
            , MOCK_PARAM(write,           [&](int, void const*, ssize_t size)       {checkExpected("write");return size;})
        {}
        ~MockConnectionFileDescriptor()
        {
            // No expected state.
            if (expected.size() == 0) {
                return;
            }
            // Threw in constructor of first set of expected actions.
            // So no destructors or other code would be run.
            if (exceptionHappened && state == Construct && nextExpected == 0) {
                return;
            }
            // Otherwise we expect some wind down.
            EXPECT_EQ(state, Destruct);
            bool okEndPosition = nextExpected == -1 || (nextExpected == 0 && nextInSequence == expected[0].expectedDest.size());
            EXPECT_TRUE(okEndPosition);
        }

        void checkExpected(std::string const& called)
        {
            if (expected.size() == 0) {
                return;
            }
            switch (state)
            {
                case Construct:
                case Code:      CheckExpectedConstruct(called);break;
                case Destruct:  CheckExpectedDestruct(called);break;
            }
        }
        bool peekDestructor(std::string const& called)
        {
            int nextDestruct = nextExpected;
            if (state == Construct) {
                --nextDestruct;
            }
            while (nextDestruct >= 0 && expected[nextDestruct].expectedDest.size() == 0) {
                --nextDestruct;
            }
            if (nextDestruct > 0 && expected[nextDestruct].expectedDest[0] == called) {
                return true;
            }
            return false;
        }
        void CheckExpectedConstruct(std::string const& called)
        {
            //std::cerr << "CheckExpectedConstruct: " << called << "\n";
            while (nextExpected < expected.size())
            {
                auto& optional  = expected[nextExpected].optional;
                auto& init      = (state == Construct) ? expected[nextExpected].expectedInit : expected[nextExpected].expectedCode;

                if (nextInSequence < init.size() && init[nextInSequence] == called) {
                    ++nextInSequence;
                    return;
                }

                auto find = std::find(std::begin(optional), std::end(optional), called);
                if (find != optional.end()) {
                    return;
                }
                if (peekDestructor(called))
                {
                    if (state == Construct) {
                        --nextExpected;
                    }
                    state = Destruct;
                    nextInSequence = 0;
                    CheckExpectedDestruct(called);
                    return;
                }
                if (nextInSequence != init.size())
                {
                    std::cerr << "Unexpected: " << called << " Expected: " << expected[nextExpected].action << ": " << expected[nextExpected].expectedInit[nextInSequence] << "\n";
                    EXPECT_EQ(called, expected[nextExpected].expectedInit[nextInSequence]);
                    return;
                }
                nextInSequence  = 0;
                if (state == Construct) {
                    state = Code;
                }
                else {
                    state = Construct;
                    ++nextExpected;
                }
            }
            state = Destruct;
            --nextExpected;
            CheckExpectedDestruct(called);
        }
        void CheckExpectedDestruct(std::string const& called)
        {
            //std::cerr << "CheckExpectedDestruct: " << called << "\n";
            while (nextExpected >= 0)
            {
                auto& dest =  expected[nextExpected].expectedDest;

                if (nextInSequence < dest.size()  && dest[nextInSequence] == called)
                {
                    ++nextInSequence;
                    return;
                }
                if (nextInSequence != dest.size())
                {
                    std::cerr << "Unexpected: " << called << " Expected: " << expected[nextExpected].action << ": " << expected[nextExpected].expectedDest[nextInSequence] << "\n";
                    EXPECT_EQ(called, expected[nextExpected].expectedDest[nextInSequence]);
                    return;
                }
                --nextExpected;
                nextInSequence = 0;
            }
            std::cerr << "Unexpected: " << called << "\n";
            EXPECT_TRUE(false);
        }
        void setAction(std::string const& action, std::initializer_list<std::string> init, std::initializer_list<std::string> code, std::initializer_list<std::string> dest, std::initializer_list<std::string> optional)
        {
            expected.emplace_back(Action{action, init, code, dest, optional});
        }
        void noteException()
        {
            exceptionHappened = true;
        }
};
class MockActionThrowDetext
{
    MockConnectionFileDescriptor& parent;
    public:
        MockActionThrowDetext(MockConnectionFileDescriptor& parent)
            : parent(parent)
        {}
        ~MockActionThrowDetext()
        {
            if (std::uncaught_exceptions() != 0) {
                parent.noteException();
            }
        }
};

#endif
