/*
 *  Copyright (c) 2016, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef COAP_CLIENT_HPP_
#define COAP_CLIENT_HPP_

#include <openthread-types.h>
#include <coap/coap_header.hpp>
#include <common/message.hpp>
#include <common/timer.hpp>
#include <net/netif.hpp>

/**
 * @file
 *   This file includes definitions for the CoAP client.
 */

namespace Thread {
namespace Coap {

class Client
{
    friend class RequestData;

public:

    typedef void (*CoapResponseHandler)(void *aContext, Header &aHeader, Message &aMessage,
                                        ThreadError result);

    Client(Ip6::Netif &aNetif);

    Message *NewMessage(const Header &mHeader);

    ThreadError SendMessage(Message &aMessage, const Ip6::MessageInfo &aMessageInfo, CoapResponseHandler aHandler, void *aContext);

    uint16_t GetNextMessageId(void) { return mMessageId++; };


private:
    void SendEmptyMessage(const Ip6::Address &aAddress, uint16_t aPort, uint16_t aMessageId, Header::Type aType);
    void SendReset(const Ip6::Address &aAddress, uint16_t aPort, uint16_t aMessageId);
    void SendEmptyAck(const Ip6::Address &aAddress, uint16_t aPort, uint16_t aMessageId);

    static void HandleRetransmissionTimer(void *aContext);
    void HandleRetransmissionTimer(void);

    static void HandleUdpReceive(void *aContext, otMessage aMessage, const otMessageInfo *aMessageInfo);
    void HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo);

    /**
     * Protocol Constants (RFC 7252).
     *
     */
    enum
    {
        // TODO Parametrize these values.
        kAckTimeout         = 2,
        kAckRandomFactor    = 1,
        kMaxRetransmit      = 2,
        kNStart             = 1,
        kDefaultLeisure     = 5,
        kProbingRate        = 1,

        // Note that 2 << (kMaxRetransmit - 1) is equal to kMaxRetransmit power of 2
        kMaxTransmitSpan    = kAckTimeout * ((2 << (kMaxRetransmit - 1)) - 1) * kAckRandomFactor,
        kMaxTransmitWait    = kAckTimeout * ((2 << kMaxRetransmit) - 1) * kAckRandomFactor,
        kMaxLatency         = 100,
        kProcessingDelay    = kAckTimeout,
        kMaxRtt             = 2 * kMaxLatency + kAckTimeout,
        kExchangeLifetime   = kMaxTransmitSpan + 2 * (kMaxLatency) + kProcessingDelay,
        kNonLifetime        = kMaxTransmitSpan + kMaxLatency
    };

    Ip6::UdpSocket mSocket;
    MessageQueue mPendingRequests;
    uint16_t mMessageId;
    Timer mRetransmissionTimer;
};

OT_TOOL_PACKED_BEGIN
class RequestData
{
    friend class Client;

public:
    /**
     * Default constructor for the object.
     *
     */
    RequestData(void) { memset(this, 0, sizeof(*this)); };

    /**
     * This constructor initializes the object with specific values.
     *
     * @param[in]  aMessageInfo  Addressing information.
     * @param[in]  aHandler      Pointer to a handler function for the response.
     * @param[in]  aContext      Context for the handler function.
     *
     */
    RequestData(const Ip6::MessageInfo &aMessageInfo, Client::CoapResponseHandler aHandler, void *aContext) {
        mDestinationPort = aMessageInfo.mPeerPort;
        mDestinationAddress = aMessageInfo.GetPeerAddr();
        mResponseHandler = aHandler;
        mResponseContext = aContext;
        mRetransmissionCount = 0;
        mRetransmissionTime = Timer::GetNow() + (Timer::SecToMsec(Client::kAckTimeout) * Client::kAckRandomFactor);
        mAcknowledged = false;
    };

    /**
     * This method appends request data to the message.
     *
     * @param[in]  aMessage  A reference to the message.
     *
     * @retval kThreadError_None    Successfully appended the bytes.
     * @retval kThreadError_NoBufs  Insufficient available buffers to grow the message.
     *
     */
    ThreadError AppendTo(Message &aMessage) {
        return aMessage.Append(this, sizeof(*this));
    };

    /**
     * This method reads request data from the message.
     *
     * @param[in]  aMessage  A reference to the message.
     *
     * @returns The number of bytes read.
     *
     */
    uint16_t ReadFrom(const Message &aMessage) {
        return aMessage.Read(aMessage.GetLength() - sizeof(*this), sizeof(*this), this);
    };

    // TODO doc
    int UpdateIn(Message &aMessage) {
        return aMessage.Write(aMessage.GetLength() - sizeof(*this), sizeof(*this), this);
    }

private:
    Ip6::Address                mDestinationAddress;  ///< IPv6 address of the message destination.
    uint16_t                    mDestinationPort;     ///< UDP port of the message destination.
    Client::CoapResponseHandler mResponseHandler;
    void                        *mResponseContext;
    uint32_t                    mRetransmissionTime;  ///< Time when the next retransmission shall be sent.
    uint8_t                     mRetransmissionCount;
    bool                        mAcknowledged: 1;
} OT_TOOL_PACKED_END;

}  // namespace Coap
}  // namespace Thread

#endif  // COAP_CLIENT_HPP_
