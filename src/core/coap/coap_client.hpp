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
#include <net/udp6.hpp>

/**
 * @file
 *   This file includes definitions for the CoAP client.
 */

namespace Thread {
namespace Coap {

class Client;

OT_TOOL_PACKED_BEGIN
class RequestData
{
    friend class Client;

public:

    /**
     * This function pointer is called when a CoAP response is received or request timed-out.
     *
     * @param[in]  aContext      A pointer to arbitrary context information.
     * @param[in]  aHeader       A pointer to the CoAP header.
     * @param[in]  aMessage      A pointer to the message.
     * @param[in]  ThreadResult  A result of the CoAP transmission. kThreadError_None if the response
     *                           was received successfully, otherwise an error code is passed.
     *
     */
    typedef void (*CoapResponseHandler)(void *aContext, Header *aHeader, Message *aMessage,
                                        ThreadError result);

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
    RequestData(const Ip6::MessageInfo &aMessageInfo, CoapResponseHandler aHandler, void *aContext);

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

    /**
     * This method updates request data in the message.
     *
     * @param[in]  aMessage  A reference to the message.
     *
     * @returns The number of bytes updated.
     *
     */
    int UpdateIn(Message &aMessage) {
        return aMessage.Write(aMessage.GetLength() - sizeof(*this), sizeof(*this), this);
    }

    /**
     * This method checks if the message shall be sent before the given time.
     *
     * @param[in]  aTime  A time to compare.
     *
     * @retval TRUE   If the message shall be sent before the given time.
     * @retval FALSE  Otherwise.
     */
    bool IsEarlier(uint32_t aTime) { return (static_cast<int32_t>(aTime - mSendTime) > 0); };

    /**
     * This method checks if the message shall be sent after the given time.
     *
     * @param[in]  aTime  A time to compare.
     *
     * @retval TRUE   If the message shall be sent after the given time.
     * @retval FALSE  Otherwise.
     */
    bool IsLater(uint32_t aTime) { return (static_cast<int32_t>(aTime - mSendTime) < 0); };

private:
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

    Ip6::Address        mDestinationAddress;    ///< IPv6 address of the message destination.
    uint16_t            mDestinationPort;       ///< UDP port of the message destination.
    CoapResponseHandler mResponseHandler;       ///< A function pointer that is called on response reception.
    void                *mResponseContext;      ///< A pointer to arbitrary context information.
    uint32_t            mSendTime;              ///< Time when the next retransmission shall be sent.
    uint32_t            mRetransmissionTimeout; ///< Delay that is applied to next retransmission.
    uint8_t             mRetransmissionCount;   ///< Number of retransmissions.
    bool                mAcknowledged: 1;       ///< Information that request was acknowledged.
} OT_TOOL_PACKED_END;

class Client
{
    friend class RequestData;

public:

    /**
     * This constructor initializes the object.
     *
     * @param[in]  aNetif  A reference to the network interface that CoAP client should be assigned to.
     *
     */
    Client(Ip6::Netif &aNetif);

    /**
     * This method starts the CoAP client.
     *
     * @retval kThreadError_None  Successfully started the CoAP client.
     *
     */
    ThreadError Start(void);

    /**
     * This method stops the CoAP client.
     *
     * @retval kThreadError_None  Successfully stopped the CoAP client.
     *
     */
    ThreadError Stop(void);

    /**
     * This method creates a new message with a CoAP header.
     *
     * @param[in]  aHeader  A reference to a CoAP header that is used to create the message.
     *
     * @returns A pointer to the message or NULL if failed to allocate message.
     *
     */
    Message *NewMessage(const Header &aHeader);

    /**
     * This method sends a CoAP message.
     *
     * If a response for a request is expected, respective function and contex information should be provided.
     * If no response is expected, these arguments should be NULL pointers.
     *
     * @param[in]  aMessage      A reference to the message to send.
     * @param[in]  aMessageInfo  A reference to the message info associated with @p aMessage.
     * @param[in]  aHandler      A function pointer that shall be called on response reception or time-out.
     * @param[in]  aContext      A pointer to arbitrary context information.
     *
     * @retval kThreadError_None   Successfully sent CoAP message.
     * @retval kThreadError_NoBufs Failed to allocate retransmission data.
     *
     */
    ThreadError SendMessage(Message &aMessage, const Ip6::MessageInfo &aMessageInfo,
                            RequestData::CoapResponseHandler aHandler, void *aContext);

    /**
     * This method returns unique Message Id that can be used in a CoAP header.
     *
     * @returns  Message Id.
     *
     */
    uint16_t GetNextMessageId(void) { return mMessageId++; };

private:
    ThreadError AddConfirmableMessage(Message &aMessage, RequestData &aRequestData);

    void RemoveMessage(Message &aMessage);

    ThreadError SendCopy(const Message &aMessage, const Ip6::MessageInfo &aMessageInfo);
    void SendEmptyMessage(const Ip6::Address &aAddress, uint16_t aPort, uint16_t aMessageId, Header::Type aType);
    void SendReset(const Ip6::Address &aAddress, uint16_t aPort, uint16_t aMessageId) {
        SendEmptyMessage(aAddress, aPort, aMessageId, Header::kTypeReset);
    };
    void SendEmptyAck(const Ip6::Address &aAddress, uint16_t aPort, uint16_t aMessageId) {
        SendEmptyMessage(aAddress, aPort, aMessageId, Header::kTypeAcknowledgment);
    };

    static void HandleRetransmissionTimer(void *aContext);
    void HandleRetransmissionTimer(void);

    static void HandleUdpReceive(void *aContext, otMessage aMessage, const otMessageInfo *aMessageInfo);
    void HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo);

    Ip6::UdpSocket mSocket;
    MessageQueue mPendingRequests;
    uint16_t mMessageId;
    Timer mRetransmissionTimer;
};

}  // namespace Coap
}  // namespace Thread

#endif  // COAP_CLIENT_HPP_
