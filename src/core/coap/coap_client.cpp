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

#include <string.h>
#include <assert.h>

#include <coap/coap_client.hpp>
#include <common/code_utils.hpp>
#include <net/ip6.hpp>
#include <platform/random.h>

/**
 * @file
 *   This file implements the CoAP client.
 */

namespace Thread {
namespace Coap {

Client::Client(Ip6::Netif &aNetif):
    mSocket(aNetif.GetIp6().mUdp),
    mRetransmissionTimer(aNetif.GetIp6().mTimerScheduler, &Client::HandleRetransmissionTimer, this)
{
    mMessageId = static_cast<uint16_t>(otPlatRandomGet());

    mSocket.Open(&Client::HandleUdpReceive, this);
}

Message *Client::NewMessage(const Header &aHeader)
{
    Message *message = NULL;

    // Assure that header has minimum required length and is terminated.
    VerifyOrExit(aHeader.GetLength() >= Header::kMinHeaderLength, ;);
    VerifyOrExit(aHeader.GetBytes()[aHeader.GetLength() - 1] == 0xff, ;);

    VerifyOrExit((message = mSocket.NewMessage(aHeader.GetLength())) != NULL, ;);
    message->Prepend(aHeader.GetBytes(), aHeader.GetLength());
    message->SetOffset(0);

exit:
    return message;
}

ThreadError Client::SendMessage(Message &aMessage, const Ip6::MessageInfo &aMessageInfo, CoapResponseHandler aHandler, void *aContext)
{
    ThreadError error;
    Message *messageCopy = NULL;

    // TODO Setup the timer and adjust retransmission parameters.

    // Append request related data to the message buffer.
    RequestData request(aMessageInfo, aHandler, aContext);
    SuccessOrExit(error = request.AppendTo(aMessage));

    // Create a message copy for lower layers.
    VerifyOrExit((messageCopy = mSocket.NewMessage(0)) != NULL, error = kThreadError_NoBufs);
    SuccessOrExit(messageCopy->SetLength(aMessage.GetLength() - sizeof(RequestData)));
    aMessage.CopyTo(0, 0, aMessage.GetLength() - sizeof(RequestData), *messageCopy);

    // Send the copy.
    SuccessOrExit(error = mSocket.SendTo(*messageCopy, aMessageInfo));

    // Enqueue the original message to handle retransmission/response.
    mPendingRequests.Enqueue(aMessage);

exit:

    if (error != kThreadError_None && messageCopy != NULL)
    {
        messageCopy->Free();
    }

    return error;
}

void Client::SendEmptyMessage(const Ip6::Address &aAddress, uint16_t aPort, uint16_t aMessageId, Header::Type aType)
{
    Header header;
    Ip6::MessageInfo messageInfo;
    Message *message;
    ThreadError error = kThreadError_None;

    header.Init();
    header.SetType(aType);
    header.SetMessageId(aMessageId);
    header.Finalize();

    VerifyOrExit((message = NewMessage(header)) != NULL, ;);

    memset(&messageInfo, 0, sizeof(messageInfo));
    messageInfo.GetPeerAddr()= aAddress;
    messageInfo.mPeerPort = aPort;

    SuccessOrExit(error = mSocket.SendTo(*message, messageInfo));

exit:
    if (error != kThreadError_None && message != NULL)
    {
        message->Free();
    }
}

void Client::SendReset(const Ip6::Address &aAddress, uint16_t aPort, uint16_t aMessageId)
{
    SendEmptyMessage(aAddress, aPort, aMessageId, Header::kTypeReset);
}

void Client::SendEmptyAck(const Ip6::Address &aAddress, uint16_t aPort, uint16_t aMessageId)
{
    SendEmptyMessage(aAddress, aPort, aMessageId, Header::kTypeAcknowledgment);
}

void Client::HandleRetransmissionTimer(void *aContext)
{
    static_cast<Client *>(aContext)->HandleRetransmissionTimer();
}

void Client::HandleRetransmissionTimer(void)
{

}

void Client::HandleUdpReceive(void *aContext, otMessage aMessage, const otMessageInfo *aMessageInfo)
{
    static_cast<Client *>(aContext)->HandleUdpReceive(*static_cast<Message *>(aMessage),
                                                      *static_cast<const Ip6::MessageInfo *>(aMessageInfo));
}

void Client::HandleUdpReceive(Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    (void)aMessageInfo;

    Header responseHeader;
    Header requestHeader;
    RequestData requestData;
    Message *message = mPendingRequests.GetHead();
    bool rejectMessage = true;
    ThreadError error;

    SuccessOrExit(error = responseHeader.FromMessage(aMessage));
    aMessage.MoveOffset(responseHeader.GetLength());

    while (message != NULL)
    {
        requestData.ReadFrom(*message);

        if ((requestData.mDestinationAddress == aMessageInfo.GetPeerAddr()) &&
            (requestData.mDestinationPort == aMessageInfo.mPeerPort))
        {
            if (requestHeader.FromMessage(*message) != kThreadError_None)
            {
                // Someone stored damaged message, delete it.
                Message *messageToRemove = message;
                message = message->GetNext();

                mPendingRequests.Dequeue(*messageToRemove);
                messageToRemove->Free();

                continue;
            }

            switch (responseHeader.GetType())
            {
            case Header::kTypeReset:
                if (responseHeader.GetMessageId() != requestHeader.GetMessageId())
                {
                    break;
                }

                if (responseHeader.IsEmpty())
                {
                    rejectMessage = false;
                    mPendingRequests.Dequeue(*message);
                    message->Free();

                    requestData.mResponseHandler(requestData.mResponseContext, responseHeader,
                                                 aMessage, kThreadError_Abort);
                }

                // Silently ignore non-empty reset messages (RFC 7252, p. 4.2).
                ExitNow();

            case Header::kTypeAcknowledgment:
                if (responseHeader.GetMessageId() != requestHeader.GetMessageId())
                {
                    break;
                }

                if (responseHeader.IsEmpty())
                {
                    // Empty acknowledgment, await non-piggybacked response.
                    rejectMessage = false;
                    requestData.mAcknowledged = true;
                    requestData.UpdateIn(*message);
                    // TODO HANDLE EMPTY ACK.
                }
                else if (responseHeader.IsResponse() && responseHeader.IsTokenEqual(requestHeader))
                {
                    // Piggybacked response.
                    rejectMessage = false;
                    mPendingRequests.Dequeue(*message);
                    message->Free();

                    requestData.mResponseHandler(requestData.mResponseContext, responseHeader,
                                                 aMessage, kThreadError_None);
                }

                // Silently ignore acknowledgments carrying requests (RFC 7252, p. 4.2)
                // or with no token match (RFC 7252, p. 5.3.2)
                ExitNow();

            case Header::kTypeConfirmable:
            case Header::kTypeNonConfirmable:
                if (!responseHeader.IsTokenEqual(requestHeader))
                {
                    break;
                }

                // Piggybacked response.
                if (responseHeader.GetType() == Header::kTypeConfirmable)
                {
                    // Send ack if it is a CON message.
                    SendEmptyAck(aMessageInfo.GetPeerAddr(), aMessageInfo.mPeerPort, responseHeader.GetMessageId());
                }

                rejectMessage = false;
                mPendingRequests.Dequeue(*message);
                message->Free();

                requestData.mResponseHandler(requestData.mResponseContext, responseHeader,
                                             aMessage, kThreadError_None);

                ExitNow();
            }
        }

        message = message->GetNext();
    }

exit:
    if (error == kThreadError_None && rejectMessage)
    {
        if (responseHeader.GetType() == Header::kTypeConfirmable ||
            responseHeader.GetType() == Header::kTypeNonConfirmable)
        {
            SendReset(aMessageInfo.GetPeerAddr(), aMessageInfo.mPeerPort, responseHeader.GetMessageId());
        }
    }
}

}  // namespace Coap
}  // namespace Thread
