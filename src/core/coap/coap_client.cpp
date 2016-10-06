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
}

ThreadError Client::Start()
{
    return mSocket.Open(&Client::HandleUdpReceive, this);
}

ThreadError Client::Stop()
{
    Message *message = mPendingRequests.GetHead();
    Message *messageToRemove;

    // Remove all pending messages.
    while (message != NULL)
    {
        messageToRemove = message;
        message = message->GetNext();

        RemoveMessage(*messageToRemove);
        messageToRemove->Free();
    }

    return mSocket.Close();
}

Message *Client::NewMessage(const Header &aHeader)
{
    Message *message = NULL;

    // Assure that header has minimum required length.
    VerifyOrExit(aHeader.GetLength() >= Header::kMinHeaderLength, ;);

    VerifyOrExit((message = mSocket.NewMessage(aHeader.GetLength())) != NULL, ;);
    message->Prepend(aHeader.GetBytes(), aHeader.GetLength());
    message->SetOffset(0);

exit:
    return message;
}

ThreadError Client::SendMessage(Message &aMessage, const Ip6::MessageInfo &aMessageInfo,
                                RequestData::CoapResponseHandler aHandler, void *aContext)
{
    ThreadError error;
    Header header;
    RequestData request;

    SuccessOrExit(error = header.FromMessage(aMessage));

    // TODO support for responses for NON
    if (header.IsConfirmable())
    {
        // Create request related data, enqueue the message and send a copy.
        request = RequestData(aMessageInfo, aHandler, aContext);
        SuccessOrExit(error = AddConfirmableMessage(aMessage, request));
        SuccessOrExit(error = SendCopy(aMessage, aMessageInfo));
    }
    else
    {
        // Send the original message.
        SuccessOrExit(error = mSocket.SendTo(aMessage, aMessageInfo));
    }

exit:

    if (error != kThreadError_None)
    {
        mPendingRequests.Dequeue(aMessage);
    }

    return error;
}

ThreadError Client::AddConfirmableMessage(Message &aMessage, RequestData &aRequestData)
{
    ThreadError error;
    uint32_t alarmFireTime;

    SuccessOrExit(error = aRequestData.AppendTo(aMessage));

    if (mRetransmissionTimer.IsRunning())
    {
        // If timer is already running, check if it should be restarted with earlier fire time.
        alarmFireTime = mRetransmissionTimer.Gett0() + mRetransmissionTimer.Getdt();

        if (aRequestData.IsEarlier(alarmFireTime))
        {
            mRetransmissionTimer.Start(aRequestData.mRetransmissionTimeout);
        }
    }
    else
    {
        mRetransmissionTimer.Start(aRequestData.mRetransmissionTimeout);
    }

    mPendingRequests.Enqueue(aMessage);

exit:
    return error;
}

void Client::RemoveMessage(Message &aMessage)
{
    mPendingRequests.Dequeue(aMessage);

    if (mRetransmissionTimer.IsRunning() && (mPendingRequests.GetHead() == NULL))
    {
        // No more requests pending, stop the timer.
        mRetransmissionTimer.Stop();
    }

    // No need to worry that the earliest pending message was removed -
    // the timer would just shoot earlier and then it'd be setup again.
}

ThreadError Client::SendCopy(const Message &aMessage, const Ip6::MessageInfo &aMessageInfo)
{
    ThreadError error;
    Message *messageCopy = NULL;

    // Create a message copy for lower layers.
    VerifyOrExit((messageCopy = mSocket.NewMessage(0)) != NULL, error = kThreadError_NoBufs);
    SuccessOrExit(error = messageCopy->SetLength(aMessage.GetLength() - sizeof(RequestData)));
    aMessage.CopyTo(0, 0, aMessage.GetLength() - sizeof(RequestData), *messageCopy);

    // Send the copy.
    SuccessOrExit(error = mSocket.SendTo(*messageCopy, aMessageInfo));

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

    VerifyOrExit((message = NewMessage(header)) != NULL, ;);

    memset(&messageInfo, 0, sizeof(messageInfo));
    messageInfo.GetPeerAddr() = aAddress;
    messageInfo.mPeerPort = aPort;

    SuccessOrExit(error = mSocket.SendTo(*message, messageInfo));

exit:

    if (error != kThreadError_None && message != NULL)
    {
        message->Free();
    }
}

void Client::HandleRetransmissionTimer(void *aContext)
{
    static_cast<Client *>(aContext)->HandleRetransmissionTimer();
}

void Client::HandleRetransmissionTimer(void)
{
    uint32_t now = otPlatAlarmGetNow();
    uint32_t nextDelta = 0xffffffff;
    RequestData requestData;
    Message *message = mPendingRequests.GetHead();
    Message *nextMessage = NULL;
    Ip6::MessageInfo messageInfo;

    while (message != NULL)
    {
        nextMessage = message->GetNext();
        requestData.ReadFrom(*message);

        if (requestData.IsLater(now))
        {
            // Calculate the next delay and choose the lowest.
            if (requestData.mSendTime - now < nextDelta)
            {
                nextDelta = requestData.mSendTime - now;
            }
        }
        else
        {
            if (requestData.mRetransmissionCount < RequestData::kMaxRetransmit)
            {
                // Increment retransmission counter and timer.
                requestData.mRetransmissionCount++;
                requestData.mRetransmissionTimeout *= 2;
                requestData.mSendTime = now + requestData.mRetransmissionTimeout;
                requestData.UpdateIn(*message);

                // Check if retransmission time is lower than current lowest.
                if (requestData.mRetransmissionTimeout < nextDelta)
                {
                    nextDelta = requestData.mRetransmissionTimeout;
                }

                // Retransmit
                if (!requestData.mAcknowledged)
                {
                    memset(&messageInfo, 0, sizeof(messageInfo));
                    messageInfo.GetPeerAddr() = requestData.mDestinationAddress;
                    messageInfo.mPeerPort = requestData.mDestinationPort;

                    SendCopy(*message, messageInfo);
                }
            }
            else
            {
                RemoveMessage(*message);
                message->Free();

                // Notify the application of timeout.
                if (requestData.mResponseHandler != NULL)
                {
                    requestData.mResponseHandler(requestData.mResponseContext, NULL,
                                                 NULL, kThreadError_NoAck);
                }
            }
        }

        message = nextMessage;
    }

    if (nextDelta != 0xffffffff)
    {
        mRetransmissionTimer.Start(nextDelta);
    }
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

                RemoveMessage(*messageToRemove);
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
                    RemoveMessage(*message);
                    message->Free();

                    if (requestData.mResponseHandler != NULL)
                    {
                        requestData.mResponseHandler(requestData.mResponseContext, NULL,
                                                     NULL, kThreadError_Abort);
                    }
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

                    // Remove the message if response is not expected.
                    if (requestData.mResponseHandler == NULL)
                    {
                        RemoveMessage(*message);
                        message->Free();
                    }
                }
                else if (responseHeader.IsResponse() && responseHeader.IsTokenEqual(requestHeader))
                {
                    // Piggybacked response.
                    rejectMessage = false;
                    RemoveMessage(*message);
                    message->Free();

                    if (requestData.mResponseHandler != NULL)
                    {
                        requestData.mResponseHandler(requestData.mResponseContext, &responseHeader,
                                                     &aMessage, kThreadError_None);
                    }
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
                if (responseHeader.IsConfirmable())
                {
                    // Send empty ack if it is a CON message.
                    SendEmptyAck(aMessageInfo.GetPeerAddr(), aMessageInfo.mPeerPort, responseHeader.GetMessageId());
                }

                rejectMessage = false;
                RemoveMessage(*message);
                message->Free();

                if (requestData.mResponseHandler != NULL)
                {
                    requestData.mResponseHandler(requestData.mResponseContext, &responseHeader,
                                                 &aMessage, kThreadError_None);
                }

                ExitNow();
            }
        }

        message = message->GetNext();
    }

exit:

    if (error == kThreadError_None && rejectMessage)
    {
        if (responseHeader.IsConfirmable() || responseHeader.IsNonConfirmable())
        {
            SendReset(aMessageInfo.GetPeerAddr(), aMessageInfo.mPeerPort, responseHeader.GetMessageId());
        }
    }
}

RequestData::RequestData(const Ip6::MessageInfo &aMessageInfo, CoapResponseHandler aHandler, void *aContext)
{
    mDestinationPort = aMessageInfo.mPeerPort;
    mDestinationAddress = aMessageInfo.GetPeerAddr();
    mResponseHandler = aHandler;
    mResponseContext = aContext;
    mRetransmissionCount = 0;
    mRetransmissionTimeout = Timer::SecToMsec(kAckTimeout);
    mRetransmissionTimeout += otPlatRandomGet() %
                              (Timer::SecToMsec(kAckTimeout) * kAckRandomFactor - Timer::SecToMsec(kAckTimeout) + 1);

    mSendTime = Timer::GetNow() + mRetransmissionTimeout;
    mAcknowledged = false;
}

}  // namespace Coap
}  // namespace Thread
