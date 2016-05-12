/*
 *    Copyright (c) 2016, Nest Labs, Inc.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
 *    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file implements an HDLC interface to the Thread stack.
 */

#include <common/code_utils.hpp>
#include <ncp/ncp.hpp>
#include <platform/serial.h>

namespace Thread {

static Tasklet sSendDoneTask(&Ncp::SendDoneTask, NULL);
static Tasklet sReceiveTask(&Ncp::ReceiveTask, NULL);
static Ncp *sNcp;

Ncp::Ncp():
    NcpBase(),
    mFrameDecoder(mReceiveFrame, sizeof(mReceiveFrame), &HandleFrame, this)
{
    sNcp = this;
}

ThreadError Ncp::Start()
{
    otPlatSerialEnable();
    return super_t::Start();
}

ThreadError Ncp::Stop()
{
    otPlatSerialDisable();
    return super_t::Stop();
}

ThreadError Ncp::Send(const uint8_t *frame, uint16_t frameLength)
{
    uint8_t *cur = mSendFrame;
    uint16_t outLength;

    outLength = sizeof(mSendFrame) - (cur - mSendFrame);
    mFrameEncoder.Init(cur, outLength);
    cur += outLength;

    outLength = sizeof(mSendFrame) - (cur - mSendFrame);
    mFrameEncoder.Encode(frame, frameLength, cur, outLength);
    cur += outLength;

    outLength = sizeof(mSendFrame) - (cur - mSendFrame);
    mFrameEncoder.Finalize(cur, outLength);
    cur += outLength;

    return otPlatSerialSend(mSendFrame, cur - mSendFrame);
}

/// TODO: queue
ThreadError Ncp::Send(const uint8_t *frame, uint16_t frameLength, Message &message)
{
    uint8_t *cur = mSendFrame;
    uint16_t outLength;
    uint16_t inLength;
    uint8_t inBuf[16];

    outLength = sizeof(mSendFrame) - (cur - mSendFrame);
    mFrameEncoder.Init(cur, outLength);
    cur += outLength;

    outLength = sizeof(mSendFrame) - (cur - mSendFrame);
    mFrameEncoder.Encode(frame, frameLength, cur, outLength);
    cur += outLength;

    for (int offset = 0; offset < message.GetLength(); offset += sizeof(inBuf))
    {
        inLength = message.Read(offset, sizeof(inBuf), inBuf);
        outLength = sizeof(mSendFrame) - (cur - mSendFrame);
        mFrameEncoder.Encode(inBuf, inLength, cur, outLength);
        cur += outLength;
    }

    outLength = sizeof(mSendFrame) - (cur - mSendFrame);
    mFrameEncoder.Finalize(cur, outLength);
    cur += outLength;

    mSendMessage = &message;

    return otPlatSerialSend(mSendFrame, cur - mSendFrame);
}

extern "C" void otPlatSerialSignalSendDone()
{
    sSendDoneTask.Post();
}

void Ncp::SendDoneTask(void *context)
{
    sNcp->SendDoneTask();
}

void Ncp::SendDoneTask()
{
    if (mSendMessage) {
        Message::Free(*mSendMessage);
        mSendMessage = NULL;
    }
    super_t::HandleSendDone();
}

extern "C" void otPlatSerialSignalReceive()
{
    sReceiveTask.Post();
}

void Ncp::ReceiveTask(void *context)
{
    sNcp->ReceiveTask();
}

void Ncp::ReceiveTask()
{
    const uint8_t *buf;
    uint16_t bufLength;

    buf = otPlatSerialGetReceivedBytes(&bufLength);

    mFrameDecoder.Decode(buf, bufLength);

    otPlatSerialHandleReceiveDone();
}

void Ncp::HandleFrame(void *context, uint8_t *aBuf, uint16_t aBufLength)
{
    sNcp->HandleFrame(aBuf, aBufLength);
}

void Ncp::HandleFrame(uint8_t *aBuf, uint16_t aBufLength)
{
    super_t::HandleReceive(aBuf, aBufLength);
}

}  // namespace Thread
