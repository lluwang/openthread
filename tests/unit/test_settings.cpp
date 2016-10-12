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

#include "test_util.h"
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <openthread.h>
#include <common/debug.hpp>
#include <openthread-instance.h>
#include <platform/flash.h>
#include <platform/settings.h>

extern "C" void otSignalTaskletPending(otInstance *)
{
}

extern "C" void otPlatUartSendDone(void)
{
}

extern "C" void otPlatUartReceived(const uint8_t *, uint16_t)
{
}

extern "C" void otPlatDiagRadioTransmitDone(otInstance *, bool, ThreadError)
{
}

extern "C" void otPlatDiagRadioReceiveDone(otInstance *, RadioPacket *, ThreadError)
{
}

extern "C" void otPlatDiagAlarmFired(otInstance *)
{
}

enum
{
    kMaxStageDataLen = 32,
};

static uint8_t sWriteBuffer[kMaxStageDataLen];
static int sWriteBufferLength;

void TestSettingsInit(void)
{
    uint8_t index;
    otInstance aInstance;

    otPlatFlashInit();
    otPlatSettingsInit(&aInstance);
    otPlatSettingsWipe(&aInstance);

    for (index = 0; index < kMaxStageDataLen; index++)
    {
        sWriteBuffer[index] = index;
    }

    sWriteBufferLength = index;
}

void TestSettingsAdd(void)
{
    uint8_t key = 7;
    uint8_t readBuffer[kMaxStageDataLen];
    int readBufferLength;
    otInstance aInstance;

    VerifyOrQuit(otPlatSettingsAdd(&aInstance, key, sWriteBuffer, sWriteBufferLength) == kThreadError_None,
                 "Settings::Add::Add Fail\n");
    VerifyOrQuit(otPlatSettingsGet(&aInstance, key, 0, readBuffer, &readBufferLength) == kThreadError_None,
                 "Settings::Add::Get Fail\n");
    VerifyOrQuit(!memcmp(readBuffer, sWriteBuffer, static_cast<uint16_t>(sWriteBufferLength)),
                 "Settings::Add::Add Check Fail\n");
}

void TestSettingsDelete(void)
{
    uint8_t key = 8;
    uint8_t readBuffer[kMaxStageDataLen];
    int readBufferLength;
    otInstance aInstance;

    VerifyOrQuit(otPlatSettingsAdd(&aInstance, key, sWriteBuffer, sWriteBufferLength) == kThreadError_None,
                 "Settings::Delete::Add Fail\n");
    VerifyOrQuit(otPlatSettingsGet(&aInstance, key, 0, readBuffer, &readBufferLength) == kThreadError_None,
                 "Settings::Delete::Get Fail\n");
    VerifyOrQuit(!memcmp(readBuffer, sWriteBuffer, static_cast<uint16_t>(sWriteBufferLength)),
                 "Settings::Delete::Add Check Fail\n");
    VerifyOrQuit(otPlatSettingsDelete(&aInstance, key, -1) == kThreadError_None, "Settings::Delete::Delete Fail\n");
    VerifyOrQuit(otPlatSettingsGet(&aInstance, key, 0, readBuffer, &readBufferLength) == kThreadError_NotFound,
                 "Settings::Delete::Get Fail\n");
}

void TestSettingsSet(void)
{
    uint8_t key = 9;
    uint8_t readBuffer[kMaxStageDataLen];
    int readBufferLength;
    otInstance aInstance;

    for (uint8_t index = 0; index < 2; index++)
    {
        VerifyOrQuit(otPlatSettingsAdd(&aInstance, key, sWriteBuffer, sWriteBufferLength) == kThreadError_None,
                     "Settings::Set::Add Fail\n");
    }

    VerifyOrQuit(otPlatSettingsSet(&aInstance, key, sWriteBuffer, sWriteBufferLength) == kThreadError_None,
                 "Settings::Set::Set Fail\n");
    VerifyOrQuit(otPlatSettingsGet(&aInstance, key, 0, readBuffer, &readBufferLength) == kThreadError_None,
                 "Settings::Set::Get Fail\n");
    VerifyOrQuit(!memcmp(readBuffer, sWriteBuffer, static_cast<uint16_t>(sWriteBufferLength)),
                 "Settings::Set::Set Check Fail\n");
}

void TestSettingsSwap(void)
{
    ThreadError error = kThreadError_None;
    uint8_t key = 11;
    uint16_t index = 0;
    uint8_t readBuffer[kMaxStageDataLen];
    int readBufferLength = kMaxStageDataLen;
    otInstance aInstance;

    while (true)
    {
        error = otPlatSettingsAdd(&aInstance, key, sWriteBuffer, sWriteBufferLength);
        VerifyOrQuit(error == kThreadError_None || error == kThreadError_NoBufs, "Settings::Swap::Add Fail\n");

        if (error == kThreadError_NoBufs)
        {
            break;
        }

        index++;
    }

    VerifyOrQuit(otPlatSettingsDelete(&aInstance, key, 0) == kThreadError_None, "Settings::Swap::Delete Fail\n");
    VerifyOrQuit(otPlatSettingsAdd(&aInstance, key, sWriteBuffer, sWriteBufferLength) == kThreadError_None,
                 "Settings::Swap::Add Fail after swap\n");
    VerifyOrQuit(otPlatSettingsGet(&aInstance, key, index - 1, readBuffer, &readBufferLength) == kThreadError_None,
                 "Settings::Swap::Get Fail\n");
    VerifyOrQuit(!memcmp(readBuffer, sWriteBuffer, static_cast<uint16_t>(sWriteBufferLength)),
                 "Settings::Swap::Add and Swap Check Fail\n");
}

void RunSettingsTests(void)
{
    DIR *dir;
    struct dirent *ent;

    TestSettingsInit();
    TestSettingsAdd();
    TestSettingsDelete();
    TestSettingsSet();
    TestSettingsSwap();

    VerifyOrQuit((dir = opendir("./tmp")) != NULL, "Open tmp fail\n");

    while ((ent = readdir(dir)) != NULL)
    {
        char path[20];

        strcpy(path, "./tmp/");
        strcat(path, ent->d_name);
        remove(path);
    }

    closedir(dir);
    rmdir("./tmp");
}

#ifdef ENABLE_TEST_MAIN
int main(void)
{
    RunSettingsTests();
    printf("All tests passed\n");
    return 0;
}
#endif
