/*
 *  Copyright (c) 2016, Nest Labs, Inc.
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

/**
 * @file
 *   This file implements a pseudo-random number generator.
 *
 */

#include <openthread-types.h>

#include <common/code_utils.hpp>
#include <platform/radio.h>
#include <platform/random.h>
#include "platform-cc2538.h"

void cc2538RandomInit(void)
{
}

uint16_t generateRandom(void)
{
    uint32_t reg;
    uint16_t seed = 0;
    uint8_t channel = 0;

    if (otPlatRadioIsEnabled())
    {
        channel = 11 + (HWREG(RFCORE_XREG_FREQCTRL) - 11) / 5;
        otPlatRadioSleep();
        otPlatRadioDisable();
    }

    HWREG(SOC_ADC_ADCCON1) &= ~(SOC_ADC_ADCCON1_RCTRL1 | SOC_ADC_ADCCON1_RCTRL0);
    HWREG(SYS_CTRL_RCGCRFC) = SYS_CTRL_RCGCRFC_RFC0;

    while (HWREG(SYS_CTRL_RCGCRFC) != SYS_CTRL_RCGCRFC_RFC0);

    HWREG(RFCORE_XREG_FRMCTRL0) = RFCORE_XREG_FRMCTRL0_INFINITY_RX;
    HWREG(RFCORE_SFR_RFST) = RFCORE_SFR_RFST_INSTR_RXON;

    while (!HWREG(RFCORE_XREG_RSSISTAT) & RFCORE_XREG_RSSISTAT_RSSI_VALID);

    while (seed == 0x0000 || seed == 0x8003)
    {
        for (uint8_t index = 0; index < (8 * sizeof(seed)); index++)
        {
            seed |= (HWREG(RFCORE_XREG_RFRND) & RFCORE_XREG_RFRND_IRND);
            seed <<= 1;
        }
    }

    HWREG(SOC_ADC_RNDL) = (seed >> 8) & 0xff;
    HWREG(SOC_ADC_RNDL) = seed & 0xff;

    HWREG(RFCORE_SFR_RFST) = RFCORE_SFR_RFST_INSTR_RFOFF;

    HWREG(SOC_ADC_ADCCON1) |= SOC_ADC_ADCCON1_RCTRL0;
    reg = HWREG(SOC_ADC_RNDL) | (HWREG(SOC_ADC_RNDH) << 8);

    if (channel)
    {
        cc2538RadioInit();
        otPlatRadioEnable();
        otPlatRadioReceive(channel);
    }

    return (uint16_t)reg;
}

uint32_t otPlatRandomGet(void)
{
    return (generateRandom() | (generateRandom() << 16));
}

ThreadError otPlatSecureRandomGet(uint16_t aInputLength, uint8_t *aOutput, uint16_t *aOutputLength)
{
    ThreadError error = kThreadError_None;

    VerifyOrExit(aOutput && aOutputLength, error = kThreadError_InvalidArgs);

    for (uint16_t length = 0; length < aInputLength; length++)
    {
        aOutput[length] = (uint8_t)generateRandom();
    }

    *aOutputLength = aInputLength;

exit:
    return error;
}
