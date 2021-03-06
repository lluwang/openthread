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
 * @brief
 *  This file defines the top-level functions for the OpenThread library.
 */

#ifndef OPENTHREAD_H_
#define OPENTHREAD_H_

#include <stdint.h>

#include <openthread-types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup api  API
 * @brief
 *   This module includes the application programming interface to the OpenThread stack.
 *
 * @{
 *
 * @defgroup execution Execution
 * @defgroup commands Commands
 * @defgroup config Configuration
 * @defgroup diags Diagnostics
 * @defgroup messages Message Buffers
 * @defgroup udp UDP
 *
 * @}
 *
 */

/**
 * @defgroup platform  Platform Abstraction
 * @brief
 *   This module includes the platform abstraction used by the OpenThread stack.
 *
 * @{
 * @}
 *
 */

/**
 * @defgroup core Core
 * @brief
 *   This module includes the core OpenThread stack.
 *
 * @{
 *
 * @defgroup core-6lowpan 6LoWPAN
 * @defgroup core-coap CoAP
 * @defgroup core-ipv6 IPv6
 * @defgroup core-mac MAC
 * @defgroup core-mesh-forwarding Mesh Forwarding
 * @defgroup core-message Message
 * @defgroup core-mle MLE
 * @defgroup core-netdata Network Data
 * @defgroup core-netif Network Interface
 * @defgroup core-arp RLOC Mapping
 * @defgroup core-security Security
 * @defgroup core-tasklet Tasklet
 * @defgroup core-timer Timer
 * @defgroup core-udp UDP
 *
 * @}
 *
 */

/**
 * @addtogroup execution  Execution
 *
 * @brief
 *   This module includes functions that control the Thread stack's execution.
 *
 * @{
 *
 */

/**
 * Initialize the OpenThread library.
 */
void otInit();

/**
 * Run the next queued tasklet in OpenThread.
 */
void otProcessNextTasklet(void);

/**
 * Indicates whether or not OpenThread has tasklets pending.
 *
 * @retval TRUE   If there are tasklets pending.
 * @retval FALSE  If there are no tasklets pending.
 */
bool otAreTaskletsPending(void);

/**
 * OpenThread calls this function when the tasklet queue transitions from empty to non-empty.
 *
 */
extern void otSignalTaskletPending(void);

/**
 * @}
 *
 */

/**
 * @addtogroup commands  Commands
 *
 * @brief
 *   This module includes functions for OpenThread commands.
 *
 * @{
 *
 */

/**
 * Enable the Thread interface.
 *
 * @retval kThreadErrorNone  Successfully enabled the Thread interface.
 */
ThreadError otEnable(void);

/**
 * Disable the Thread interface.
 *
 * @retval kThreadErrorNone  Successfully disabled the Thread interface.
 */
ThreadError otDisable(void);

/**
 * This function pointer is called during an IEEE 802.15.4 Active Scan when an IEEE 802.15.4 Beacon is received or
 * the scan completes.
 *
 * @param[in]  aResult  A valid pointer to the beacon information or NULL when the active scan completes.
 *
 */
typedef void (*otHandleActiveScanResult)(otActiveScanResult *aResult);

/**
 * This function starts an IEEE 802.15.4 Active Scan
 *
 * @param[in]  aScanChannels  A bit vector indicating which channels to scan.
 * @param[in]  aScanDuration  The time in milliseconds to spend scanning each channel.
 * @param[in]  aCallback      A pointer to a function that is called when a beacon is received or the scan completes.
 *
 * @retval kThreadError_None  Accepted the Active Scan request.
 * @retval kThreadError_Busy  Already performing an Active Scan.
 *
 */
ThreadError otActiveScan(uint16_t aScanChannels, uint16_t aScanDuration, otHandleActiveScanResult aCallback);

/**
 * This function determines if an IEEE 802.15.4 Active Scan is currently in progress.
 *
 * @returns true if an active scan is in progress.
 */
bool otActiveScanInProgress(void);

/**
 * @}
 *
 */

/**
 * @addtogroup config  Configuration
 *
 * @brief
 *   This module includes functions for configuration.
 *
 * @{
 *
 */

/**
 * @defgroup config-general  General
 *
 * @brief
 *   This module includes functions that manage configuration parameters for the Thread Child, Router, and Leader rols.
 *
 * @{
 *
 */

/**
 * Get the IEEE 802.15.4 channel.
 *
 * @returns The IEEE 802.15.4 channel.
 *
 * @sa otSetChannel
 */
uint8_t otGetChannel(void);

/**
 * Set the IEEE 802.15.4 channel
 *
 * @param[in]  aChannel  The IEEE 802.15.4 channel.
 *
 * @retval  kThreadErrorNone         Successfully set the channel.
 * @retval  kThreadErrorInvalidArgs  If @p aChnanel is not in the range [11, 26].
 *
 * @sa otGetChannel
 */
ThreadError otSetChannel(uint8_t aChannel);

/**
 * Get the Thread Child Timeout used when operating in the Child role.
 *
 * @returns The Thread Child Timeout value.
 *
 * @sa otSetChildTimeout
 */
uint32_t otGetChildTimeout(void);

/**
 * Set the Thread Child Timeout used when operating in the Child role.
 *
 * @sa otSetChildTimeout
 */
void otSetChildTimeout(uint32_t aTimeout);

/**
 * Get the IEEE 802.15.4 Extended Address.
 *
 * @returns A pointer to the IEEE 802.15.4 Extended Address.
 */
const uint8_t *otGetExtendedAddress(void);

/**
 * Get the IEEE 802.15.4 Extended PAN ID.
 *
 * @returns A pointer to the IEEE 802.15.4 Extended PAN ID.
 *
 * @sa otSetExtendedPanId
 */
const uint8_t *otGetExtendedPanId(void);

/**
 * Set the IEEE 802.15.4 Extended PAN ID.
 *
 * @param[in]  aExtendedPanId  A pointer to the IEEE 802.15.4 Extended PAN ID.
 *
 * @sa otGetExtendedPanId
 */
void otSetExtendedPanId(const uint8_t *aExtendedPanId);

/**
 * Get the MLE Link Mode configuration.
 *
 * @returns The MLE Link Mode configuration.
 *
 * @sa otSetLinkMode
 */
otLinkModeConfig otGetLinkMode(void);

/**
 * Set the MLE Link Mode configuration.
 *
 * @param[in]  aConfig  A pointer to the Link Mode configuration.
 *
 * @retval kThreadErrorNone  Successfully set the MLE Link Mode configuration.
 *
 * @sa otGetLinkMode
 */
ThreadError otSetLinkMode(otLinkModeConfig aConfig);

/**
 * Get the thrMasterKey.
 *
 * @param[out]  aKeyLength  A pointer to an unsigned 8-bit value that the function will set to the number of bytes that
 *                          represent the thrMasterKey. Caller may set to NULL.
 *
 * @returns A pointer to a buffer containing the thrMasterKey.
 *
 * @sa otSetMasterKey
 */
const uint8_t *otGetMasterKey(uint8_t *aKeyLength);

/**
 * Set the thrMasterKey.
 *
 * @param[in]  aKey        A pointer to a buffer containing the thrMasterKey.
 * @param[in]  aKeyLength  Number of bytes representing the thrMasterKey stored at aKey. Valid range is [0, 16].
 *
 * @retval kThreadErrorNone         Successfully set the thrMasterKey.
 * @retval kThreadErrorInvalidArgs  If aKeyLength is larger than 16.
 *
 * @sa otGetMasterKey
 */
ThreadError otSetMasterKey(const uint8_t *aKey, uint8_t aKeyLength);

/**
 * Get the Thread Network Name.
 *
 * @returns A pointer to the Thread Network Name.
 *
 * @sa otSetNetworkName
 */
const char *otGetNetworkName(void);

/**
 * Set the Thread Network Name.
 *
 * @param[in]  aNetworkName  A pointer to the Thread Network Name.
 *
 * @retval kThreadErrorNone  Successfully set the Thread Network Name.
 *
 * @sa otGetNetworkName
 */
ThreadError otSetNetworkName(const char *aNetworkName);

/**
 * Get the IEEE 802.15.4 PAN ID.
 *
 * @returns The IEEE 802.15.4 PAN ID.
 *
 * @sa otSetPanId
 */
otPanId otGetPanId(void);

/**
 * Set the IEEE 802.15.4 PAN ID.
 *
 * @param[in]  aPanId  The IEEE 802.15.4 PAN ID.
 *
 * @retval kThreadErrorNone         Successfully set the PAN ID.
 * @retval kThreadErrorInvalidArgs  If aPanId is not in the range [0, 65534].
 *
 * @sa otGetPanId
 */
ThreadError otSetPanId(otPanId aPanId);

/**
 * Get the list of IPv6 addresses assigned to the Thread interface.
 *
 * @returns A pointer to the first Network Inteface Address.
 */
const otNetifAddress *otGetUnicastAddresses();

/**
 * Add a Network Interface Address to the Thread interface.
 *
 * @param[in]  aAddress  A pointer to a Network Interface Address.
 *
 * @retval kThreadErrorNone  Successfully added the Network Interface Address.
 * @retval kThreadErrorBusy  The Network Interface Address pointed to by @p aAddress is already added.
 */
ThreadError otAddUnicastAddress(otNetifAddress *aAddress);

/**
 * Remove a Network Interface Address from the Thread interface.
 *
 * @param[in]  aAddress  A pointer to a Network Interface Address.
 *
 * @retval kThreadErrorNone      Successfully removed the Network Interface Address.
 * @retval kThreadErrorNotFound  The Network Interface Address point to by @p aAddress was not added.
 */
ThreadError otRemoveUnicastAddress(otNetifAddress *aAddress);

/**
 * @}
 */

/**
 * @defgroup config-router  Router/Leader
 *
 * @brief
 *   This module includes functions that manage configuration parameters for the Thread Router and Leader roles.
 *
 * @{
 *
 */

/**
 * Get the Thread Leader Weight used when operating in the Leader role.
 *
 * @returns The Thread Child Timeout value.
 *
 * @sa otSetLeaderWeight
 */
uint8_t otGetLocalLeaderWeight(void);

/**
 * Set the Thread Leader Weight used when operating in the Leader role.
 *
 * @param[in]  aWeight  The Thread Leader Weight value..
 *
 * @sa otGetLeaderWeight
 */
void otSetLocalLeaderWeight(uint8_t aWeight);

/**
 * @}
 */

/**
 * @defgroup config-br  Border Router
 *
 * @brief
 *   This module includes functions that manage configuration parameters that apply to the Thread Border Router role.
 *
 * @{
 *
 */

/**
 * Add a border router configuration to the local network data.
 *
 * @param[in]  aConfig  A pointer to the border router configuration.
 *
 * @retval kThreadErrorNone         Successfully added the configuration to the local network data.
 * @retval kThreadErrorInvalidArgs  One or more configuration parameters were invalid.
 * @retval kThreadErrorSize         Not enough room is available to add the configuration to the local network data.
 *
 * @sa otRemoveBorderRouter
 * @sa otSendServerData
 */
ThreadError otAddBorderRouter(const otBorderRouterConfig *aConfig);

/**
 * Remove a border router configuration from the local network data.
 *
 * @param [in]  aPrefix  A pointer to an IPv6 prefix.
 *
 * @retval kThreadErrorNone  Successfully removed the configuration from the local network data.
 *
 * @sa otAddBorderRouter
 * @sa otSendServerData
 */
ThreadError otRemoveBorderRouter(const otIp6Prefix *aPrefix);

/**
 * Add an external route configuration to the local network data.
 *
 * @param[in]  aConfig  A pointer to the external route configuration.
 *
 * @retval kThreadErrorNone         Successfully added the configuration to the local network data.
 * @retval kThreadErrorInvalidArgs  One or more configuration parameters were invalid.
 * @retval kThreadErrorSize         Not enough room is available to add the configuration to the local network data.
 *
 * @sa otRemoveExternalRoute
 * @sa otSendServerData
 */
ThreadError otAddExternalRoute(const otExternalRouteConfig *aConfig);

/**
 * Remove an external route configuration from the local network data.
 *
 * @param[in]  aPrefix  A pointer to an IPv6 prefix.
 *
 * @retval kThreadErrorNone  Successfully removed the configuration from the local network data.
 *
 * @sa otAddExternalRoute
 * @sa otSendServerData
 */
ThreadError otRemoveExternalRoute(const otIp6Prefix *aPrefix);

/**
 * Immediately register the local network data with the Leader.
 *
 *
 * retval kThreadErrorNone  Successfully queued a Server Data Request message for delivery.
 *
 * @sa otAddBorderRouter
 * @sa otRemoveBorderRouter
 * @sa otAddExternalRoute
 * @sa otRemoveExternalRoute
 */
ThreadError otSendServerData(void);

/**
 * @}
 *
 */

/**
 * @defgroup config-test  Test
 *
 * @brief
 *   This module includes functions that manage configuration parameters required for Thread Certification testing.
 *
 * @{
 *
 */

/**
 * Get the CONTEXT_ID_REUSE_DELAY parameter used in the Leader role.
 *
 * @returns The CONTEXT_ID_REUSE_DELAY value.
 *
 * @sa otSetContextIdReuseDelay
 */
uint32_t otGetContextIdReuseDelay(void);

/**
 * Set the CONTEXT_ID_REUSE_DELAY parameter used in the Leader role.
 *
 * @param[in]  aDelay  The CONTEXT_ID_REUSE_DELAY value.
 *
 * @sa otGetContextIdReuseDelay
 */
void otSetContextIdReuseDelay(uint32_t aDelay);

/**
 * Get the thrKeySequenceCounter.
 *
 * @returns The thrKeySequenceCounter value.
 *
 * @sa otSetKeySequenceCounter
 */
uint32_t otGetKeySequenceCounter(void);

/**
 * Set the thrKeySequenceCounter.
 *
 * @param[in]  aKeySequenceCounter  The thrKeySequenceCounter value.
 *
 * @sa otGetKeySequenceCounter
 */
void otSetKeySequenceCounter(uint32_t aKeySequenceCounter);

/**
 * Get the NETWORK_ID_TIMEOUT parameter used in the Router role.
 *
 * @returns The NETWORK_ID_TIMEOUT value.
 *
 * @sa otSetNetworkIdTimeout
 */
uint32_t otGetNetworkIdTimeout(void);

/**
 * Set the NETWORK_ID_TIMEOUT parameter used in the Leader role.
 *
 * @param[in]  aTimeout  The NETWORK_ID_TIMEOUT value.
 *
 * @sa otGetNetworkIdTimeout
 */
void otSetNetworkIdTimeout(uint32_t aTimeout);

/**
 * Get the ROUTER_UPGRADE_THRESHOLD parameter used in the REED role.
 *
 * @returns The ROUTER_UPGRADE_THRESHOLD value.
 *
 * @sa otSetRouterUpgradeThreshold
 */
uint8_t otGetRouterUpgradeThreshold(void);

/**
 * Set the ROUTER_UPGRADE_THRESHOLD parameter used in the Leader role.
 *
 * @param[in]  aThreshold  The ROUTER_UPGRADE_THRESHOLD value.
 *
 * @sa otGetRouterUpgradeThreshold
 */
void otSetRouterUpgradeThreshold(uint8_t aThreshold);

/**
 * Release a Router ID that has been allocated by the device in the Leader role.
 *
 * @param[in]  aRouterId  The Router ID to release. Valid range is [0, 62].
 *
 * @retval kThreadErrorNone  Successfully released the Router ID specified by aRouterId.
 */
ThreadError otReleaseRouterId(uint8_t aRouterId);

/**
 * Add an IEEE 802.15.4 Extended Address to the MAC whitelist.
 *
 * @param[in]  aExtAddr  A pointer to the IEEE 802.15.4 Extended Address.
 *
 * @retval kThreadErrorNone    Successfully added to the MAC whitelist.
 * @retval kThreadErrorNoBufs  No buffers available for a new MAC whitelist entry.
 *
 * @sa otAddMacWhitelistRssi
 * @sa otRemoveMacWhitelist
 * @sa otClearMacWhitelist
 * @sa otDisableMacWhitelist
 * @sa otEnableMacWhitelist
 */
ThreadError otAddMacWhitelist(const uint8_t *aExtAddr);

/**
 * Add an IEEE 802.15.4 Extended Address to the MAC whitelist and fix the RSSI value.
 *
 * @param[in]  aExtAddr  A pointer to the IEEE 802.15.4 Extended Address.
 * @param[in]  aRssi     The RSSI in dBm to use when receiving messages from aExtAddr.
 *
 * @retval kThreadErrorNone    Successfully added to the MAC whitelist.
 * @retval kThreadErrorNoBufs  No buffers available for a new MAC whitelist entry.
 *
 * @sa otAddMacWhitelistRssi
 * @sa otRemoveMacWhitelist
 * @sa otClearMacWhitelist
 * @sa otDisableMacWhitelist
 * @sa otEnableMacWhitelist
 */
ThreadError otAddMacWhitelistRssi(const uint8_t *aExtAddr, int8_t aRssi);

/**
 * Remove an IEEE 802.15.4 Extended Address from the MAC whitelist.
 *
 * @param[in]  aExtAddr  A pointer to the IEEE 802.15.4 Extended Address.
 *
 * @sa otAddMacWhitelist
 * @sa otAddMacWhitelistRssi
 * @sa otClearMacWhitelist
 * @sa otDisableMacWhitelist
 * @sa otEnableMacWhitelist
 */
void otRemoveMacWhitelist(const uint8_t *aExtAddr);

/**
 *  Remove all entries from the MAC whitelist.
 *
 * @sa otAddMacWhitelist
 * @sa otAddMacWhitelistRssi
 * @sa otRemoveMacWhitelist
 * @sa otDisableMacWhitelist
 * @sa otEnableMacWhitelist
 */
void otClearMacWhitelist();

/**
 * Disable MAC whitelist filtering.
 *
 *
 * @sa otAddMacWhitelist
 * @sa otAddMacWhitelistRssi
 * @sa otRemoveMacWhitelist
 * @sa otClearMacWhitelist
 * @sa otEnableMacWhitelist
 */
void otDisableMacWhitelist();

/**
 * Enable MAC whitelist filtering.
 *
 * @sa otAccMacWhitelist
 * @sa otAddMacWhitelistRssi
 * @sa otRemoveMacWhitelist
 * @sa otClearMacWhitelist
 * @sa otDisableMacWhitelist
 */
void otEnableMacWhitelist();

/**
 * Detach from the Thread network.
 *
 * @retval kThreadErrorNone    Successfully detached from the Thread network.
 * @retval kThreadErrorBusy    Thread is disabled.
 */
ThreadError otBecomeDetached();

/**
 * Attempt to reattach as a child.
 *
 * @param[in]  aFilter  Identifies whether to join any, same, or better partition.
 *
 * @retval kThreadErrorNone    Successfully begin attempt to become a child.
 * @retval kThreadErrorBusy    Thread is disabled or in the middle of an attach process.
 */
ThreadError otBecomeChild(otMleAttachFilter aFilter);

/**
 * Attempt to become a router.
 *
 * @retval kThreadErrorNone    Successfully begin attempt to become a router.
 * @retval kThreadErrorBusy    Thread is disabled or already operating in a router or leader role.
 */
ThreadError otBecomeRouter();

/**
 * Become a leader and start a new partition.
 *
 * @retval kThreadErrorNone  Successfully became a leader and started a new partition.
 */
ThreadError otBecomeLeader();

/**
 * @}
 *
 */

/**
 * @}
 *
 */

/**
 * @addtogroup diags  Diagnostics
 *
 * @brief
 *   This module includes functions that expose internal state.
 *
 * @{
 *
 */

/**
 * Get the device role.
 *
 * @retval ::kDeviceRoleDisabled  The Thread stack is disabled.
 * @retval ::kDeviceRoleDetached  The device is not currently participating in a Thread network/partition.
 * @retval ::kDeviceRoleChild     The device is currently operating as a Thread Child.
 * @retval ::kDeviceRoleRouter    The device is currently operating as a Thread Router.
 * @retval ::kDeviceRoleLeader    The device is currently operating as a Thread Leader.
 */
otDeviceRole otGetDeviceRole();

/**
 * Get the Leader's Router ID.
 *
 * @returns The Leader's Router ID.
 */
uint8_t otGetLeaderRouterId();

/**
 * Get the Leader's Weight.
 *
 * @returns The Leader's Weight.
 */
uint8_t otGetLeaderWeight();

/**
 * Get the Network Data Version.
 *
 * @returns The Network Data Version.
 */
uint8_t otGetNetworkDataVersion();

/**
 * Get the Partition ID.
 *
 * @returns The Partition ID.
 */
uint32_t otGetPartitionId();

/**
 * Get the RLOC16.
 *
 * @returns The RLOC16.
 */
uint16_t otGetRloc16(void);

/**
 * Get the current Router ID Sequence.
 *
 * @returns The Router ID Sequence.
 */
uint8_t otGetRouterIdSequence();

/**
 * Get the Stable Network Data Version.
 *
 * @returns The Stable Network Data Version.
 */
uint8_t otGetStableNetworkDataVersion();

/**
 * @}
 *
 */

/**
 * Test if two IPv6 addresses are the same.
 *
 * @param[in]  a  A pointer to the first IPv6 address to compare.
 * @param[in]  b  A pointer to the second IPv6 address to compare.
 *
 * @retval TRUE   The two IPv6 addresses are the same.
 * @retval FALSE  The two IPv6 addresses are not the same.
 */
bool otIsIp6AddressEqual(const otIp6Address *a, const otIp6Address *b);

/**
 * Convert a human-readable IPv6 address string into a binary representation.
 *
 * @param[in]   aString   A pointer to a NULL-terminated string.
 * @param[out]  aAddress  A pointer to an IPv6 address.
 *
 * @retval kThreadErrorNone        Successfully parsed the string.
 * @retval kThreadErrorInvalidArg  Failed to parse the string.
 */
ThreadError otIp6AddressFromString(const char *aString, otIp6Address *aAddress);

/**
 * @addtogroup messages  Message Buffers
 *
 * @brief
 *   This module includes functions that manipulate OpenThread message buffers
 *
 * @{
 *
 */

/**
 * This type points to an OpenThread message buffer.
 */
typedef void *otMessage;

/**
 * Free an allocated message buffer.
 *
 * @param[in]  aMessage  A pointer to a message buffer.
 *
 * @retval kThreadErrorNone  Successfully freed the message buffer.
 *
 * @sa otNewUdpMessage
 * @sa otAppendMessage
 * @sa otGetMessageLength
 * @sa otSetMessageLength
 * @sa otGetMessageOffset
 * @sa otSetMessageOffset
 * @sa otReadMessage
 * @sa otWriteMessage
 */
ThreadError otFreeMessage(otMessage aMessage);

/**
 * Get the message length in bytes.
 *
 * @param[in]  aMessage  A pointer to a message buffer.
 *
 * @returns The message length in bytes.
 *
 * @sa otNewUdpMessage
 * @sa otFreeMessage
 * @sa otAppendMessage
 * @sa otSetMessageLength
 * @sa otGetMessageOffset
 * @sa otSetMessageOffset
 * @sa otReadMessage
 * @sa otWriteMessage
 * @sa otSetMessageLength
 */
uint16_t otGetMessageLength(otMessage aMessage);

/**
 * Set the message length in bytes.
 *
 * @param[in]  aMessage  A pointer to a message buffer.
 * @param[in]  aLength   A length in bytes.
 *
 * @retval kThreadErrorNone    Successfully set the message length.
 * @retval kThreadErrorNoBufs  No available buffers to grow the message.
 *
 * @sa otNewUdpMessage
 * @sa otFreeMessage
 * @sa otAppendMessage
 * @sa otGetMessageLength
 * @sa otGetMessageOffset
 * @sa otSetMessageOffset
 * @sa otReadMessage
 * @sa otWriteMessage
 */
ThreadError otSetMessageLength(otMessage aMessage, uint16_t aLength);

/**
 * Get the message offset in bytes.
 *
 * @param[in]  aMessage  A pointer to a message buffer.
 *
 * @returns The message offset value.
 *
 * @sa otNewUdpMessage
 * @sa otFreeMessage
 * @sa otAppendMessage
 * @sa otGetMessageLength
 * @sa otSetMessageLength
 * @sa otSetMessageOffset
 * @sa otReadMessage
 * @sa otWriteMessage
 */
uint16_t otGetMessageOffset(otMessage aMessage);

/**
 * Set the message offset in bytes.
 *
 * @param[in]  aMessage  A pointer to a message buffer.
 * @param[in]  aOffset   An offset in bytes.
 *
 * @retval kThreadErrorNone        Successfully set the message offset.
 * @retval kThreadErrorInvalidArg  The offset is beyond the message length.
 *
 * @sa otNewUdpMessage
 * @sa otFreeMessage
 * @sa otAppendMessage
 * @sa otGetMessageLength
 * @sa otSetMessageLength
 * @sa otGetMessageOffset
 * @sa otReadMessage
 * @sa otWriteMessage
 */
ThreadError otSetMessageOffset(otMessage aMessage, uint16_t aOffset);

/**
 * Append bytes to a message.
 *
 * @param[in]  aMessage  A pointer to a message buffer.
 * @param[in]  aBuf      A pointer to the data to append.
 * @param[in]  aLength   Number of bytes to append.
 *
 * @returns The number of bytes appended.
 *
 * @sa otNewUdpMessage
 * @sa otFreeMessage
 * @sa otGetMessageLength
 * @sa otSetMessageLength
 * @sa otGetMessageOffset
 * @sa otSetMessageOffset
 * @sa otReadMessage
 * @sa otWriteMessage
 */
int otAppendMessage(otMessage aMessage, const void *aBuf, uint16_t aLength);

/**
 * Read bytes from a message.
 *
 * @param[in]  aMessage  A pointer to a message buffer.
 * @param[in]  aOffset   An offset in bytes.
 * @param[in]  aBuf      A pointer to a buffer that message bytes are read to.
 * @param[in]  aLength   Number of bytes to read.
 *
 * @returns The number of bytes read.
 *
 * @sa otNewUdpMessage
 * @sa otFreeMessage
 * @sa otAppendMessage
 * @sa otGetMessageLength
 * @sa otSetMessageLength
 * @sa otGetMessageOffset
 * @sa otSetMessageOffset
 * @sa otWriteMessage
 */
int otReadMessage(otMessage aMessage, uint16_t aOffset, void *aBuf, uint16_t aLength);

/**
 * Write bytes to a message.
 *
 * @param[in]  aMessage  A pointer to a message buffer.
 * @param[in]  aOffset   An offset in bytes.
 * @param[in]  aBuf      A pointer to a buffer that message bytes are written from.
 * @param[in]  aLength   Number of bytes to write.
 *
 * @returns The number of bytes written.
 *
 * @sa otNewUdpMessage
 * @sa otFreeMessage
 * @sa otAppendMessage
 * @sa otGetMessageLength
 * @sa otSetMessageLength
 * @sa otGetMessageOffset
 * @sa otSetMessageOffset
 * @sa otReadMessage
 */
int otWriteMessage(otMessage aMessage, uint16_t aOffset, const void *aBuf, uint16_t aLength);

/**
 * @}
 *
 */

/**
 * @addtogroup udp  UDP
 *
 * @brief
 *   This module includes functions that control UDP communication.
 *
 * @{
 *
 */

/**
 * Allocate a new message buffer for sending a UDP message.
 *
 * @returns A pointer to the message buffer or NULL if no message buffers are available.
 *
 * @sa otFreeMessage
 */
otMessage otNewUdpMessage();

/**
 * Open a UDP/IPv6 socket.
 *
 * @param[in]  aSocket    A pointer to a UDP socket structure.
 * @param[in]  aCallback  A pointer to the application callback function.
 * @param[in]  aContext   A pointer to application-specific context.
 *
 * @retval kThreadErrorNone  Successfully openned the socket.
 * @retval kThreadErrorBusy  Socket is already openned.
 *
 * @sa otNewUdpMessage
 * @sa otCloseUdpSocket
 * @sa otBindUdpSocket
 * @sa otSendUdp
 */
ThreadError otOpenUdpSocket(otUdpSocket *aSocket, otUdpReceive aCallback, void *aContext);

/**
 * Close a UDP/IPv6 socket.
 *
 * @param[in]  aSocket  A pointer to a UDP socket structure.
 *
 * @retval kThreadErrorNone  Successfully closed the socket.
 *
 * @sa otNewUdpMessage
 * @sa otOpenUdpSocket
 * @sa otBindUdpSocket
 * @sa otSendUdp
 */
ThreadError otCloseUdpSocket(otUdpSocket *aSocket);

/**
 * Bind a UDP/IPv6 socket.
 *
 * @param[in]  aSocket    A pointer to a UDP socket structure.
 * @param[in]  aSockName  A pointer to an IPv6 socket address structure.
 *
 * @retval kThreadErrorNone  Bind operation was successful.
 *
 * @sa otNewUdpMessage
 * @sa otOpenUdpSocket
 * @sa otCloseUdpSocket
 * @sa otSendUdp
 */
ThreadError otBindUdpSocket(otUdpSocket *aSocket, otSockAddr *aSockName);

/**
 * Send a UDP/IPv6 message.
 *
 * @param[in]  aSocket       A pointer to a UDP socket structure.
 * @param[in]  aMessage      A pointer to a message buffer.
 * @param[in]  aMessageInfo  A pointer to a message info structure.
 *
 * @sa otNewUdpMessage
 * @sa otOpenUdpSocket
 * @sa otCloseUdpSocket
 * @sa otBindUdpSocket
 * @sa otSendUdp
 */
ThreadError otSendUdp(otUdpSocket *aSocket, otMessage aMessage, const otMessageInfo *aMessageInfo);

/**
 * @}
 *
 */

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // OPENTHREAD_H_
