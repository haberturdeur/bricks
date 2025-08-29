#pragma once

#include "bricks/events.hpp"

#include <esp_event_base.h>
#include <esp_wifi_types_generic.h>
#include <esp_netif_types.h>

ESP_EVENT_DECLARE_BASE(WIFI_EVENT);
ESP_EVENT_DECLARE_BASE(IP_EVENT);

namespace bricks::events::idf {

namespace WiFi {

struct                             WifiReady {};                                   // WIFI_EVENT_WIFI_READY = 0,                            /**< Wi-Fi ready */
using                               ScanDone = wifi_event_sta_scan_done_t;         // WIFI_EVENT_SCAN_DONE,                                 /**< Finished scanning AP */
struct                              StaStart {};                                   // WIFI_EVENT_STA_START,                                 /**< Station start */
struct                               StaStop {};                                   // WIFI_EVENT_STA_STOP,                                  /**< Station stop */
using                           StaConnected = wifi_event_sta_connected_t;         // WIFI_EVENT_STA_CONNECTED,                             /**< Station connected to AP */
using                        StaDisconnected = wifi_event_sta_disconnected_t;      // WIFI_EVENT_STA_DISCONNECTED,                          /**< Station disconnected from AP */
using                      StaAuthmodeChange = wifi_event_sta_authmode_change_t;   // WIFI_EVENT_STA_AUTHMODE_CHANGE,                       /**< The auth mode of AP connected by device's station changed */
using                        StaWpsErSuccess = wifi_event_sta_wps_er_success_t;    // WIFI_EVENT_STA_WPS_ER_SUCCESS,                        /**< Station WPS succeeds in enrollee mode */
struct                        StaWpsErFailed {};                                   // WIFI_EVENT_STA_WPS_ER_FAILED,                         /**< Station WPS fails in enrollee mode */
struct                       StaWpsErTimeout {};                                   // WIFI_EVENT_STA_WPS_ER_TIMEOUT,                        /**< Station WPS timeout in enrollee mode */
using                            StaWpsErPin = wifi_event_sta_wps_er_pin_t;        // WIFI_EVENT_STA_WPS_ER_PIN,                            /**< Station WPS pin code in enrollee mode */
struct                    StaWpsErPbcOverlap {};                                   // WIFI_EVENT_STA_WPS_ER_PBC_OVERLAP,                    /**< Station WPS overlap in enrollee mode */
struct                               ApStart {};                                   // WIFI_EVENT_AP_START,                                  /**< Soft-AP start */
struct                                ApStop {};                                   // WIFI_EVENT_AP_STOP,                                   /**< Soft-AP stop */
using                         ApStaConnected = wifi_event_ap_staconnected_t;       // WIFI_EVENT_AP_STACONNECTED,                           /**< A station connected to Soft-AP */
using                      ApStaDisconnected = wifi_event_ap_stadisconnected_t;    // WIFI_EVENT_AP_STADISCONNECTED,                        /**< A station disconnected from Soft-AP */
using                       ApProbeReqRecved = wifi_event_ap_probe_req_rx_t;       // WIFI_EVENT_AP_PROBEREQRECVED,                         /**< Receive probe request packet in soft-AP interface */
using                              FtmReport = wifi_event_ftm_report_t;            // WIFI_EVENT_FTM_REPORT,                                /**< Receive report of FTM procedure */
using                          StaBssRssiLow = wifi_event_bss_rssi_low_t;          // WIFI_EVENT_STA_BSS_RSSI_LOW,                          /**< AP's RSSI crossed configured threshold */
using                         ActionTxStatus = wifi_event_action_tx_status_t;      // WIFI_EVENT_ACTION_TX_STATUS,                          /**< Status indication of Action Tx operation */
using                                RocDone = wifi_event_roc_done_t;              // WIFI_EVENT_ROC_DONE,                                  /**< Remain-on-Channel operation complete */
struct                      StaBeaconTimeout {};                                   // WIFI_EVENT_STA_BEACON_TIMEOUT,                        /**< Station beacon timeout */
struct ConnectionlessModuleWakeIntervalStart {};                                   // WIFI_EVENT_CONNECTIONLESS_MODULE_WAKE_INTERVAL_START, /**< Connectionless module wake interval start */
using                         ApWpsRgSuccess = wifi_event_ap_wps_rg_success_t;     // WIFI_EVENT_AP_WPS_RG_SUCCESS,                         /**< Soft-AP wps succeeds in registrar mode */
using                          ApWpsRgFailed = wifi_event_ap_wps_rg_fail_reason_t; // WIFI_EVENT_AP_WPS_RG_FAILED,                          /**< Soft-AP wps fails in registrar mode */
struct                        ApWpsRgTimeout {};                                   // WIFI_EVENT_AP_WPS_RG_TIMEOUT,                         /**< Soft-AP wps timeout in registrar mode */
using                             ApWpsRgPin = wifi_event_ap_wps_rg_pin_t;         // WIFI_EVENT_AP_WPS_RG_PIN,                             /**< Soft-AP wps pin code in registrar mode */
struct                     ApWpsRgPbcOverlap {};                                   // WIFI_EVENT_AP_WPS_RG_PBC_OVERLAP,                     /**< Soft-AP wps overlap in registrar mode */
struct                             ItwtSetup {};                                   // WIFI_EVENT_ITWT_SETUP,                                /**< iTWT setup */
struct                          ItwtTeardown {};                                   // WIFI_EVENT_ITWT_TEARDOWN,                             /**< iTWT teardown */
struct                             ItwtProbe {};                                   // WIFI_EVENT_ITWT_PROBE,                                /**< iTWT probe */
struct                           ItwtSuspend {};                                   // WIFI_EVENT_ITWT_SUSPEND,                              /**< iTWT suspend */
struct                             TwtWakeup {};                                   // WIFI_EVENT_TWT_WAKEUP,                                /**< TWT wakeup */
struct                             BtwtSetup {};                                   // WIFI_EVENT_BTWT_SETUP,                                /**< bTWT setup */
struct                          BtwtTeardown {};                                   // WIFI_EVENT_BTWT_TEARDOWN,                             /**< bTWT teardown*/
struct                            NanStarted {};                                   // WIFI_EVENT_NAN_STARTED,                               /**< NAN Discovery has started */
struct                            NanStopped {};                                   // WIFI_EVENT_NAN_STOPPED,                               /**< NAN Discovery has stopped */
using                            NanSvcMatch = wifi_event_nan_svc_match_t;         // WIFI_EVENT_NAN_SVC_MATCH,                             /**< NAN Service Discovery match found */
using                             NanReplied = wifi_event_nan_replied_t;           // WIFI_EVENT_NAN_REPLIED,                               /**< Replied to a NAN peer with Service Discovery match */
using                             NanReceive = wifi_event_nan_receive_t;           // WIFI_EVENT_NAN_RECEIVE,                               /**< Received a Follow-up message */
using                          NdpIndication = wifi_event_ndp_indication_t;        // WIFI_EVENT_NDP_INDICATION,                            /**< Received NDP Request from a NAN Peer */
using                             NdpConfirm = wifi_event_ndp_confirm_t;           // WIFI_EVENT_NDP_CONFIRM,                               /**< NDP Confirm Indication */
using                          NdpTerminated = wifi_event_ndp_terminated_t;        // WIFI_EVENT_NDP_TERMINATED,                            /**< NAN Datapath terminated indication */
using                      HomeChannelChange = wifi_event_home_channel_change_t;   // WIFI_EVENT_HOME_CHANNEL_CHANGE,                       /**< Wi-Fi home channel change，doesn't occur when scanning */
using                         StaNeighborRep = wifi_event_neighbor_report_t;       // WIFI_EVENT_STA_NEIGHBOR_REP,                          /**< Received Neighbor Report response */
using                        ApWrongPassword = wifi_event_ap_wrong_password_t;     // WIFI_EVENT_AP_WRONG_PASSWORD,                         /**< a station tried to connect with wrong password */

using Base = bricks::events::Base<
    WIFI_EVENT,
    WifiReady,
    ScanDone,
    StaStart,
    StaStop,
    StaConnected,
    StaDisconnected,
    StaAuthmodeChange,
    StaWpsErSuccess,
    StaWpsErFailed,
    StaWpsErTimeout,
    StaWpsErPin,
    StaWpsErPbcOverlap,
    ApStart,
    ApStop,
    ApStaConnected,
    ApStaDisconnected,
    ApProbeReqRecved,
    FtmReport,
    StaBssRssiLow,
    ActionTxStatus,
    RocDone,
    StaBeaconTimeout,
    ConnectionlessModuleWakeIntervalStart,
    ApWpsRgSuccess,
    ApWpsRgFailed,
    ApWpsRgTimeout,
    ApWpsRgPin,
    ApWpsRgPbcOverlap,
    ItwtSetup,
    ItwtTeardown,
    ItwtProbe,
    ItwtSuspend,
    TwtWakeup,
    BtwtSetup,
    BtwtTeardown,
    NanStarted,
    NanStopped,
    NanSvcMatch,
    NanReplied,
    NanReceive,
    NdpIndication,
    NdpConfirm,
    NdpTerminated,
    HomeChannelChange,
    StaNeighborRep,
    ApWrongPassword
>;

} // namespace WiFi

namespace IP {

using      StaGotIp = utils::Unique<ip_event_got_ip_t, IP_EVENT_STA_GOT_IP>; // IP_EVENT_STA_GOT_IP,               /*!< station got IP from connected AP */
struct    StaLostIp {};                                               // IP_EVENT_STA_LOST_IP,              /*!< station lost IP and the IP is reset to 0 */
using StaIpAssigned = ip_event_ap_staipassigned_t;                    // IP_EVENT_AP_STAIPASSIGNED,         /*!< soft-AP assign an IP to a connected station */
using        GotIp6 = ip_event_got_ip6_t;                             // IP_EVENT_GOT_IP6,                  /*!< station or ap or ethernet interface v6IP addr is preferred */
using      EthGotIp = utils::Unique<ip_event_got_ip_t, IP_EVENT_STA_GOT_IP>; // IP_EVENT_ETH_GOT_IP,               /*!< ethernet got IP from connected AP */
struct    EthLostIp {};                                               // IP_EVENT_ETH_LOST_IP,              /*!< ethernet lost IP and the IP is reset to 0 */
using      PppGotIp = utils::Unique<ip_event_got_ip_t, IP_EVENT_STA_GOT_IP>; // IP_EVENT_PPP_GOT_IP,               /*!< PPP interface got IP */
struct    PppLostIp {};                                               // IP_EVENT_PPP_LOST_IP,              /*!< PPP interface lost IP */
using          RxTx = ip_event_tx_rx_t;                               // IP_EVENT_TX_RX,                    /*!< transmitting/receiving data packet */

using NetifBase = Base<
    IP_EVENT,
    StaGotIp,      // IP_EVENT_STA_GOT_IP
    StaLostIp,     // IP_EVENT_STA_LOST_IP
    StaIpAssigned, // IP_EVENT_AP_STAIPASSIGNED
    GotIp6,        // IP_EVENT_GOT_IP6
    EthGotIp,      // IP_EVENT_ETH_GOT_IP (same payload as STA_GOT_IP)
    EthLostIp,     // IP_EVENT_ETH_LOST_IP
    PppGotIp,      // IP_EVENT_PPP_GOT_IP (same payload as STA_GOT_IP)
    PppLostIp,     // IP_EVENT_PPP_LOST_IP
    RxTx           // IP_EVENT_TX_RX
>;

} // namespace IP

} // namespace bricks::events::idf
