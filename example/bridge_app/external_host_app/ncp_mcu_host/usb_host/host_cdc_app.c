/*
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 - 2017,2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "usb_host_config.h"
#include "usb_host.h"
#include "fsl_device_registers.h"
#include "usb_host_cdc.h"
#include "fsl_debug_console.h"
#include "host_cdc.h"
#include "fsl_adapter_timer.h"
#include "usb_phy.h"
#include "fsl_common.h"
#include "board.h"
//#include "fsl_adapter_timer.h"
#if (defined(FSL_FEATURE_SOC_SYSMPU_COUNT) && (FSL_FEATURE_SOC_SYSMPU_COUNT > 0U))
#include "fsl_sysmpu.h"
#endif /* FSL_FEATURE_SOC_SYSMPU_COUNT */
#include "host_cdc_app.h"
#include "fsl_component_serial_manager.h"
#if ((!USB_HOST_CONFIG_KHCI) && (!USB_HOST_CONFIG_EHCI) && (!USB_HOST_CONFIG_OHCI) && (!USB_HOST_CONFIG_IP3516HS))
#error Please enable USB_HOST_CONFIG_KHCI, USB_HOST_CONFIG_EHCI, USB_HOST_CONFIG_OHCI, or USB_HOST_CONFIG_IP3516HS in file usb_host_config.
#endif
#include "ncp_mcu_host_os.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*******************************************************************************
 * Prototypes
 ******************************************************************************/
extern void USB_HostClockInit(void);
extern void USB_HostIsrEnable(void);
extern void USB_HostTaskFn(void *param);
void BOARD_InitHardware(void);
extern void UART_UserRxCallback(void *callbackParam,
                                serial_manager_callback_message_t *message,
                                serial_manager_status_t status);
extern void UART_UserTxCallback(void *callbackParam,
                                serial_manager_callback_message_t *message,
                                serial_manager_status_t status);
/*******************************************************************************
 * Variables
 ******************************************************************************/
/* Allocate the memory for the heap. */
#if defined(configAPPLICATION_ALLOCATED_HEAP) && (configAPPLICATION_ALLOCATED_HEAP)
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) uint8_t ucHeap[configTOTAL_HEAP_SIZE];
#endif
usb_host_handle g_hostHandle;
volatile uint8_t g_AttachFlag;
serial_write_handle_t g_UartTxHandle;
serial_write_handle_t g_UartRxHandle;

extern char usbRecvUart[USB_HOST_CDC_UART_RX_MAX_LEN];

#ifdef CONFIG_USB_BRIDGE
extern void usb_recv_task(void *param);
#endif
TaskHandle_t app_task_thread;
uint32_t g_halTimerHandle[(HAL_TIMER_HANDLE_SIZE + 3) / 4];
static uint32_t systemTickControl;

/*******************************************************************************
 * Code
 ******************************************************************************/

void USB_ControllerSuspended(void)
{

}

/*!
 * @brief USB isr function.
 */

/*!
 * @brief host callback function.
 *
 * device attach/detach callback function.
 *
 * @param deviceHandle           device handle.
 * @param configurationHandle attached device's configuration descriptor information.
 * @param event_code           callback event code, please reference to enumeration host_event_t.
 *
 * @retval kStatus_USB_Success              The host is initialized successfully.
 * @retval kStatus_USB_NotSupported         The application don't support the configuration.
 */
usb_status_t USB_HostEvent(usb_device_handle deviceHandle,
                           usb_host_configuration_handle configurationHandle,
                           uint32_t event_code)
{
    usb_status_t status;
    status = kStatus_USB_Success;

    switch (event_code & 0x0000FFFFU)
    {
        case kUSB_HostEventAttach:
            status = USB_HostCdcEvent(deviceHandle, configurationHandle, event_code);
            break;
        case kUSB_HostEventNotSupported:
            usb_echo("device not supported.\r\n");
            break;

        case kUSB_HostEventEnumerationDone:
            status = USB_HostCdcEvent(deviceHandle, configurationHandle, event_code);
            break;

        case kUSB_HostEventDetach:
            status = USB_HostCdcEvent(deviceHandle, configurationHandle, event_code);
            break;

        case kUSB_HostEventEnumerationFail:
            usb_echo("enumeration failed\r\n");
            break;

        case kUSB_HostEventNotSuspended:
            if (kStatus_Idle != g_cdc.suspendResumeState)
            {
                if (g_cdc.suspendBus)
                {
                    usb_echo("Suspend BUS failed.\r\n");
                }
                else
                {
                    usb_echo("Suspend device failed.\r\n");
                }
            }
            g_cdc.suspendResumeState = kStatus_Idle;
            break;
        case kUSB_HostEventSuspended:
            if (kStatus_Idle != g_cdc.suspendResumeState)
            {
                USB_ControllerSuspended();
                g_cdc.suspendResumeState = kStatus_Suspended;
            }
            else
            {
                g_cdc.suspendResumeState = kStatus_Idle;
            }
            break;
        case kUSB_HostEventDetectResume:
            if (kStatus_Idle != g_cdc.suspendResumeState)
            {
            }
            break;
        case kUSB_HostEventResumed:
            if (kStatus_Idle != g_cdc.suspendResumeState)
            {
                if (g_cdc.suspendBus)
                {
                    usb_echo("BUS has been resumed.\r\n");
                }
                else
                {
                    usb_echo("Device has been resumed.\r\n");
                }
            }
            g_cdc.suspendResumeState = kStatus_Idle;
            break;

        default:
            break;
    }
    os_event_notify_put((os_thread_t)app_task_thread);

    return status;
}

usb_status_t USB_HostControlRemoteWakeup(usb_host_handle hostHandle,
                                         usb_device_handle deviceHandle,
                                         host_inner_transfer_callback_t callbackFn,
                                         void *callbackParam,
                                         uint8_t enable)
{
    usb_host_transfer_t *transfer;
    uint32_t infoValue = 0U;

    if (hostHandle == NULL)
    {
        return kStatus_USB_InvalidHandle;
    }

    /* malloc one transfer */
    if (USB_HostMallocTransfer(hostHandle, &transfer) != kStatus_USB_Success)
    {
#ifdef HOST_ECHO
        usb_echo("error to get transfer\r\n");
#endif
        return kStatus_USB_Busy;
    }
    /* initialize transfer */
    transfer->transferBuffer = NULL;
    transfer->transferLength = 0;
    transfer->callbackFn     = callbackFn;
    transfer->callbackParam  = callbackParam;
    transfer->setupPacket->bmRequestType =
        USB_REQUEST_TYPE_RECIPIENT_DEVICE | USB_REQUEST_TYPE_DIR_OUT | USB_REQUEST_TYPE_TYPE_STANDARD;
    transfer->setupPacket->bRequest = (enable ? USB_REQUEST_STANDARD_SET_FEATURE : USB_REQUEST_STANDARD_CLEAR_FEATURE);
    transfer->setupPacket->wValue =
        USB_SHORT_TO_LITTLE_ENDIAN(USB_REQUEST_STANDARD_FEATURE_SELECTOR_DEVICE_REMOTE_WAKEUP);
    transfer->setupPacket->wIndex  = USB_SHORT_TO_LITTLE_ENDIAN(0x00U);
    transfer->setupPacket->wLength = USB_SHORT_TO_LITTLE_ENDIAN(0x00U);

    USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDeviceControlPipe, &infoValue);

    if (USB_HostSendSetup(hostHandle, (usb_host_pipe_handle)infoValue, transfer) !=
        kStatus_USB_Success) /* call host driver api */
    {
#ifdef HOST_ECHO
        usb_echo("failed for USB_HostControlRemoteWakeup\r\n");
#endif
        USB_HostFreeTransfer(hostHandle, transfer);
        return kStatus_USB_Error;
    }
    return kStatus_USB_Success;
}

static void USB_HostRemoteWarkupCallback(void *param, usb_host_transfer_t *transfer, usb_status_t status)
{
    if (NULL == param)
    {
        return;
    }
    USB_HostFreeTransfer(param, transfer);

    if (kStatus_USB_Success == status)
    {
        if (kStatus_SuspendWaitClearRemoteWakeup == g_cdc.suspendResumeState)
        {
            usb_echo("Remote wakeup feature cleared.\r\n");
            g_cdc.isSetRemoteWakeup  = 0U;
            g_cdc.suspendResumeState = kStatus_Suspending;
        }
        else if (kStatus_SuspendWaitSetRemoteWakeup == g_cdc.suspendResumeState)
        {
            usb_echo("Remote wakeup feature set.\r\n");
            g_cdc.isSetRemoteWakeup  = 1U;
            g_cdc.suspendResumeState = kStatus_Suspending;
        }
        else
        {
        }
    }
    else
    {
        g_cdc.suspendResumeState = kStatus_SuspendFailRemoteWakeup;
        usb_echo(
            "\tSend clear remote wakeup feature request failed. \r\nWhether need to continue? "
            "Please ENTER y(es) or n(o): ");
    }
}

void HW_TimerCallback(void *param)
{
    g_cdc.hwTick++;
    USB_HostUpdateHwTick(g_hostHandle, g_cdc.hwTick);
}

void HW_TimerInit(void)
{
    hal_timer_config_t halTimerConfig;
    halTimerConfig.timeout            = 1000U;
    halTimerConfig.srcClock_Hz        = CLOCK_GetCoreSysClkFreq();
    halTimerConfig.instance           = 0U;
    hal_timer_handle_t halTimerHandle = &g_halTimerHandle[0];
    HAL_TimerInit(halTimerHandle, &halTimerConfig);
    HAL_TimerInstallCallback(halTimerHandle, HW_TimerCallback, NULL);
}

void HW_TimerControl(uint8_t enable)
{
    if (enable)
    {
        HAL_TimerEnable(g_halTimerHandle);
    }
    else
    {
        HAL_TimerDisable(g_halTimerHandle);
    }
}

void USB_LowpowerModeInit(void)
{
    HW_TimerInit();
}

void USB_PreLowpowerMode(void)
{
    if (SysTick->CTRL & SysTick_CTRL_ENABLE_Msk)
    {
        systemTickControl = SysTick->CTRL;
        SysTick->CTRL &= ~SysTick_CTRL_TICKINT_Msk;
    }
}

void USB_PostLowpowerMode(void)
{
    SysTick->CTRL = systemTickControl;
}

void USB_PowerPreSwitchHook(void)
{
    HW_TimerControl(0U);

    USB_PreLowpowerMode();
}

void USB_PowerPostSwitchHook(void)
{
    USB_PostLowpowerMode();
    HW_TimerControl(1U);
}

extern uint8_t usb_enter_pm2;

void usb_host_pm_task(void)
{
    usb_status_t usb_error;

    switch (g_cdc.suspendResumeState)
    {
        case kStatus_Idle:
            if (1 == usb_enter_pm2)
            {
                g_cdc.suspendResumeState = kStatus_SartSuspend;
                usb_echo("Start suspend USB BUS...\r\n");
            }

            break;
        case kStatus_SartSuspend:
            g_cdc.suspendBus = 1;
            if (g_cdc.supportRemoteWakeup)
            {
                usb_echo("\r\nIf you want to wakeup device.Please Enter: wlan-usb-pm-cfg 2\r\n");
                g_cdc.suspendResumeState = kStatus_SuspendSetRemoteWakeup;
            }
            break;
        case kStatus_SuspendSetRemoteWakeup:
            usb_error = USB_HostControlRemoteWakeup(g_hostHandle, g_cdc.deviceHandle, USB_HostRemoteWarkupCallback,
                                                    g_hostHandle, 1);
            if (kStatus_USB_Success == usb_error)
            {
                g_cdc.suspendResumeState = kStatus_SuspendWaitSetRemoteWakeup;
            }
            else
            {
                g_cdc.suspendResumeState = kStatus_SuspendFailRemoteWakeup;
                usb_echo("\tSend set remote wakeup feature request failed.");
            }

            break;
        case kStatus_SuspendWaitSetRemoteWakeup:
        case kStatus_SuspendWaitClearRemoteWakeup:
            break;
        case kStatus_SuspendFailRemoteWakeup:
            g_cdc.suspendResumeState = kStatus_Idle;
            break;
        case kStatus_Suspending:
            g_cdc.suspendResumeState = kStatus_SuspendRequest;
            if (kStatus_USB_Success ==
                USB_HostSuspendDeviceResquest(g_hostHandle, g_cdc.suspendBus ? NULL : g_cdc.deviceHandle))
            {
            }
            else
            {
                usb_echo("Send suspend request failed.\r\n");
                g_cdc.suspendResumeState = kStatus_Idle;
            }
            break;
        case kStatus_SuspendRequest:
            break;
        case kStatus_Suspended:
            if (g_cdc.suspendBus)
            {
                usb_echo("BUS has been suspended.\r\n");
            }
            else
            {
                usb_echo("Device has been suspended.\r\n");
            }

            /*flush the output befor enter lowpower*/

            USB_PowerPreSwitchHook();

            g_cdc.suspendResumeState = kStatus_WaitResume;

            USB_PowerPostSwitchHook();

            break;
        case kStatus_WaitResume:
            if (2 == usb_enter_pm2)
            {
                usb_echo("Start resume the device.\r\n");
                g_cdc.suspendResumeState = kStatus_ResumeRequest;
                if (kStatus_USB_Success ==
                    USB_HostResumeDeviceResquest(g_hostHandle, g_cdc.suspendBus ? NULL : g_cdc.deviceHandle))
                {
                }
                else
                {
                    g_cdc.suspendResumeState = kStatus_Idle;
                    usb_echo("Send resume signal failed.\r\n");
                }
            }
            break;
        case kStatus_ResumeRequest:
            break;
        default:
            break;
    }

    usb_enter_pm2 = 0;
}

void USB_OTG1_IRQHandler(void)
{
    USB_HostEhciIsrFunction(g_hostHandle);
}

void USB_OTG2_IRQHandler(void)
{
    USB_HostEhciIsrFunction(g_hostHandle);
}

void USB_HostClockInit(void)
{
    usb_phy_config_struct_t phyConfig = {
        BOARD_USB_PHY_D_CAL,
        BOARD_USB_PHY_TXCAL45DP,
        BOARD_USB_PHY_TXCAL45DM,
    };

    if (CONTROLLER_ID == kUSB_ControllerEhci0)
    {
        CLOCK_EnableUsbhs0PhyPllClock(kCLOCK_Usbphy480M, 480000000U);
        CLOCK_EnableUsbhs0Clock(kCLOCK_Usb480M, 480000000U);
    }
    else
    {
        CLOCK_EnableUsbhs1PhyPllClock(kCLOCK_Usbphy480M, 480000000U);
        CLOCK_EnableUsbhs1Clock(kCLOCK_Usb480M, 480000000U);
    }
    USB_EhciPhyInit(CONTROLLER_ID, BOARD_XTAL0_CLK_HZ, &phyConfig);
}

void USB_HostIsrEnable(void)
{
    uint8_t irqNumber;

    uint8_t usbHOSTEhciIrq[] = USBHS_IRQS;
    irqNumber                = usbHOSTEhciIrq[CONTROLLER_ID - kUSB_ControllerEhci0];
/* USB_HOST_CONFIG_EHCI */

/* Install isr, set priority, and enable IRQ. */
#if defined(__GIC_PRIO_BITS)
    GIC_SetPriority((IRQn_Type)irqNumber, USB_HOST_INTERRUPT_PRIORITY);
#else
    NVIC_SetPriority((IRQn_Type)irqNumber, USB_HOST_INTERRUPT_PRIORITY);
#endif
    EnableIRQ((IRQn_Type)irqNumber);
}

void USB_HostTaskFn(void *param)
{
    USB_HostEhciTaskFunction(param);
}

static void usb_pm_task(void *param)
{
    while (1)
    {
        usb_host_pm_task();
        vTaskDelay(1);
    }
}

/*!
 * @brief app initialization.
 */
void APP_init(void)
{
    status_t status = (status_t)kStatus_SerialManager_Error;
    /*
     g_UartTxHandle  = (serial_write_handle_t)&s_serialWriteHandleBuffer[0];
     g_UartRxHandle  = (serial_read_handle_t)&s_serialReadHandleBuffer[0];
     status          = (status_t)SerialManager_OpenWriteHandle(g_serialHandle, g_UartTxHandle);
     assert(kStatus_SerialManager_Success == status);
     (void)SerialManager_InstallTxCallback(g_UartTxHandle, UART_UserTxCallback, &g_UartTxHandle);

     status = (status_t)SerialManager_OpenReadHandle(g_serialHandle, g_UartRxHandle);
     assert(kStatus_SerialManager_Success == status);
     (void)SerialManager_InstallRxCallback(g_UartRxHandle, UART_UserRxCallback, &g_UartRxHandle);

     SerialManager_ReadNonBlocking(g_UartRxHandle, (uint8_t *)&usbRecvUart[0], USB_HOST_CDC_UART_RX_MAX_LEN);
 */
    g_AttachFlag = 0;

    USB_HostCdcInitBuffer();

    USB_HostClockInit();

#if ((defined FSL_FEATURE_SOC_SYSMPU_COUNT) && (FSL_FEATURE_SOC_SYSMPU_COUNT))
    SYSMPU_Enable(SYSMPU, 0);
#endif /* FSL_FEATURE_SOC_SYSMPU_COUNT */

    status = USB_HostInit(CONTROLLER_ID, &g_hostHandle, USB_HostEvent);
    if (status != kStatus_USB_Success)
    {
        usb_echo("host init error\r\n");
        return;
    }
    USB_HostIsrEnable();

    usb_echo("host init done\r\n");
    usb_echo("This example requires that the CDC device uses Hardware flow\r\n");
    usb_echo(
        "if the device does't support it, please set USB_HOST_UART_SUPPORT_HW_FLOW to zero and rebuild this "
        "project\r\n");
    usb_echo("Type strings, then the string\r\n");
    usb_echo("will be echoed back from the device\r\n");
}

/*Recv irq data and status*/
void usb_host_task(void *hostHandle)
{
    while (1)
    {
        USB_HostTaskFn(hostHandle);
    }
}

/*Monitor HW interface status*/
void app_task(void *param)
{
#if ((defined(USB_HOST_CONFIG_LOW_POWER_MODE)) && (USB_HOST_CONFIG_LOW_POWER_MODE > 0U))
    USB_LowpowerModeInit();
#endif

    APP_init();

#if ((defined(USB_HOST_CONFIG_LOW_POWER_MODE)) && (USB_HOST_CONFIG_LOW_POWER_MODE > 0U))
    HW_TimerControl(1);
#endif

    if (xTaskCreate(usb_host_task, "usb host task", 2000L / sizeof(portSTACK_TYPE), g_hostHandle, OS_PRIO_2, NULL) !=
        pdPASS)
    {
        usb_echo("create host task error\r\n");
    }

    while (1)
    {
        USB_HostCdcTask(&g_cdc);
    }
}

int usb_host_init(void)
{
    if (xTaskCreate(app_task, "usb app task", 2000L / sizeof(portSTACK_TYPE), NULL, OS_PRIO_3, &app_task_thread) !=
        pdPASS)
    {
        usb_echo("create cdc task error\r\n");

        return -1;
    }

#ifdef CONFIG_USB_BRIDGE
    if (xTaskCreate(usb_recv_task, "usb recv task", 2000L / sizeof(portSTACK_TYPE), NULL, OS_PRIO_2, NULL) != pdPASS)
    {
        usb_echo("create usb recv task task error\r\n");

        return -1;
    }
#endif

    if (xTaskCreate(usb_pm_task, "usb pm task", 2000L / sizeof(portSTACK_TYPE), &g_cdc, OS_PRIO_2, NULL) != pdPASS)
    {
        usb_echo("usb host suspend/resume task create failed!\r\n");
        return -1;
    }

    return 0;
}
