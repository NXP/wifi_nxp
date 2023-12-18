/**@file ncp_mcu_host_os.h
 *
 *  Copyright 2008-2023 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 * *  \brief OS Abstraction Layer
 *
 * The OS abstraction layer provides wrapper APIs over some of the
 * commonly used OS primitives. Since the behaviour and semantics of the various
 * OSes differs widely, some abstraction APIs require a specific handling as
 * listed below.
 *
 *
 * The OS abstraction layer provides the following types of primitives:
 *
 * - Thread: Create or delete a thread using os_thread_create() or
 *    os_thread_delete(). Block a thread using os_thread_sleep(). Complete a
 *    thread's execution using os_thread_self_complete().
 * - Message Queue: Create or delete a message queue using os_queue_create() or
 *    os_queue_delete(). Send a message using os_queue_send() and received a
 *    message using os_queue_recv().
 * - Mutex: Create or delete a mutex using os_mutex_create() or
 *    os_mutex_delete(). Acquire a mutex using os_mutex_get() and release it
 *    using os_mutex_put().
 * - Semaphores: Create or delete a semaphore using os_semaphore_create() or
 *    os_semaphore_delete. Acquire a semaphore
 *    using os_semaphore_get() and release it using os_semaphore_put().
 * - Dynamic Memory Allocation: Dynamically allocate memory using
 *    os_mem_alloc(), os_mem_calloc() or os_mem_realloc() and free it using
 *    os_mem_free().
 */

#ifndef __NCP_MCU_HOST_OS_H__
#define __NCP_MCU_HOST_OS_H__
#include "wifi_config.h"

#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#include "timers.h"

#include "ncp_mcu_host_utils.h"

#ifdef CONFIG_OS_DEBUG
#define os_dprintf(...) ll_log("[OS]" __VA_ARGS__)
#else
#define os_dprintf(...)
#endif

#define is_isr_context() (SCB->ICSR & SCB_ICSR_VECTACTIVE_Msk) //(xPortIsInsideInterrupt())

/*** Thread Management ***/
typedef void *os_thread_arg_t;

/**
 * Structure to be used during call to the function
 * os_thread_create(). Please use the macro \ref os_thread_stack_define
 * instead of using this structure directly.
 */
typedef struct os_thread_stack
{
    /** Total stack size */
    int size;
} os_thread_stack_t;

/**
 * Helper macro to define the stack size (in bytes) before a new thread is
 * created using the function os_thread_create().
 */
#define os_thread_stack_define(stackname, stacksize) \
    os_thread_stack_t stackname = {(stacksize) / (sizeof(portSTACK_TYPE))}

typedef xTaskHandle os_thread_t;

static inline const char *get_current_taskname()
{
    os_thread_t *handle = (os_thread_t *)xTaskGetCurrentTaskHandle();
    if (handle)
        return pcTaskGetTaskName(*handle);
    else
        return "Unknown";
}

/*** Tick function */
#define MAX_CUSTOM_HOOKS 4

/** Get current OS tick counter value
 *
 * \return 32 bit value of ticks since boot-up
 */
static inline unsigned os_ticks_get()
{
    if (is_isr_context())
        return xTaskGetTickCountFromISR();
    else
        return xTaskGetTickCount();
}

/** Create new thread
 *
 * This function starts a new thread.  The new thread starts execution by
 * invoking main_func(). The parameter arg is passed as the sole argument of
 * main_func().
 *
 * After finishing execution, the new thread should either call:
 * - os_thread_self_complete() to suspend itself OR
 * - os_thread_delete() to delete itself
 *
 * Failing to do this and just returning from main_func() will result in
 * undefined behavior.
 *
 *
 * @param[out] thandle Pointer to a thread handle
 * @param[in] name Name of the new thread. A copy of this string will be
 * made by the OS for itself. The maximum name length is defined by the
 * macro configMAX_TASK_NAME_LEN in FreeRTOS header file . Any name length
 * above it will be truncated.
 * @param[in] main_func Function pointer to new thread function
 * @param[in] arg The sole argument passed to main_func()
 * @param[in] stack A pointer to initialized object of type \ref
 * os_thread_stack_t. The object should be created and initialized using
 * os_thread_stack_define().
 * @param[in] prio The priority of the new thread. One value among
 * OS_PRIO_0, OS_PRIO_1, OS_PRIO_2, OS_PRIO_3 and OS_PRIO_4 should be
 * passed. OS_PRIO_0 represents the highest priority and OS_PRIO_4
 * represents the lowest priority.
 *
 * @return WM_SUCCESS if thread was created successfully
 * @return -WM_FAIL if thread creation failed
 */
static inline int os_thread_create(os_thread_t *thandle,
                                   const char *name,
                                   void (*main_func)(os_thread_arg_t arg),
                                   void *arg,
                                   os_thread_stack_t *stack,
                                   int prio)
{
    int ret;

    ret = xTaskCreate(main_func, name, stack->size, arg, prio, thandle);

    os_dprintf(
        " Thread Create: ret %d thandle %p"
        " stacksize = %d\r\n",
        ret, thandle ? *thandle : NULL, stack->size);
    return ret == pdPASS ? WM_SUCCESS : -WM_FAIL;
}

static inline os_thread_t os_get_current_task_handle()
{
    return xTaskGetCurrentTaskHandle();
}

/** Terminate a thread
 *
 * This function deletes a thread. The task being deleted will be removed from
 * all ready, blocked, suspended and event lists.
 *
 * @param[in] thandle Pointer to the thread handle of the thread to be
 * deleted. If self deletion is required NULL should be passed.
 *
 * @return WM_SUCCESS if operation success
 * @return -WM_FAIL if operation fails
 */
static inline int os_thread_delete(os_thread_t *thandle)
{
    if (thandle == NULL)
    {
        os_dprintf("OS: Thread Self Delete\r\n");
        vTaskDelete(NULL);
    }
    else
    {
        os_dprintf("OS: Thread Delete: %p\r\n", *thandle);
        vTaskDelete(*thandle);
    }

    *thandle = NULL;

    return WM_SUCCESS;
}

/** Sleep for specified number of OS ticks
 *
 * This function causes the calling thread to sleep and block for the given
 * number of OS ticks. The actual time that the task remains blocked depends on
 * the tick rate. The function os_msec_to_ticks() is provided to convert from
 * real-time to ticks.
 *
 * Any other thread can wake up this task specifically using the API
 * os_thread_wait_abort()
 *
 * @param[in] ticks Number of ticks to sleep
 *
 * @return 0 If slept for given ticks or more
 * @return Positive value if woken up before given ticks.
 * @note The value returned is amount of ticks left before the task was
 * to be originally scheduled to be woken up. So if sleep was for 10 ticks
 * and the task is woken up after 8 ticks then 2 will be returned.
 */
static inline void os_thread_sleep(int ticks)
{
    os_dprintf("OS: Thread Sleep: %d\r\n", ticks);
    vTaskDelay(ticks);
    return;
}

/** Convert milliseconds to OS ticks
 *
 * This function converts the given millisecond value to the number of OS
 * ticks.
 *
 * This is useful as functions like os_thread_sleep() accept only ticks
 * as input.
 *
 * @param[in] msecs Milliseconds
 *
 * @return Number of OS ticks corresponding to msecs
 */
/*! @brief Convert the milliseconds to ticks in FreeRTOS. */

static inline unsigned long os_msec_to_ticks(unsigned long msecs)
{
    return (msecs) / (portTICK_RATE_MS);
}

/** Convert ticks to milliseconds
 *
 * This function converts the given ticks value to milliseconds. This is useful
 * as some functions, like os_ticks_get(), return values in units of OS ticks.
 *
 * @param[in] ticks OS ticks
 *
 * @return Number of milliseconds corresponding to ticks
 */
static inline unsigned long os_ticks_to_msec(unsigned long ticks)
{
    return (ticks) * (portTICK_RATE_MS);
}

/** Suspend the given thread
 *
 * - The function os_thread_self_complete() will \b permanently suspend the
 * given thread. Passing NULL will suspend the current thread. This
 * function never returns.
 * - The thread continues to consume system resources. To delete the thread
 * the function os_thread_delete() needs to be called separately.
 *
 * @param[in] thandle Pointer to thread handle
 */
static inline void os_thread_self_complete(os_thread_t *thandle)
{
    /* Suspend self until someone calls delete. This is required because in
     * freeRTOS, main functions of a thread cannot return.
     */
    if (thandle != NULL)
    {
        os_dprintf("OS: Thread Complete: %p\r\n", *thandle);
        vTaskSuspend(*thandle);
    }
    else
    {
        os_dprintf("OS: Thread Complete: SELF\r\n");
        vTaskSuspend(NULL);
    }

    /*
     * We do not want this function to return ever.
     */
    while (1)
        os_thread_sleep(os_msec_to_ticks(60000));
}

#ifndef CONFIG_WIFI_MAX_PRIO
#error Define CONFIG_WIFI_MAX_PRIO in wifi_config.h
#elif CONFIG_WIFI_MAX_PRIO < 4
#error CONFIG_WIFI_MAX_PRIO must be defined to be greater than or equal to 4
#endif
#define OS_PRIO_0 CONFIG_WIFI_MAX_PRIO /** High **/
#define OS_PRIO_1 (CONFIG_WIFI_MAX_PRIO - 1)
#define OS_PRIO_2 (CONFIG_WIFI_MAX_PRIO - 2)
#define OS_PRIO_3 (CONFIG_WIFI_MAX_PRIO - 3)
#define OS_PRIO_4 (CONFIG_WIFI_MAX_PRIO - 4) /** Low **/

/** Structure used for queue definition */
typedef struct os_queue_pool
{
    /** Size of the queue */
    int size;
} os_queue_pool_t;

/** Define OS Queue pool
 *
 * This macro helps define the name and size of the queue to be created
 * using the function os_queue_create().
 */
#define os_queue_pool_define(poolname, poolsize) os_queue_pool_t poolname = {poolsize};

typedef xQueueHandle os_queue_t;

/** Create an OS queue
 *
 * This function creates a new queue instance. This allocates the storage
 * required by the new queue and returns a handle for the queue.
 *
 * @param[out] qhandle Pointer to the handle of the newly created queue
 * @param[in] name String specifying the name of the queue
 * @param[in] msgsize The number of bytes each item in the queue will
 * require. Items are queued by copy, not by reference, so this is the
 * number of bytes that will be copied for each posted item. Each item on
 * the queue must be the same size.
 * @param[in] poolname The object of the type \ref os_queue_pool_t. The
 * helper macro os_queue_pool_define() helps to define this object.
 *
 * @return WM_SUCCESS if queue creation was successful
 * @return -WM_FAIL if queue creation failed
 */
int os_queue_create(os_queue_t *qhandle, const char *name, int msgsize, os_queue_pool_t *poolname);

/** Wait Forever */
#define OS_WAIT_FOREVER portMAX_DELAY
/** Do Not Wait */
#define OS_NO_WAIT 0

/** Post an item to the back of the queue.
 *
 * This function posts an item to the back of a queue. The item is queued by
 * copy, not by reference. This function can also be called from an interrupt
 * service routine.
 *
 * @param[in] qhandle Pointer to the handle of the queue
 * @param[in] msg A pointer to the item that is to be placed on the
 * queue. The size of the items the queue will hold was defined when the
 * queue was created, so this many bytes will be copied from msg
 * into the queue storage area.
 * @param[in] wait The maximum amount of time, in OS ticks, the task should
 * block waiting for space to become available on the queue, should it already
 * be full. The function os_msec_to_ticks() can be used to convert from
 * real-time to OS ticks. The special values \ref OS_WAIT_FOREVER and \ref
 * OS_NO_WAIT are provided to respectively wait infinitely or return
 * immediately.
 *
 * @return WM_SUCCESS if send operation was successful
 * @return -WM_E_INVAL if invalid parameters are passed
 * @return -WM_FAIL if send operation failed
 */
static inline int os_queue_send(os_queue_t *qhandle, const void *msg, unsigned long wait)
{
    int ret;
    signed portBASE_TYPE xHigherPriorityTaskWoken = pdFALSE;
    if (!qhandle || !(*qhandle))
        return -WM_E_INVAL;

    os_dprintf("OS: Queue Send: handle %p, msg %p, wait %d\r\n", *qhandle, msg, wait);

    if (is_isr_context())
    {
        /* This call is from Cortex-M3 handler mode, i.e. exception
         * context, hence use FromISR FreeRTOS APIs.
         */
        ret = xQueueSendToBackFromISR(*qhandle, msg, &xHigherPriorityTaskWoken);
        portEND_SWITCHING_ISR(xHigherPriorityTaskWoken);
    }
    else
        ret = xQueueSendToBack(*qhandle, msg, wait);
    os_dprintf("OS: Queue Send: done\r\n");

    return ret == pdTRUE ? WM_SUCCESS : -WM_FAIL;
}

/** Receive an item from queue
 *
 * This function receives an item from a queue. The item is received by copy so
 * a buffer of adequate size must be provided. The number of bytes copied into
 * the buffer was defined when the queue was created.
 *
 * @param[in] qhandle Pointer to handle of the queue
 * @param[out] msg Pointer to the buffer into which the received item will
 * be copied. The size of the items in the queue was defined when the queue was
 * created. This pointer should point to a buffer as many bytes in size.
 * @param[in] wait The maximum amount of time, in OS ticks, the task should
 * block waiting for messages to arrive on the queue, should it already
 * be empty. The function os_msec_to_ticks() can be used to convert from
 * real-time to OS ticks. The special values \ref OS_WAIT_FOREVER and \ref
 * OS_NO_WAIT are provided to respectively wait infinitely or return
 * immediately.
 *
 * @return WM_SUCCESS if receive operation was successful
 * @return -WM_E_INVAL if invalid parameters are passed
 * @return -WM_FAIL if receive operation failed
 *
 * \note This function must not be used in an interrupt service routine.
 */

static inline int os_queue_recv(os_queue_t *qhandle, void *msg, unsigned long wait)
{
    int ret;
    if (!qhandle || !(*qhandle))
        return -WM_E_INVAL;

    os_dprintf("OS: Queue Receive: handle %p, msg %p, wait %d\r\n", *qhandle, msg, wait);
    ret = xQueueReceive(*qhandle, msg, wait);
    os_dprintf("OS: Queue Receive: done\r\n");
    return ret == pdTRUE ? WM_SUCCESS : -WM_FAIL;
}

/** Delete queue
 *
 * This function deletes a queue. It frees all the memory allocated for storing
 * of items placed on the queue.
 *
 * @param[in] qhandle Pointer to handle of the queue to be deleted.
 *
 * @return Currently always returns WM_SUCCESS
 */
static inline int os_queue_delete(os_queue_t *qhandle)
{
    os_dprintf("OS: Queue Delete: handle %p\r\n", *qhandle);

    vQueueDelete(*qhandle);
    // sem_debug_delete((const xSemaphoreHandle)*qhandle);
    *qhandle = NULL;

    return WM_SUCCESS;
}

/*** Tick function */
#define MAX_CUSTOM_HOOKS 4

/*** Mutex ***/
typedef xSemaphoreHandle os_mutex_t;

/** Priority Inheritance Enabled */
#define OS_MUTEX_INHERIT 1
/** Priority Inheritance Disabled */
#define OS_MUTEX_NO_INHERIT 0

/** Create mutex
 *
 * This function creates a mutex.
 *
 * @param [out] mhandle Pointer to a mutex handle
 * @param [in] name Name of the mutex
 * @param [in] flags Priority inheritance selection. Valid options are \ref
 * OS_MUTEX_INHERIT or \ref OS_MUTEX_NO_INHERIT.
 *
 * @note Currently non-inheritance in mutex is not supported.
 *
 * @return WM_SUCCESS on success
 * @return -WM_FAIL on error
 */
static inline int os_mutex_create(os_mutex_t *mhandle, const char *name, int flags)
{
    if (flags == OS_MUTEX_NO_INHERIT)
    {
        *mhandle = NULL;
        os_dprintf("Cannot create mutex for non-inheritance yet \r\n");
        return -WM_FAIL;
    }
    os_dprintf("OS: Mutex Create: name = %s \r\n", name);
    *mhandle = xSemaphoreCreateMutex();
    os_dprintf("OS: Mutex Create: handle = %p\r\n", *mhandle);
    if (*mhandle)
    {
        // sem_debug_add((const xQueueHandle)*mhandle,
        //	      name, 1);
        return WM_SUCCESS;
    }
    else
        return -WM_FAIL;
}

/** Acquire mutex
 *
 * This function acquires a mutex. Only one thread can acquire a mutex at any
 * given time. If already acquired the callers will be blocked for the specified
 * time duration.
 *
 * @param[in] mhandle Pointer to mutex handle
 * @param[in] wait The maximum amount of time, in OS ticks, the task should
 * block waiting for the mutex to be acquired. The function os_msec_to_ticks()
 * can be used to convert from real-time to OS ticks. The special values \ref
 * OS_WAIT_FOREVER and \ref OS_NO_WAIT are provided to respectively wait
 * infinitely or return immediately.
 *
 * @return WM_SUCCESS when mutex is acquired
 * @return -WM_E_INVAL if invalid parameters are passed
 * @return -WM_FAIL on failure
 */
static inline int os_mutex_get(os_mutex_t *mhandle, unsigned long wait)
{
    int ret;
    if (!mhandle || !(*mhandle))
        return -WM_E_INVAL;
    os_dprintf("OS: Mutex Get: handle %p\r\n", *mhandle);
    ret = xSemaphoreTake(*mhandle, wait);
    return ret == pdTRUE ? WM_SUCCESS : -WM_FAIL;
}

/** Release mutex
 *
 * This function releases a mutex previously acquired using os_mutex_get().
 *
 * @note The mutex should be released from the same thread context from which it
 * was acquired. If you wish to acquire and release in different contexts,
 * please use os_semaphore_get() and os_semaphore_put() variants.
 *
 * @param[in] mhandle Pointer to the mutex handle
 *
 * @return WM_SUCCESS when mutex is released
 * @return -WM_E_INVAL if invalid parameters are passed
 * @return -WM_FAIL on failure
 */
static inline int os_mutex_put(os_mutex_t *mhandle)
{
    int ret;

    if (!mhandle || !(*mhandle))
        return -WM_E_INVAL;

    os_dprintf("OS: Mutex Put: %p\r\n", *mhandle);

    ret = xSemaphoreGive(*mhandle);
    return ret == pdTRUE ? WM_SUCCESS : -WM_FAIL;
}

/** Delete mutex
 *
 * This function deletes a mutex.
 *
 * @param[in] mhandle Pointer to the mutex handle
 *
 * @note A mutex should not be deleted if other tasks are blocked on it.
 *
 * @return WM_SUCCESS on success
 */
static inline int os_mutex_delete(os_mutex_t *mhandle)
{
    vSemaphoreDelete(*mhandle);
    // sem_debug_delete((const xSemaphoreHandle)*mhandle);
    *mhandle = NULL;
    return WM_SUCCESS;
}

/*** Semaphore ***/

typedef xSemaphoreHandle os_semaphore_t;

/** Create binary semaphore
 *
 * This function creates a binary semaphore. A binary semaphore can be acquired
 * by only one entity at a given time.
 *
 * @param[out] mhandle Pointer to a semaphore handle
 * @param[in] name Name of the semaphore
 *
 * @return WM_SUCCESS on success
 * @return -WM_FAIL on error
 */
static inline int os_semaphore_create(os_semaphore_t *mhandle, const char *name)
{
    vSemaphoreCreateBinary(*mhandle);
    if (*mhandle)
    {
        // sem_debug_add((const xSemaphoreHandle)*mhandle,
        //	      name, 1);
        return WM_SUCCESS;
    }
    else
        return -WM_FAIL;
}

/** Acquire semaphore
 *
 * This function acquires a semaphore. At a given time, a binary semaphore can
 * be acquired only once, while a counting semaphore can be acquired as many as
 * 'count' number of times. Once this condition is reached, the other callers of
 * this function will be blocked for the specified time duration.
 *
 * @param[in] mhandle Pointer to a semaphore handle
 * @param[in] wait The maximum amount of time, in OS ticks, the task should
 * block waiting for the semaphore to be acquired. The function
 * os_msec_to_ticks() can be used to convert from real-time to OS ticks. The
 * special values \ref OS_WAIT_FOREVER and \ref OS_NO_WAIT are provided to
 * respectively wait infinitely or return immediately.
 *
 * @return WM_SUCCESS when semaphore is acquired
 * @return -WM_E_INVAL if invalid parameters are passed
 * @return -WM_FAIL on failure
 */
static inline int os_semaphore_get(os_semaphore_t *mhandle, unsigned long wait)
{
    int ret;
    signed portBASE_TYPE xHigherPriorityTaskWoken = pdFALSE;
    if (!mhandle || !(*mhandle))
        return -WM_E_INVAL;
    os_dprintf("OS: Semaphore Get: handle %p\r\n", *mhandle);
    if (is_isr_context())
    {
        /* This call is from Cortex-M3 handler mode, i.e. exception
         * context, hence use FromISR FreeRTOS APIs.
         */
        ret = xSemaphoreTakeFromISR(*mhandle, &xHigherPriorityTaskWoken);
        portEND_SWITCHING_ISR(xHigherPriorityTaskWoken);
    }
    else
        ret = xSemaphoreTake(*mhandle, wait);
    return ret == pdTRUE ? WM_SUCCESS : -WM_FAIL;
}

/** Release semaphore
 *
 * This function releases a semaphore previously acquired using
 * os_semaphore_get().
 *
 * @note This function can also be called from interrupt-context.
 *
 * @param[in] mhandle Pointer to a semaphore handle
 *
 * @return WM_SUCCESS when semaphore is released
 * @return -WM_E_INVAL if invalid parameters are passed
 * @return -WM_FAIL on failure
 */
static inline int os_semaphore_put(os_semaphore_t *mhandle)
{
    int ret;
    signed portBASE_TYPE xHigherPriorityTaskWoken = pdFALSE;
    if (!mhandle || !(*mhandle))
        return -WM_E_INVAL;

    os_dprintf("OS: Semaphore Put: handle %p\r\n", *mhandle);
    if (is_isr_context())
    {
        /* This call is from Cortex-M3 handler mode, i.e. exception
         * context, hence use FromISR FreeRTOS APIs.
         */
        ret = xSemaphoreGiveFromISR(*mhandle, &xHigherPriorityTaskWoken);
        portEND_SWITCHING_ISR(xHigherPriorityTaskWoken);
    }
    else
        ret = xSemaphoreGive(*mhandle);
    return ret == pdTRUE ? WM_SUCCESS : -WM_FAIL;
}

/* OS Memory allocation API's */
#ifndef CONFIG_HEAP_DEBUG

/** Allocate memory
 *
 * This function allocates memory dynamically.
 *
 *  @param[in] size Size of the memory to be allocated
 *
 * @return Pointer to the allocated memory
 * @return NULL if allocation fails
 */
#ifdef CONFIG_MEM_MONITOR_DEBUG
// extern int os_mem_alloc_cnt;
// extern void record_os_mem_alloc(uint32_t size, char const *func, uint32_t line_num);

static inline void *os_mem_alloc_priv(uint32_t size, char const *func, uint32_t line_num)
{
    void *ptr = pvPortMalloc(size);

    // os_mem_alloc_cnt++;
    // record_os_mem_alloc(size, func, line_num);

    return ptr;
}

#define os_mem_alloc(size) os_mem_alloc_priv((size), __func__, __LINE__)
#else
#define os_mem_alloc(size) pvPortMalloc(size)
#endif

/** Allocate memory and zero it
 *
 * This function allocates memory dynamically and sets the memory contents to
 * zero.
 *
 * @param[in] size Size of the memory to be allocated
 *
 * @return Pointer to the allocated memory
 * @return NULL if allocation fails
 */
static inline void *os_mem_calloc(size_t size)
{
    void *ptr = pvPortMalloc(size);
    if (ptr)
        (void)memset(ptr, 0x00, size);

    return ptr;
}
/** Free Memory
 *
 * This function frees dynamically allocated memory using any of the dynamic
 * allocation primitives.
 *
 * @param[in] ptr Pointer to the memory to be freed
 */
#ifdef CONFIG_MEM_MONITOR_DEBUG
// extern int os_mem_free_cnt;
// extern void record_os_mem_free(char const *func, uint32_t line_num);

static inline void os_mem_free_priv(void *ptr, char const *func, uint32_t line_num)
{
    vPortFree(ptr);

    // os_mem_free_cnt++;
    // record_os_mem_free(func, line_num);
}

#define os_mem_free(ptr) os_mem_free_priv((ptr), __func__, __LINE__)

#else
#define os_mem_free(ptr) vPortFree(ptr)
#endif

#else  /* ! CONFIG_HEAP_DEBUG */
static inline void *os_mem_alloc(size_t size) WARN_UNUSED_RET;
static inline void *os_mem_calloc(size_t size) WARN_UNUSED_RET;
static inline void *os_mem_realloc(void *ptr, size_t size) WARN_UNUSED_RET;

/** This function allocates memory dynamically
 *  @param [in] size Size of memory to be allocated
 *
 *  @return Pointer to the allocated memory
 *  @return NULL if allocation fails
 */
static inline void *os_mem_alloc(size_t size)
{
    void *ptr = pvPortMalloc(size);
    if (ptr)
        (void)PRINTF("MDC:A:%x:%d\r\n", ptr, size);
    return ptr;
}
/** This function allocates memory dynamically and
 *  sets memory content to zero
 *  @param [in] size Size of memory to be allocated
 *
 *  @return Pointer to the allocated memory
 *  @return NULL if allocation fails
 */
static inline void *os_mem_calloc(size_t size)
{
    void *ptr = pvPortMalloc(size);
    if (ptr)
    {
        (void)PRINTF("MDC:A:%x:%d\r\n", ptr, size);
        (void)memset(ptr, 0x00, size);
    }

    return ptr;
}

/**This function attempts to resize the memory block pointed to by
 *  ptr that was previously allocated with a call to os_mem_alloc()
 *  or os_mem_calloc()
 * @param [in] ptr  Pointer to earlier alocated memory
 * @param [in] size New size
 *
 * @return Pointer to the newly resized memory block
 * @return NULL if reallocation fails
 */
static inline void *os_mem_realloc(void *ptr, size_t size)
{
    void *new_ptr = pvPortReAlloc(ptr, size);
    if (new_ptr)
        (void)PRINTF("MDC:R:%x:%x:%d\r\n", ptr, new_ptr, size);

    return new_ptr;
}
/** This function frees dynamically allocated memory
 *  @param [in] ptr Pointer to memory to be freed
 */
static inline void os_mem_free(void *ptr)
{
    vPortFree(ptr);
    (void)PRINTF("MDC:F:%x\r\n", ptr);
}
#endif /* CONFIG_HEAP_DEBUG */

/*** Event Notification ***/

/**
 * Wait for task notification
 *
 * This function waits for task notification from other task or interrupt
 * context. This is similar to binary semaphore, but uses less RAM and much
 * faster than semaphore mechanism
 *
 * @param[in] wait_time Timeout specified in no. of OS ticks
 *
 * @return WM_SUCCESS when notification is successful
 * @return -WM_FAIL on failure or timeout
 */
static inline int os_event_notify_get(unsigned long wait_time)
{
    int ret = ulTaskNotifyTake(pdTRUE, wait_time);
    return ret == pdTRUE ? WM_SUCCESS : -WM_FAIL;
}

/**
 * Give task notification
 *
 * This function gives task notification so that waiting task can be
 * unblocked. This is similar to binary semaphore, but uses less RAM and much
 * faster than semaphore mechanism
 *
 * @param[in] task Task handle to be notified
 *
 * @return WM_SUCCESS when notification is successful
 * @return -WM_FAIL on failure or timeout
 */
static inline int os_event_notify_put(os_thread_t task)
{
    int ret                                       = pdTRUE;
    signed portBASE_TYPE xHigherPriorityTaskWoken = pdFALSE;

    if (!task)
        return -WM_E_INVAL;
    if (is_isr_context())
    {
        /* This call is from Cortex-M3/4 handler mode, i.e. exception
         * context, hence use FromISR FreeRTOS APIs.
         */
        vTaskNotifyGiveFromISR(task, &xHigherPriorityTaskWoken);
        portEND_SWITCHING_ISR(xHigherPriorityTaskWoken);
    }
    else
    {
        ret = xTaskNotifyGive(task);
    }

    return ret == pdTRUE ? WM_SUCCESS : -WM_FAIL;
}

#endif /*__NCP_MCU_HOST_OS_H__ */
