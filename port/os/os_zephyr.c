/** @file os.c
 *
 *  @brief OS interaction API
 *
 *  Copyright 2008-2022 NXP
 *
 *  NXP CONFIDENTIAL
 *  The source code contained or described herein and all documents related to
 *  the source code ("Materials") are owned by NXP, its
 *  suppliers and/or its licensors. Title to the Materials remains with NXP,
 *  its suppliers and/or its licensors. The Materials contain
 *  trade secrets and proprietary and confidential information of NXP, its
 *  suppliers and/or its licensors. The Materials are protected by worldwide copyright
 *  and trade secret laws and treaty provisions. No part of the Materials may be
 *  used, copied, reproduced, modified, published, uploaded, posted,
 *  transmitted, distributed, or disclosed in any way without NXP's prior
 *  express written permission.
 *
 *  No license under any patent, copyright, trade secret or other intellectual
 *  property right is granted to or conferred upon you by disclosure or delivery
 *  of the Materials, either expressly, by implication, inducement, estoppel or
 *  otherwise. Any license under such intellectual property rights must be
 *  express and approved by NXP in writing.
 *
 */
#include <zephyr/init.h>
#include <inttypes.h>
#include <stdio.h>
#include <wm_os.h>
#include <wmlog.h>

#define mainTEST_TASK_PRIORITY (tskIDLE_PRIORITY)
#define mainTEST_DELAY         (400 / portTICK_RATE_MS)


/* Freertos handles this internally? */
void os_thread_stackmark(char *name)
{
    /* Nothing to-do */
}

typedef struct event_wait_t
{
    /* parameter passed in the event get call */
    unsigned thread_mask;
    /* The 'get' thread will wait on this sem */
    os_semaphore_t sem;
    struct event_wait_t *next;
    struct event_wait_t *prev;
} event_wait_t;

typedef struct event_group_t
{
    /* Main event flags will be stored here */
    unsigned flags;
    /* This flag is used to indicate deletion
     * of event group */
    bool delete_group;
    /* to protect this structure and the waiting list */
    os_mutex_t mutex;
    event_wait_t *list;
} event_group_t;


int os_thread_create(os_thread_t *thandle,
                                   const char *name,
                                   void (*main_func)(os_thread_arg_t arg),
                                   void *arg,
                                   os_thread_stack_t *stack,
                                   int prio)
{
    struct zep_thread *thread = NULL;

    thread = os_mem_alloc(sizeof(struct zep_thread));
    if (thread == NULL) {
        printk("OS: Thread Alloc fail name %s\r\n", name);
	return -WM_FAIL;
    }
    thread->id = k_thread_create(&stack->thread, stack->stack,
        stack->size, thread_wrapper, main_func, arg, thread, prio, 0, K_NO_WAIT);
    k_thread_name_set(thread->id, name);
    k_sem_init(&thread->event, 0, 1);

    *thandle = thread;
    return WM_SUCCESS;
}


int os_thread_delete(os_thread_t *thandle)
{
    if (thandle == NULL)
    {
        os_dprintf("OS: Thread Self Delete\r\n");
        os_mem_free(*thandle);
        return 0;
    }
    else
    {
        os_dprintf("OS: Thread Delete: %p\r\n", thandle);
        k_thread_abort((*thandle)->id);
        os_mem_free(*thandle);
    }

    return WM_SUCCESS;
}

/* Memory allocation OSA layer. Based on Zephyr's libc malloc implementation. */
#define HEAP_BYTES CONFIG_WIFI_NET_HEAP_SIZE

//static struct sys_heap osa_malloc_heap;
//struct k_mutex osa_malloc_heap_mutex;
//static char osa_malloc_heap_mem[HEAP_BYTES];

void* os_mem_alloc(size_t size)
{
#if 0
    int lock_ret;

    lock_ret = k_mutex_lock(&osa_malloc_heap_mutex, K_FOREVER);
    __ASSERT_NO_MSG(lock_ret == 0);

    void *ptr = sys_heap_aligned_alloc(&osa_malloc_heap, __alignof__(z_max_align_t), size);
    if (ptr == NULL && size != 0) {
    	errno = ENOMEM;
    }

    (void)k_mutex_unlock(&osa_malloc_heap_mutex);
    return ptr;
#endif
    return k_malloc(size);
}

void *os_mem_calloc(size_t size)
{
    void *ptr = os_mem_alloc(size);
    if (ptr == NULL && size != 0) {
	return NULL;
    }
    memset(ptr, 0, size);
    return ptr;
}

void *os_mem_realloc(void *old_ptr, size_t new_size)
{
#if 0
    int lock_ret;

    lock_ret = k_mutex_lock(&osa_malloc_heap_mutex, K_FOREVER);
    __ASSERT_NO_MSG(lock_ret == 0);
    void *ptr = sys_heap_aligned_realloc(&osa_malloc_heap, old_ptr,
        __alignof__(z_max_align_t), new_size);
    if (ptr == NULL && new_size != 0) {
	return NULL;
    }

    (void)k_mutex_unlock(&osa_malloc_heap_mutex);
    return ptr;
#endif
    void *p;

    if (new_size == 0)
    {
        os_mem_free(old_ptr);
        return NULL;
    }

    if (old_ptr == NULL)
    {
        return os_mem_alloc(new_size);
    }

    p = os_mem_calloc(new_size);

    if (p)
    {
        if (old_ptr != NULL)
        {
            memcpy(p, old_ptr, new_size);
            os_mem_free(old_ptr);
        }
    }

    return p;
}

void os_mem_free(void *ptr)
{
#if 0
    int lock_ret;

    lock_ret = k_mutex_lock(&osa_malloc_heap_mutex, K_FOREVER);
    __ASSERT_NO_MSG(lock_ret == 0);
    sys_heap_free(&osa_malloc_heap, ptr);
    (void)k_mutex_unlock(&osa_malloc_heap_mutex);
#endif
    k_free(ptr);
}

/* Prepares OSA layer, by setting up heap */
static int osa_prepare(const struct device *unused)
{
    ARG_UNUSED(unused);

//    sys_heap_init(&osa_malloc_heap, osa_malloc_heap_mem, HEAP_BYTES);
//    k_mutex_init(&osa_malloc_heap_mutex);
    return 0;
}

SYS_INIT(osa_prepare, POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);

/* Used to convert 3 argument zephyr threads to one arg OSA threads */
void thread_wrapper(void *entry, void* arg, void* tdata)
{
    /* Save thread data */
    k_thread_custom_data_set(tdata);
    void (*func)(void*) = entry;
    func(arg);
}

/*** Message Queue ***/
int os_queue_create(os_queue_t *qhandle, const char *name, int msgsize, os_queue_pool_t *poolname)
{
    struct k_msgq *msgq = NULL;

    msgq = os_mem_alloc(sizeof(struct k_msgq));
    if (msgq == NULL)
    {
        printk("OS: MsgQueue Alloc fail name %s\r\n", name);
        return -WM_FAIL;
    }

	k_msgq_init(msgq, poolname->buffer, msgsize, poolname->size / msgsize);
	*qhandle = msgq;
	return WM_SUCCESS;
}

int os_queue_send(os_queue_t *qhandle, const void *msg, unsigned long wait)
{
    int ret;

    if (qhandle == NULL)
    {
        return -WM_E_INVAL;
    }

    os_dprintf("OS: Queue Send: handle %p, msg %p, wait %d\r\n", qhandle, msg, wait);
    ret = k_msgq_put(*qhandle, msg, K_TICKS(wait));
    os_dprintf("OS: Queue Send: done\r\n");

    return ret == 0 ? WM_SUCCESS: -WM_FAIL;
}

int os_queue_recv(os_queue_t *qhandle, void *msg, unsigned long wait)
{
    int ret;
    if (qhandle == NULL)
    {
        return -WM_E_INVAL;
    }

    os_dprintf("OS: Queue Receive: handle %p, msg %p, wait %d\r\n", qhandle, msg, wait);
    ret = k_msgq_get(*qhandle, msg, K_TICKS(wait));
    os_dprintf("OS: Queue Receive: done\r\n");
    return ret == 0 ? WM_SUCCESS : -WM_FAIL;
}

int os_queue_delete(os_queue_t *qhandle)
{
    os_dprintf("OS: Queue Delete: handle %p\r\n", qhandle);

    if (qhandle == NULL || (*qhandle) == NULL)
        return WM_SUCCESS;

    k_msgq_purge(*qhandle);
    os_mem_free(*qhandle);
    *qhandle = NULL;
    return WM_SUCCESS;
}

int os_queue_get_msgs_waiting(os_queue_t *qhandle)
{
    int nmsg = 0;
    if (qhandle == NULL)
    {
        return -WM_E_INVAL;
    }
    nmsg = k_msgq_num_used_get(*qhandle);
    os_dprintf("OS: Queue Msg Count: handle %p, count %d\r\n", qhandle, nmsg);
    return nmsg;
}

/*** Mutex ***/
int os_mutex_create(os_mutex_t *mhandle, const char *name, int flags)
{
    struct k_mutex *mutex = NULL;
    int ret;
    if (flags == OS_MUTEX_NO_INHERIT)
    {
        os_dprintf("Cannot create mutex for non-inheritance yet \r\n");
        return -WM_FAIL;
    }
    os_dprintf("OS: Mutex Create: name = %s\r\n", name);

    mutex = os_mem_alloc(sizeof(struct k_mutex));
    if (mutex == NULL)
    {
        printk("OS: Mutex Alloc fail name %s\r\n", name);
        return -WM_FAIL;
    }

    ret = k_mutex_init(mutex);
    if (ret != 0)
    {
        printk("OS: Mutex Init fail ret %d, name %s\r\n", ret, name);
    }

    os_dprintf("OS: Mutex Create: handle = %p\r\n", mhandle);
    *mhandle = mutex;
    return WM_SUCCESS;
}

int os_mutex_get(os_mutex_t *mhandle, unsigned long wait)
{
    int ret;
    if (mhandle == NULL)
    {
        return -WM_E_INVAL;
    }
    os_dprintf("OS: Mutex Get: handle %p\r\n", mhandle);
    ret = k_mutex_lock(*mhandle, K_TICKS(wait));
    return ret == 0 ? WM_SUCCESS : -WM_FAIL;
}

int os_mutex_put(os_mutex_t *mhandle)
{
    int ret;

    if (mhandle == NULL)
    {
        return -WM_E_INVAL;
    }

    os_dprintf("OS: Mutex Put: %p\r\n", mhandle);

    ret = k_mutex_unlock(*mhandle);
    return ret == 0 ? WM_SUCCESS : -WM_FAIL;
}

int os_recursive_mutex_create(os_mutex_t *mhandle, const char *name)
{
    int ret;
    if (mhandle == NULL)
    {
        return -WM_E_INVAL;
    }

    os_dprintf("OS: Recursive Mutex Create: name = %s \r\n", name);
    ret = os_mutex_create(mhandle, name, OS_MUTEX_INHERIT);
    os_dprintf("OS: Recursive Mutex Create: handle = %p\r\n", mhandle);

    return ret == 0 ? WM_SUCCESS : -WM_FAIL;
}

int os_recursive_mutex_get(os_mutex_t *mhandle, unsigned long wait)
{
    os_dprintf("OS: Recursive Mutex Get: handle %p\r\n", mhandle);
    int ret = k_mutex_lock(*mhandle, K_TICKS(wait));
    return ret == 0 ? WM_SUCCESS : -WM_FAIL;
}

int os_recursive_mutex_put(os_mutex_t *mhandle)
{
    os_dprintf("OS: Recursive Mutex Put: %p\r\n", mhandle);
    int ret = k_mutex_unlock(*mhandle);
    return ret == 0 ? WM_SUCCESS : -WM_FAIL;
}

int os_mutex_delete(os_mutex_t *mhandle)
{
    
    if (mhandle == NULL || (*mhandle) == NULL)
        return WM_SUCCESS;

    os_mutex_get(mhandle, OS_WAIT_FOREVER);
    os_mutex_put(mhandle);
    os_mem_free(*mhandle);
    *mhandle = NULL;
    return WM_SUCCESS;
}

/*** Semaphore ***/
int os_semaphore_create(os_semaphore_t *mhandle, const char *name)
{
    int ret;
    struct k_sem *sem = NULL;

    sem = os_mem_alloc(sizeof(struct k_sem));
    if (sem == NULL)
    {
        printk("OS: Sem Alloc fail name %s\r\n", name);
        return -WM_FAIL;
    }

    ret = k_sem_init(sem, 1, 1);
    if (ret != 0)
    {
        printk("OS: Sem Init fail ret %d, name %s\r\n", ret, name);
        return -WM_FAIL;
    }

    *mhandle = sem;
    return WM_SUCCESS;
}

int os_semaphore_create_counting(os_semaphore_t *mhandle,
                                               const char *name,
                                               unsigned long maxcount,
                                               unsigned long initcount)
{
    int ret;
    struct k_sem *sem = NULL;

    sem = os_mem_alloc(sizeof(struct k_sem));
    if (sem == NULL)
    {
        printk("OS: Sem Alloc fail name %s\r\n", name);
        return -WM_FAIL;
    }

    ret = k_sem_init(sem, initcount, maxcount);
    if (ret != 0)
    {
        printk("OS: Sem Init fail ret %d, name %s\r\n", ret, name);
        return -WM_FAIL;
    }

    *mhandle = sem;
    return WM_SUCCESS;
}

int os_semaphore_get(os_semaphore_t *mhandle, unsigned long wait)
{
    int ret;
    if (mhandle == NULL)
    {
        return -WM_E_INVAL;
    }
    os_dprintf("OS: Semaphore Get: handle %p\r\n", mhandle);
    ret = k_sem_take(*mhandle, K_TICKS(wait));
    return ret == 0 ? WM_SUCCESS : -WM_FAIL;
}

int os_semaphore_put(os_semaphore_t *mhandle)
{
    if (mhandle == NULL)
    {
        return -WM_E_INVAL;
    }

    os_dprintf("OS: Semaphore Put: handle %p\r\n", mhandle);
    k_sem_give(*mhandle);
    return WM_SUCCESS;
}

int os_semaphore_getcount(os_semaphore_t *mhandle)
{
    os_dprintf("OS: Semaphore Get Count: handle %p\r\n", mhandle);
    return k_sem_count_get(*mhandle);
}

int os_semaphore_delete(os_semaphore_t *mhandle)
{
    if (mhandle == NULL || (*mhandle) == NULL)
        return WM_SUCCESS;

    k_sem_reset(*mhandle);
    os_mem_free(*mhandle);
    *mhandle = NULL;
    return WM_SUCCESS;
}

/*** Timer ***/
/* TODO: add this to highest prio workqueue */
static void timer_callback_work_handler(struct k_work *item)
{
	struct timer_data *ptimer = CONTAINER_OF(item, struct timer_data, work);

	ptimer->callback(ptimer);
}

static void timer_callback(struct k_timer *tmr)
{
    int ret;
    struct timer_data *ptimer = k_timer_user_data_get(tmr);

    ret = k_work_submit(&ptimer->work);
    if (ret < 0)
    {
        printk("timer[%p] submit to system queue fail ret %d\r\n", (void *)ptimer, ret);
    }
}

int os_timer_create(os_timer_t *timer_t,
                    const char *name,
                    os_timer_tick ticks,
                    void (*call_back)(os_timer_arg_t),
                    void *cb_arg,
                    os_timer_reload_t reload,
                    os_timer_activate_t activate)
{
    struct timer_data *ptimer = NULL;

    ptimer = os_mem_alloc(sizeof(struct timer_data));
    if (ptimer == NULL)
    {
        printk("OS: Timer Alloc fail\r\n");
        return -WM_FAIL;
    }

    ptimer->reload_options = reload;
    ptimer->period = ticks;
    ptimer->callback = call_back;
    ptimer->user_arg = cb_arg;
    k_timer_init(&ptimer->timer, timer_callback, NULL);
    k_timer_user_data_set(&ptimer->timer, ptimer);

    /* put callback in system work queue thread to avoid non-isr operations in isr context */
    k_work_init(&ptimer->work, timer_callback_work_handler);

    if (activate == OS_TIMER_AUTO_ACTIVATE)
    {
	    if (ptimer->reload_options == OS_TIMER_ONE_SHOT)
	    {
	        k_timer_start(&ptimer->timer, K_TICKS(ptimer->period), K_NO_WAIT);
	    } else
	    {
	        k_timer_start(&ptimer->timer, K_TICKS(ptimer->period),
			K_TICKS(ptimer->period));
	    }
    }

    *timer_t = ptimer;
    return WM_SUCCESS;
}

int os_timer_activate(os_timer_t *timer_t)
{
    struct timer_data *ptimer;
    if (timer_t == NULL)
       return -WM_E_INVAL;

    ptimer = (struct timer_data *)(*timer_t);
    if (ptimer->reload_options == OS_TIMER_ONE_SHOT)
    {
        k_timer_start(&ptimer->timer, K_TICKS(ptimer->period), K_NO_WAIT);
    } else
    {
        k_timer_start(&ptimer->timer, K_TICKS(ptimer->period),
        K_TICKS(ptimer->period));
    }
    return WM_SUCCESS;
}

int os_timer_change(os_timer_t *timer_t, os_timer_tick ntime, os_timer_tick block_time)
{
    struct timer_data *ptimer;

    if (timer_t == NULL)
        return -WM_E_INVAL;

    ptimer = (struct timer_data *)(*timer_t);
    ptimer->period = ntime;
    return WM_SUCCESS;
}

bool os_timer_is_running(os_timer_t *timer_t)
{
    int ret;
    struct timer_data *ptimer;

    if (timer_t == NULL)
        return false;

    ptimer = (struct timer_data *)(*timer_t);
    ret = k_timer_remaining_ticks(&ptimer->timer);
    return ret == 0 ? false : true;
}

void *os_timer_get_context(os_timer_t *timer_t)
{
    struct timer_data *ptimer;

    if (timer_t == NULL)
        return NULL;

    ptimer = (struct timer_data *)(*timer_t);
    return ptimer->user_arg;
}

int os_timer_reset(os_timer_t *timer_t)
{
    return os_timer_activate(timer_t);
}

int os_timer_deactivate(os_timer_t *timer_t)
{
    struct timer_data *ptimer;

    if (timer_t == NULL)
        return -WM_E_INVAL;

    ptimer = (struct timer_data *)(*timer_t);
    k_timer_stop(&ptimer->timer);
    return WM_SUCCESS;
}

int os_timer_delete(os_timer_t *timer_t)
{
    struct timer_data *ptimer;

    if (timer_t == NULL || (*timer_t) == NULL)
        return WM_SUCCESS;

    ptimer = (struct timer_data *)(*timer_t);
    k_timer_stop(&ptimer->timer);
    os_mem_free(ptimer);
    *timer_t = NULL;
    return WM_SUCCESS;
}

static inline void os_event_flags_remove_node(event_wait_t *node, event_group_t *grp_ptr)
{
    if (node->prev != NULL)
    {
        node->prev->next = node->next;
    }
    if (node->next != NULL)
    {
        node->next->prev = node->prev;
    }
    /* If only one node is present */
    if (node->next == NULL && node->prev == NULL)
    {
        grp_ptr->list = NULL;
    }
    os_mem_free(node);
}

int os_event_flags_create(event_group_handle_t *hnd)
{
    int ret;
    event_group_t *eG = os_mem_alloc(sizeof(event_group_t));
    if (eG == NULL)
    {
        os_dprintf("ERROR:Mem allocation\r\n");
        return -WM_FAIL;
    }
    (void)memset(eG, 0x00, sizeof(event_group_t));
    ret = os_mutex_create(&eG->mutex, "event-flag", OS_MUTEX_INHERIT);
    if (ret != WM_SUCCESS)
    {
        os_mem_free(eG);
        return -WM_FAIL;
    }
    *hnd = (event_group_handle_t)eG;
    return WM_SUCCESS;
}

int os_event_flags_get(event_group_handle_t hnd,
                       unsigned requested_flags,
                       flag_rtrv_option_t option,
                       unsigned *actual_flags_ptr,
                       unsigned wait_option)
{
    bool wait_done = false;
    unsigned status;
    int ret;
    *actual_flags_ptr = 0;
    event_wait_t *tmp = NULL, *node = NULL;
    if (hnd == 0U)
    {
        os_dprintf("ERROR:Invalid event flag handle\r\n");
        return -WM_FAIL;
    }
    if (requested_flags == 0U)
    {
        os_dprintf("ERROR:Requested flag is zero\r\n");
        return -WM_FAIL;
    }
    if (actual_flags_ptr == NULL)
    {
        os_dprintf("ERROR:Flags pointer is NULL\r\n");
        return -WM_FAIL;
    }
    event_group_t *eG = (event_group_t *)hnd;

check_again:
    (void)os_mutex_get(&eG->mutex, OS_WAIT_FOREVER);

    if ((option == EF_AND) || (option == EF_AND_CLEAR))
    {
        if ((eG->flags & requested_flags) == requested_flags)
        {
            status = eG->flags;
        }
        else
        {
            status = 0;
        }
    }
    else if ((option == EF_OR) || (option == EF_OR_CLEAR))
    {
        status = (requested_flags & eG->flags);
    }
    else
    {
        os_dprintf("ERROR:Invalid event flag get option\r\n");
        (void)os_mutex_put(&eG->mutex);
        return -WM_FAIL;
    }
    /* Check flags */
    if (status != 0U)
    {
        *actual_flags_ptr = status;

        /* Clear the requested flags from main flag */
        if ((option == EF_AND_CLEAR) || (option == EF_OR_CLEAR))
        {
            eG->flags &= ~status;
        }

        if (wait_done)
        {
            /*Delete the created semaphore */
            (void)os_semaphore_delete(&tmp->sem);
            /* Remove ourselves from the list */
            os_event_flags_remove_node(tmp, eG);
        }
        (void)os_mutex_put(&eG->mutex);
        return WM_SUCCESS;
    }
    else
    {
        if (wait_option != 0U)
        {
            if (wait_done == false)
            {
                /* Add to link list */
                /* Prepare a node to add in the link list */
                node = os_mem_alloc(sizeof(event_wait_t));
                if (node == NULL)
                {
                    os_dprintf("ERROR:memory alloc\r\n");
                    (void)os_mutex_put(&eG->mutex);
                    return -WM_FAIL;
                }
                (void)memset(node, 0x00, sizeof(event_wait_t));
                /* Set the requested flag in the node */
                node->thread_mask = requested_flags;
                /* Create a semaophore */
                ret = os_semaphore_create(&node->sem, "wait_thread");
                if (ret != 0)
                {
                    os_dprintf("ERROR:In creating semaphore\r\n");
                    os_mem_free(node);
                    (void)os_mutex_put(&eG->mutex);
                    return -WM_FAIL;
                }
                /* If there is no node present */
                if (eG->list == NULL)
                {
                    eG->list = node;
                    tmp      = eG->list;
                }
                else
                {
                    tmp = eG->list;
                    /* Move to last node */
                    while (tmp->next != NULL)
                    {
                        os_dprintf("waiting \r\n");
                        tmp = tmp->next;
                    }
                    tmp->next  = node;
                    node->prev = tmp;
                    tmp        = tmp->next;
                }
                /* Take semaphore first time */
                ret = os_semaphore_get(&tmp->sem, OS_WAIT_FOREVER);
                if (ret != WM_SUCCESS)
                {
                    os_dprintf("ERROR:1st sem get error\r\n");
                    (void)os_mutex_put(&eG->mutex);
                    /*Delete the created semaphore */
                    (void)os_semaphore_delete(&tmp->sem);
                    /* Remove ourselves from the list */
                    os_event_flags_remove_node(tmp, eG);
                    return -WM_FAIL;
                }
            }
            (void)os_mutex_put(&eG->mutex);
            /* Second time get is performed for work-around purpose
            as in current implementation of semaphore 1st request
            is always satisfied */
            ret = os_semaphore_get(&tmp->sem, os_msec_to_ticks(wait_option));
            if (ret != WM_SUCCESS)
            {
                (void)os_mutex_get(&eG->mutex, OS_WAIT_FOREVER);
                /*Delete the created semaphore */
                (void)os_semaphore_delete(&tmp->sem);
                /* Remove ourselves from the list */
                os_event_flags_remove_node(tmp, eG);
                (void)os_mutex_put(&eG->mutex);
                return EF_NO_EVENTS;
            }

            /* We have woken up */
            /* If the event group deletion has been requested */
            if (eG->delete_group)
            {
                (void)os_mutex_get(&eG->mutex, OS_WAIT_FOREVER);
                /*Delete the created semaphore */
                (void)os_semaphore_delete(&tmp->sem);
                /* Remove ourselves from the list */
                os_event_flags_remove_node(tmp, eG);
                (void)os_mutex_put(&eG->mutex);
                return -WM_FAIL;
            }
            wait_done = true;
            goto check_again;
        }
        else
        {
            (void)os_mutex_put(&eG->mutex);
            return EF_NO_EVENTS;
        }
    }
}

int os_event_flags_set(event_group_handle_t hnd, unsigned flags_to_set, flag_rtrv_option_t option)
{
    event_wait_t *tmp = NULL;

    if (hnd == 0U)
    {
        os_dprintf("ERROR:Invalid event flag handle\r\n");
        return -WM_FAIL;
    }
    if (flags_to_set == 0U)
    {
        os_dprintf("ERROR:Flags to be set is zero\r\n");
        return -WM_FAIL;
    }

    event_group_t *eG = (event_group_t *)hnd;

    (void)os_mutex_get(&eG->mutex, OS_WAIT_FOREVER);

    /* Set flags according to the set_option */
    if (option == EF_OR)
    {
        eG->flags |= flags_to_set;
    }
    else if (option == EF_AND)
    {
        eG->flags &= flags_to_set;
    }
    else
    {
        os_dprintf("ERROR:Invalid flag set option\r\n");
        (void)os_mutex_put(&eG->mutex);
        return -WM_FAIL;
    }

    if (eG->list != NULL)
    {
        tmp = eG->list;
        if (tmp->next == NULL)
        {
            if ((tmp->thread_mask & eG->flags) != 0U)
            {
                (void)os_semaphore_put(&tmp->sem);
            }
        }
        else
        {
            while (tmp != NULL)
            {
                if ((tmp->thread_mask & eG->flags) != 0U)
                {
                    (void)os_semaphore_put(&tmp->sem);
                }
                tmp = tmp->next;
            }
        }
    }
    (void)os_mutex_put(&eG->mutex);
    return WM_SUCCESS;
}

int os_event_flags_delete(event_group_handle_t *hnd)
{
    int i, max_attempt = 3;
    event_wait_t *tmp = NULL;

    if (*hnd == 0U)
    {
        os_dprintf("ERROR:Invalid event flag handle\r\n");
        return -WM_FAIL;
    }
    event_group_t *eG = (event_group_t *)*hnd;

    (void)os_mutex_get(&eG->mutex, OS_WAIT_FOREVER);

    /* Set the flag to delete the group */
    eG->delete_group = 1;

    if (eG->list != NULL)
    {
        tmp = eG->list;
        if (tmp->next == NULL)
        {
            (void)os_semaphore_put(&tmp->sem);
        }
        else
        {
            while (tmp != NULL)
            {
                (void)os_semaphore_put(&tmp->sem);
                tmp = tmp->next;
            }
        }
    }
    (void)os_mutex_put(&eG->mutex);

    /* If still list is not empty then wait for 3 seconds */
    for (i = 0; i < max_attempt; i++)
    {
        (void)os_mutex_get(&eG->mutex, OS_WAIT_FOREVER);
        if (eG->list != NULL)
        {
            (void)os_mutex_put(&eG->mutex);
            os_thread_sleep(os_msec_to_ticks(1000));
        }
        else
        {
            (void)os_mutex_put(&eG->mutex);
            break;
        }
    }

    (void)os_mutex_get(&eG->mutex, OS_WAIT_FOREVER);
    if (eG->list != NULL)
    {
        (void)os_mutex_put(&eG->mutex);
        return -WM_FAIL;
    }
    else
    {
        (void)os_mutex_put(&eG->mutex);
    }

    /* Delete the event group */
    os_mem_free(eG);
    *hnd = 0;
    return WM_SUCCESS;
}

int os_rwlock_create(os_rw_lock_t *plock, const char *mutex_name, const char *lock_name)
{
    return os_rwlock_create_with_cb(plock, mutex_name, lock_name, NULL);
}
int os_rwlock_create_with_cb(os_rw_lock_t *plock, const char *mutex_name, const char *lock_name, cb_fn r_fn)
{
    int ret = WM_SUCCESS;
    ret     = os_mutex_create(&(plock->reader_mutex), mutex_name, OS_MUTEX_INHERIT);
    if (ret == -WM_FAIL)
    {
        return -WM_FAIL;
    }
    ret     = os_mutex_create(&(plock->write_mutex), mutex_name, OS_MUTEX_INHERIT);
    if (ret == -WM_FAIL)
    {
        return -WM_FAIL;
    }
    ret = os_semaphore_create(&(plock->rw_lock), lock_name);
    if (ret == -WM_FAIL)
    {
        return -WM_FAIL;
    }
    plock->reader_count = 0;
    plock->reader_cb    = r_fn;
    return ret;
}

int os_rwlock_read_lock(os_rw_lock_t *lock, unsigned int wait_time)
{
    int ret = WM_SUCCESS;
    ret     = os_mutex_get(&(lock->reader_mutex), OS_WAIT_FOREVER);
    if (ret == -WM_FAIL)
    {
        return ret;
    }
    lock->reader_count++;
    if (lock->reader_count == 1U)
    {
        if (lock->reader_cb != NULL)
        {
            ret = lock->reader_cb(lock, wait_time);
            if (ret == -WM_FAIL)
            {
                lock->reader_count--;
                (void)os_mutex_put(&(lock->reader_mutex));
                return ret;
            }
        }
        else
        {
            /* If  1 it is the first reader and
             * if writer is not active, reader will get access
             * else reader will block.
             */
            ret = os_semaphore_get(&(lock->rw_lock), wait_time);
            if (ret == -WM_FAIL)
            {
                lock->reader_count--;
                (void)os_mutex_put(&(lock->reader_mutex));
                return ret;
            }
        }
    }
    (void)os_mutex_put(&(lock->reader_mutex));
    return ret;
}

int os_rwlock_read_unlock(os_rw_lock_t *lock)
{
    int ret = os_mutex_get(&(lock->reader_mutex), OS_WAIT_FOREVER);
    if (ret == -WM_FAIL)
    {
        return ret;
    }
    lock->reader_count--;
    if (lock->reader_count == 0U)
    {
        /* This is last reader so
         * give a chance to writer now
         */
        (void)os_semaphore_put(&(lock->rw_lock));
    }
    (void)os_mutex_put(&(lock->reader_mutex));
    return ret;
}

int os_rwlock_write_lock(os_rw_lock_t *lock, unsigned int wait_time)
{
    int ret = os_semaphore_get(&(lock->rw_lock), wait_time);
    return ret;
}

void os_rwlock_write_unlock(os_rw_lock_t *lock)
{
    (void)os_semaphore_put(&(lock->rw_lock));
}

void os_rwlock_delete(os_rw_lock_t *lock)
{
    lock->reader_cb = NULL;
    (void)os_semaphore_delete(&(lock->rw_lock));
    (void)os_mutex_delete(&(lock->reader_mutex));
    lock->reader_count = 0;
}
