#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <pthread.h>

#define FALSE             -1
#define TRUE              0
#define MAX_SEND_RECV_LEN 200

#define MPU_BRIDGE_INBUF_SIZE   200
#define MPU_BRIDGE_MAX_COMMANDS 500

#define NCP_BRIDGE_COMMAND_LEN             4096 // The max number bytes which UART can receive.
#define NCP_BRIDGE_RESPONSE_LEN            4096
#define NCP_BRIDGE_CMD_SIZE_LOW_BYTES      4
#define NCP_BRIDGE_CMD_SIZE_HIGH_BYTES     5
#define NCP_BRIDGE_CMD_SEQUENCE_LOW_BYTES  6
#define NCP_BRIDGE_CMD_SEQUENCE_HIGH_BYTES 7

#define MPU_DUMP_WRAPAROUND 16

#define CRC32_POLY   0x04c11db7
#define CHECKSUM_LEN 4

#define mpu_in_range(c, lo, up) ((uint8_t)(c) >= (lo) && (uint8_t)(c) <= (up))
#define mpu_isdigit(c)          mpu_in_range((c), '0', '9')
#define mpu_islower(c)          mpu_in_range((c), 'a', 'z')
#define mpu_isupper(c)          mpu_in_range((c), 'A', 'Z')

#define NCP_BRIDGE_RING_BUFFER_SIZE 4096
/* Note: the actual allocated space is subject to NCP_BRIDGE_RING_BUFFER_SIZE_ALIGN, so round
 * NCP_BRIDGE_RING_BUFFER_SIZE up to a power of 2.*/
#define _ALIGN                            8
#define NCP_BRIDGE_RING_BUFFER_SIZE_ALIGN ((NCP_BRIDGE_RING_BUFFER_SIZE + (_ALIGN - 1)) & ~(_ALIGN - 1))
#define min(a, b)                         (((a) < (b)) ? (a) : (b))

#define ICMP_ECHO             8 /* echo */
#define IP_HEADER_LEN         20
#define PING_RECVFROM_TIMEOUT 2000

typedef struct _ring_buffer
{
    void *buffer;            /* ring buffer */
    uint32_t size;           /* buffer size*/
    uint32_t head;           /* ring buffer head*/
    uint32_t tail;           /* ring buffer tail*/
    pthread_mutex_t *f_lock; /* mutex */
} ring_buffer_t;

typedef struct serial_data_send
{
    uint8_t *data_buf;
    int serial_fd;
} send_data_t;

typedef struct serial_data_recv
{
    ring_buffer_t *data_buf;
    int serial_fd;
} recv_data_t;

/** Structure for registering CLI commands */
struct mpu_bridge_cli_command
{
    /** The name of the CLI command */
    const char *name;
    /** The help text associated with the command */
    const char *help;
    /** The function that should be invoked for this command. */
    int (*function)(int argc, char **argv);
};

/*Open UART Serial Port*/
int UART_Open(int fd, char *port);

/*Close UART Serial Port*/
void UART_Close(int fd);

/*Set Baud rate  Data Bits  Stop BIts*/
int UART_Set(int fd);

/*Initialize UART Serial Port*/
int UART_INIT(int fd);

/*Receive UART data*/
int UART_Recv(void *arg);

/*Wait keyboard input without blocking other thread*/
int keyboardhit();

/*Send command data*/
int UART_NCP_Send(void *arg);

/** Register a mpu bridge cli command
 *
 * This function registers a command with the command-line interface.
 *
 * \param[in] command The structure to register one mpu bridge cli command
 * \return TRUE on success
 * \return FALSE on failure
 */
int mpu_bridge_register_command(const struct mpu_bridge_cli_command *command);

/** Unregister a mpu bridge cli command
 *
 * This function unregisters a command from the command-line interface.
 *
 * \param[in] command The structure to unregister one mpu bridge cli command
 * \return TRUE on success
 * \return FALSE on failure
 */
int mpu_bridge_unregister_command(const struct mpu_bridge_cli_command *command);

/** Register a batch of mpu bridge cli commands
 *
 * Often, a module will want to register several commands.
 *
 * \param[in] commands Pointer to an array of commands.
 * \param[in] num_commands Number of commands in the array.
 * \return TRUE on success
 * \return FALSE on failure
 */
int mpu_bridge_register_commands(const struct mpu_bridge_cli_command *commands, int num_commands);

/** Unregister a batch of mpu bridge cli commands
 *
 * \param[in] commands Pointer to an array of commands.
 * \param[in] num_commands Number of commands in the array.
 * \return TRUE on success
 * \return FLASE on failure
 */
int mpu_bridge_unregister_commands(const struct mpu_bridge_cli_command *commands, int num_commands);

/* Built-in "help" command: prints all registered commands and their help
 * text string, if any. */
int help_command(int argc, char **argv);

int string_equal(const char *s1, const char *s2);

/**
 * @brief       This function convters string to decimal number.
 */
int get_uint(const char *arg, unsigned int *dest, unsigned int len);

/*
 * @brief convert String to integer
 *
 *@param value        A pointer to string
 *@return             integer
 **/
uint32_t a2hex_or_atoi(char *value);

/**
 *@brief convert string to hex integer
 *
 *@param s            A pointer string buffer
 *@return             hex integer
 **/
uint32_t a2hex(const char *s);

/**
 *@brief convert char to hex integer
 *
 *@param chr          char
 *@return             hex integer
 **/
uint8_t hexc2bin(char chr);

/*Dump buffer in hex format on console.*/
void mpu_dump_hex(const void *data, unsigned int len);
