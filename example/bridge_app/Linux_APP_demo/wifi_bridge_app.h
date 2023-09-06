#include<stdlib.h>
#include<stdint.h>
#include <sys/types.h>

#define FALSE -1
#define TRUE 0
#define MAX_SEND_RECV_LEN 200
typedef struct serial_data
{
    uint8_t *databuf;
    int serial_fd;
}send_data, recv_data;


/*Open UART Serial Port*/
int UART_Open(int fd, char* port);

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