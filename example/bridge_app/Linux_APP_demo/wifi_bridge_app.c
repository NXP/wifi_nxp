#include<sys/stat.h>
#include<fcntl.h>
#include<unistd.h>
#include<string.h>
#include<termios.h>
#include<fcntl.h>
#include<pthread.h>
#include<unistd.h>
#include<wifi_bridge_app.h>
#include<wifi_bridge_command.h>

char databuf[200];
char respbuf[200];
uint8_t cmd_response_buf[1500];
uint8_t command[200] = {0};
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief        Open UART serial port
 * 
 * @param fd     file descriptor
 * @param port   serial port
 * @return       If open UART port successfully: fd, else: FALSE
 */
int UART_Open(int fd, char* port)
{
    if(port == NULL)
    {
        printf("The port is NULL!\r\n");
        return FALSE;
    }
    fd = open(port, O_RDWR | O_NOCTTY | O_NDELAY);
    if(fd == FALSE)
    {
        printf("Open UART %s failed!\r\n",port);
        return FALSE;
    }

    if(fcntl(fd, F_SETFL, 0) < 0)
    {
        printf("fcntl failed!\r\n");
        return FALSE;
    }
    
    if(isatty(STDIN_FILENO) == 0)
    {
        printf("standard input isn't a terminal device\r\n");
        return FALSE;
    }
    return fd;
}

/**
 * @brief      Close UART port
 * 
 * @param fd   file descriptor
 */
void UART_Close(int fd)
{
    close(fd);
}

/**
 * @brief      Set UART port property
 * 
 * @param fd   file descriptor
 * @return     Set port successfully: TRUE  else: FALSE
 */
int UART_Set(int fd)
{
    struct termios options;

    if(tcgetattr(fd, &options) != 0)
    {
        perror("SetupSerial 1");
        return FALSE;
    }

    printf("Begin to set port parameters.\r\n");
    /*Set Input and Output baud rate*/
    bzero(&options, sizeof(options));
    cfsetispeed(&options, B115200);
    cfsetospeed(&options, B115200);
    /*Local area connection mode*/
    options.c_cflag |= CLOCAL;
    /*Serial data reception*/
    options.c_cflag |= CREAD;
    /*Hardware flow control*/
    options.c_cflag |= CRTSCTS;
    /*Set data bit*/
    options.c_cflag &= ~CSIZE;
    options.c_cflag |= CS8;
    /*Set parity bit*/
    options.c_cflag &= ~PARENB;
    options.c_iflag &= ~INPCK;
    /*Set stop bit*/
    options.c_cflag &= ~CSTOPB;
    /*Raw output*/
    options.c_oflag &= ~OPOST;
    options.c_iflag &= ~(IXON | IXOFF |IXANY);//Disable XON/XOFF flow control both i/p and o/p
    options.c_lflag &= ~(ICANON | ECHO |ECHOE | ISIG);
    /*Set wait time and minimum received uint8_tacters*/
    options.c_cc[VTIME] = 0;
    options.c_cc[VMIN] = 0;

    tcflush(fd,TCIOFLUSH);

    if(tcsetattr(fd, TCSANOW, &options) != 0)
    {
        printf("port set error!\r\n");
        return FALSE;
    }
    return TRUE;
}

/**
 * @brief       Initialize UART serial port
 * 
 * @param fd    file descriptor
 * @return      Success : TRUE     Failed: FALSE
 */
int UART_Init(int fd)
{
    return UART_Set(fd);
}

/**
 * @brief        Receive response from bride_app
 * 
 * @param arg    arg
 * @return       TRUE
 */
int UART_Recv(void *arg)
{
    recv_data *R_D = (recv_data *)arg;
    int recv_length = 0;
    int i = 0;
    while(1)
    {
        if(pthread_mutex_lock(&mutex) == 0)
        {
            fflush(stdin);
            int recv_resp_length = 0;
            int cmd_size = 0;
            while(1)
            {
                recv_length = read(R_D->serial_fd, R_D->databuf, 200);
                memcpy(cmd_response_buf + recv_resp_length, R_D->databuf, recv_length);
                recv_resp_length += recv_length;
                if(recv_resp_length >= 4 && cmd_size == 0)
                    cmd_size = cmd_response_buf[3] << 8 | cmd_response_buf[2];
                if(recv_resp_length == 0 ||(recv_resp_length >= cmd_size))
                    break;
            }
            
            if(recv_resp_length > 0)
            {
                wlan_process_response(cmd_response_buf);
            }
        pthread_mutex_unlock(&mutex);
        }
        usleep(1000);
    }
    return TRUE;
}

/**
 * @brief      Waiting for input
 * 
 * @return     Set successfully: TRUE  else: FALSE
 */
int keyboardhit()
{
    struct termios oldt, newt;
    int ch, oldf;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_cflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, F_GETFL, 0);
    oldf = fcntl(STDIN_FILENO, F_SETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO ,F_SETFL, oldf);
    if(ch != EOF)
    {
        ungetc(ch, stdin);
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief        Send command to bridge_app
 * 
 * @param arg    arg
 * @return       TRUE
 */
int UART_NCP_Send(void *arg)
{
    send_data *S_D = (send_data *)arg;
    int ret;
    int Datalen, len;
    char ent[2], nul[2];
    nul[0] = '\n';                       //only input enter
    ent[0] = '\r';
    while (1)
    {
        if(pthread_mutex_lock(&mutex) == 0)
        {
            while (keyboardhit() == TRUE)
            {
                fgets(databuf, MAX_SEND_RECV_LEN, stdin);
                if(!strncmp(databuf, nul, 1))
                    continue;
                databuf[strlen(databuf) - 1] = '\0';
                ret = string_to_command(S_D->databuf);
                if(ret == TRUE)
                {
                    W_CMD *temp = (W_CMD *)command;
                    Datalen = temp->size;
                    len = write(S_D->serial_fd, command, Datalen);
                    if(len != Datalen)
                    {
                        printf("Failed to send command!\r\n");
                        tcflush(S_D->serial_fd, TCOFLUSH);
                        return FALSE;
                    }
                    printf("Sent command successfully!\r\n");
                }
                else
                    printf("Failed to send command. Please input command again.\r\n");
            }
            pthread_mutex_unlock(&mutex);
        }
        usleep(500);
    }
    return TRUE;
}

/**
 * @brief        Main function
 * 
 * @param argc   argc
 * @param argv   argv
 * @return       TRUE
 */
int main(int argc, char **argv)
{
    int fd, error;
    
    if(argc != 2)
    {
        printf("Usage: WIFI_CLI /dev/tty*\r\n");
        return FALSE;
    }
    fd = UART_Open(fd, argv[1]);
    if (fd == FALSE)
        return FALSE;
    error = UART_Init(fd);

    if(error == FALSE)
        return FALSE;

    pthread_t ret_send_thread, ret_recv_thread;
    recv_data R_data;
    R_data.serial_fd = fd;
    R_data.databuf = respbuf;
    ret_recv_thread = pthread_create(&ret_recv_thread, NULL, (void *)UART_Recv, (void *)&R_data);
    if(ret_recv_thread != 0)
    {
        printf("Failed to creat Receive Thread!\r\n");
        exit(EXIT_FAILURE);
    }
    else
        printf("Success to creat Receive Thread!\r\n");

    send_data data;
    data.databuf = databuf;
    data.serial_fd = fd;
    ret_send_thread = pthread_create(&ret_send_thread, NULL, (void*)UART_NCP_Send, (void *)&data);
    if(ret_send_thread != 0)
    {
        printf("Failed to creat Send Thread!\r\n");
        exit(EXIT_FAILURE);
    }
    else
        printf("Success to creat Send Thread!\r\n");

    printf("You can input these commands:\r\n");
    wlan_bridge_command_print();
    while(1)
    {
        usleep(100000);
    }

    pthread_join(ret_send_thread, NULL);
    pthread_join(ret_recv_thread, NULL);
    UART_Close(fd);
    
    return TRUE;
}