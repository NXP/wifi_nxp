CC := gcc
BIN = MPU_BRIDGE
SOURCE = mpu_bridge_app.c mpu_bridge_command.c
LDFLAGS = -lpthread
CFLAGS = -Wall
CFLAGS += -std=gnu99

#When use USB interface
#1.Enable the below two compile options and enable rdrw612 compile macro 'CONFIG_USB_BRIDGE'
#2.Need install libusb in host compile environment to support host app compile
LDFLAGS += -I/usr/local/include/libusb-1.0 -L/usr/local/lib -lusb-1.0
CFLAGS += -g -DCONFIG_USB_BRIDGE
#-DCONFIG_NCP_SOCKET_SEND_FIFO

.PHONY : $(BIN)

$(BIN): $(SOURCE)
	@echo "start compiling ......"
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -I.
.PHONY : clean
clean :
	-rm $(BIN)
