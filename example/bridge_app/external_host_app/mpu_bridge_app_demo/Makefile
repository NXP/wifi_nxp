CC := gcc
BIN = MPU_BRIDGE
SOURCE = mpu_bridge_app.c mpu_bridge_command.c
LDFLAGS = -lpthread
CFLAGS = -Wall
CFLAGS += -std=gnu99

#When use USB interface
#******For NCP MPU Host side(i.mx8mini)*****
#1.Need install libusb in host compile environment to support host app compile
#2.Use "make CONFIG_NCP_USB=y" to enable usb interface

#******For NCP device side(rw61x)*****
#Enable compile macro 'CONFIG_USB_BRIDGE'

ifeq ($(CONFIG_NCP_USB), y)
CFLAGS += -g -DCONFIG_USB_BRIDGE  -DCONFIG_NCP_SOCKET_SEND_FIFO
#**Note**
#Path of '-I/usr/local/include/libusb-1.0 -L/usr/local/lib' is corresponding to your libusb install path.
LDFLAGS += -I/usr/local/include/libusb-1.0 -L/usr/local/lib -lusb-1.0
endif

.PHONY : $(BIN)

$(BIN): $(SOURCE)
	@echo "start compiling ......"
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -I.
.PHONY : clean
clean :
	-rm $(BIN)
