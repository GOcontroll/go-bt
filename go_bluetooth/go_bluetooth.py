#!/usr/bin/env python3
import logging
import os
import subprocess
import threading
import time
import traceback
from hashlib import sha1
from logging.handlers import RotatingFileHandler
from signal import pause
import auth

import rfcommServerConstants as commands
import server
from bluedot.btcomm import BluetoothServer
from can_settings import can_settings
from conf import get_features, get_conf
from controller_configuration import controller_configuration, module_settings
from controller_programs import controller_programs
from controller_settings import controller_settings
from ethernet_settings import ethernet_settings
from wlan_settings import access_point_settings, wireless_settings
from wwan_settings import wwan_settings
import makeAgent as agent

logger = logging.getLogger(__name__)


# thread that makes an led flash in the colour orange
def status_led_gocontroll(led):
    while 1 == 1:
        try:
            led.set_led_brightness(127)
            led.set_led_red(165)
            led.set_led_green(50)
            led.set_led_blue(0)
            if kill_threads:
                break
            time.sleep(0.5)
            led.set_led_brightness(0)
        except Exception as ex:
            logger.error(f"failed to toggle led:\n{ex}")
            return
        time.sleep(0.5)
        if kill_threads_shutdown:
            break


def update_controller(commandnmbr, arg):
    global zip_url
    level1 = ord(arg[0])
    arg = arg[1:]
    if level1 == commands.CHECK_FOR_UPDATE:
        # TODO apt update?
        pass

    # update the controller through its own network connection
    elif level1 == commands.UPDATE_CONTROLLER_LOCAL:
        # TODO apt upgrade?
        pass

    # transferred file cleared the checksum test
    elif level1 == commands.UPDATE_FILE_APROVED:
        server.send(chr(commandnmbr) + chr(commands.UPDATE_LOCAL_FAILED))

    # transferred file did not clear the checksum test or file transfer was cancelled
    elif level1 == commands.UPDATE_FILE_CORRUPTED:
        # print("file was corrupted")
        try:
            os.remove("/tmp/temporary.zip")
        except Exception as _:
            # print("file was not yet created")
            pass


###########################################################################################

# file transfer
# sets up the script to receive a file


def file_transfer(commandnmbr, arg):
    global transfer_mode
    global first_write
    global file_size
    global i
    global progress
    progress = 0
    i = 0
    first_write = 1
    transfer_mode = 1
    file_size = int(arg)
    server.send(chr(commandnmbr) + chr(commands.FILE_TRANSFER_ENABLED))
    tf = threading.Thread(target=check_for_file_reception)
    tf.start()


# handles the receiving of filedata over bluetooth
def receive_zip(data):
    global file_timeout
    global transfer_mode
    global first_write
    global i
    global progress
    global file_size
    file_timeout = 0
    progress_check = progress
    i += 1
    progress = int(((i * 990) / file_size) * 100)
    if (
        progress > progress_check
    ):  # only send progress when it changes to clear up bluetooth bandwidth
        server.send(
            chr(commands.FILE_TRANSFER)
            + chr(commands.FILE_TRANSFER_PROGRESS)
            + chr(progress)
        )
    if first_write == 1:
        with open("/tmp/temporary.zip", "wb") as file:
            file.write(data)
        first_write = 0
    else:
        with open("/tmp/temporary.zip", "ab") as file:
            file.write(data)
    if file_size == os.path.getsize("/tmp/temporary.zip"):
        transfer_mode = "command"
        checksum = sha1("/tmp/temporary.zip")
        time.sleep(0.2)
        server.send(
            chr(commands.FILE_TRANSFER)
            + chr(commands.FILE_TRANSFER_COMPLETE)
            + checksum
        )


# watchdog timer for file reception, stops the script from getting stuck in file reception mode
def check_for_file_reception():
    global file_timeout
    global transfer_mode
    global kill_threads
    file_timeout = 0
    while file_timeout <= 2:
        time.sleep(0.5)
        file_timeout += 0.5
        if kill_threads:
            break
    if transfer_mode != "command":
        server.send(chr(commands.FILE_TRANSFER) + chr(commands.NO_FILE_RECEIVED))
        transfer_mode = "command"


# send(filetransfer + filetransfer state + (progress))

##########################################################################################

# request enabled features by the app


def request_enabled_features(commandnmbr, arg):
    level1 = ord(arg[0])

    if level1 == commands.INIT_FEATURES:
        features_out = "\n".join(map(str, get_features().values()))
        features_out = features_out.lower()
        logger.debug(f"features: {features_out}")
        server.send(chr(commandnmbr) + features_out)

    elif level1 == commands.FEATURES_APROVED:
        logger.debug("requesting verification")
        server.send(
            chr(commands.VERIFY_DEVICE) + chr(commands.DEVICE_VERIFICATION_EXCHANGE_KEY)
        )


##########################################################################################

# reboot the controller


def reboot_controller():
    logger.info("rebooting...")
    server.bt_server.disconnect_client()
    global kill_threads_shutdown
    kill_threads_shutdown = True
    tf.join()
    subprocess.run(["reboot"])


##########################################################################################
# command_list
##########################################################################################


def command_list(byte, string):
    string = string.decode("utf-8")
    if byte == commands.VERIFY_DEVICE and get_features().get("verify_device", False):
        auth.verify_device(byte, string)
        return
    elif byte == commands.UPDATE_CONTROLLER and get_features().get(
        "update_controller", False
    ):
        update_controller(byte, string)
        return
    elif byte == commands.FILE_TRANSFER and get_features().get("file_transfer", False):
        file_transfer(byte, string)
        return
    elif byte == commands.ETHERNET_SETTINGS and get_features().get(
        "ethernet_settings", False
    ):
        ethernet_settings(byte, string)
        return
    elif byte == commands.WIRELESS_SETTINGS and get_features().get(
        "wireless_settings", False
    ):
        wireless_settings(byte, string)
        return
    elif byte == commands.AP_SETTINGS and get_features().get("ap_settings", False):
        access_point_settings(byte, string)
        return
    elif byte == commands.CONTROLLER_SETTINGS and get_features().get(
        "controller_settings", False
    ):
        controller_settings(byte, string)
        return
    elif byte == commands.CONTROLLER_PROGRAMS and get_features().get(
        "controller_programs", False
    ):
        controller_programs(byte, string)
        return
    elif byte == commands.WWAN_SETTINGS and get_features().get("wwan_settings", False):
        wwan_settings(byte, string)
        return
    elif byte == commands.CAN_SETTINGS and get_features().get("can_settings", False):
        can_settings(byte, string)
        return
    elif byte == commands.CONTROLLER_CONFIGURATION and get_features().get(
        "controller_configuration", False
    ):
        controller_configuration(byte, string)
        return
    elif byte == commands.MODULE_SETTINGS and get_features().get(
        "module_settings", False
    ):
        module_settings(byte, string)
        return
    elif byte == commands.REQUEST_ENABLED_FEATURES:
        request_enabled_features(byte, string)
        return
    elif byte == commands.REBOOT_CONTROLLER and get_features().get(
        "reboot_controller", False
    ):
        reboot_controller()
        return
    else:
        server.send(chr(commands.UNKNOWN_COMMAND) + "unknown command")


# function that gets called when the controller receives a message
def data_received(data):
    logger.debug(f"incoming:\n{data}\ntrusted: {auth.get_trust()}")
    try:
        global transfer_mode
        first_byte = data[0]
        if (
            auth.get_trust()
            or first_byte == commands.VERIFY_DEVICE
            or first_byte == commands.REQUEST_ENABLED_FEATURES
        ):
            data = data[1:]
            # get message till stopbyte
            data = data.split(bytes([255]))[0]
            command_list(first_byte, data)
        else:
            server.send(
                chr(commands.VERIFY_DEVICE)
                + chr(commands.DEVICE_VERIFICATION_EXCHANGE_KEY)
            )
    except Exception:
        error = "error:" + traceback.format_exc()
        server.send(chr(commands.SERVER_ERROR) + error)
        return


# function that gets called when a device connects to the server
def when_client_connects():
    logger.info(f"client connected: {server.bt_server.client_address}")
    global read_can_bus_load
    global tf
    global kill_threads
    global kill_threads_shutdown
    read_can_bus_load = False
    kill_threads = False
    kill_threads_shutdown = False
    try:
        #huh?
        import go_leds.go_leds

        led1 = go_leds.go_leds.get_led(1)
        tf = threading.Thread(target=status_led_gocontroll, args=(led1,))
        tf.start()
    except ImportError:
        pass
    except Exception as ex:
        logger.error(f"Unknown error when trying to init the status led thread:\n{ex}")
    auth.set_trust(False)
    request_enabled_features(
        commands.REQUEST_ENABLED_FEATURES, chr(commands.INIT_FEATURES)
    )


# function that gets called when a device disconnects from the server
def when_client_disconnects():
    global kill_threads
    kill_threads = True
    logger.info("client disconnected")


def setup_logging():
    # Create a logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Set the logging level

    # Format for log messages
    formatter = logging.Formatter(
        "%(asctime)s {%(filename)s:%(lineno)d} %(levelname)s - %(message)s"
    )

    # Create a console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    try:
        # Create a rotating file handler
        file_handler = RotatingFileHandler(
            "/var/log/go_bluetooth.log", maxBytes=5 * 1024 * 1024, backupCount=3
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except PermissionError:
        logger.warning(
            "Unable to open /var/log/go_bluetooth.log due to insufficient permissions, only logging to console"
        )


def main():
    setup_logging()
    logger.info("Creating bluetooth agent")
    threading.Thread(target=agent.create_bt_agent).start()
    logger.info("go-bluetooth server starting")
    conf = get_conf()
    auth.set_passkey(conf.get("pass_hash"))
    s = BluetoothServer(
        data_received,
        encoding=None,
        when_client_connects=when_client_connects,
        when_client_disconnects=when_client_disconnects,
    )
    server.bt_server = s
    pause()


if __name__ == "__main__":
    main()
