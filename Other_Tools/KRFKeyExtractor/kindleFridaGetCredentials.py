import frida
import argparse
from io import BytesIO
import collections 
from frida_tools.reactor import Reactor
import threading
import sys
import signal
import numbers
import zipfile 
import lzma
import os
import json
##Usage:
# Install Windows subsystem for Android or another android emulator, might also work on rooted Android device
# install kindle for Android on device/emulator
# install and run frida server on the device/emulator
# install frida for python that matches the version on the device 
# install Android platform tools and connect to device/emulator
# copy this python scrtipt and compiled_agent.js into the same folder
# run Kindle on Android, and download the books you want to convert from your library 
# run script, for example `python kindleFridaGetCredentials.py 
# write credentials into credential file, like credentials.json
# adb push kindledecr executable for appropriate platfrom and credentials.json into device/emulator
# copy it somewhere where it can be executed, like /data/local/tmp and chmod +x it. copy credetials.json along with it.
# run kindledecr executable and hope for the best, books should appear in the output folder. 
# adb pull output folder and add books to Calibre or wherever you feel like. 

# note: compiled_agent.js is compiled from agent.js by npx frida-compile agent.js -o compiled_agent.js
# npm install frida-java-bridge and npm install --save-dev frida-compile 



def create_target_parser(target_type):
    def parse_target(value):
        if target_type == "file":
            return (target_type, [value])
        if target_type == "gated":
            return (target_type, re.compile(value))
        if target_type == "pid":
            return (target_type, int(value))
        return (target_type, value)

    return parse_target
    
parser = argparse.ArgumentParser(
        prog='kindleInstrument',
        formatter_class=argparse.RawDescriptionHelpFormatter)
#parser.add_argument('-p','--process', default="com.amazon.kindle", help='the Kindle process you are trying to instrument')
parser.add_argument(
            "-n",
            "--attach-name",
            help="attach to NAME",
            metavar="NAME",
            dest="target",
            type=create_target_parser("name"),
        )
parser.add_argument(
            "-N",
            "--attach-identifier",
            help="attach to IDENTIFIER",
            metavar="IDENTIFIER",
            dest="target",
            type=create_target_parser("identifier"),
        )
parser.add_argument(
            "-p", "--attach-pid", help="attach to PID", metavar="PID", dest="target", type=create_target_parser("pid")
        )
def dir_path(string):
    if os.path.isdir(string):
        return string
    else:
        raise NotADirectoryError(string)
#usb by default
parser.add_argument('-H', '--host', type=str,
                        help='device connected over IP, or use \'local\' for local connection')
args = parser.parse_args()



#console.log(hex(p.readByteArray(ln)))

script_text=open("compiled_agent.js","r",encoding="utf8").read()

def find_device(device_type):
    for device in frida.enumerate_devices():
        if device.type == device_type:
            return device
    return None
    
class MiniReactor(object):
    def __init__(self,host,target,scr,on_message):
        self._reactor= Reactor(self._process_input, self._on_stop)
        self._device =None
        self._ready = threading.Event()
        self._stopping = threading.Event()
        if host is None or len(host)==0:
            self._device_type="usb"
            self._host=None
        else:
            if host=="local":
                self._host=None
                self._device_type=None#"local"
            else:
                self._host=host
                self._device_type="remote"
        self._device_id=None
        self._keepalive_interval=None
        self._schedule_on_output = lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data))
        self._schedule_on_device_lost = lambda: self._reactor.schedule(self._on_device_lost)
        self._started = False
        self._target=target
        self._session = None
        self._schedule_on_session_detached = lambda reason, crash: self._reactor.schedule( lambda: self._on_session_detached(reason, crash))
        self._session_transport = "multiplexed"
        self._runtime="qjs"
        self._realm="native"
        self._script_text=scr
        self._script=None
        self._exit_on_error=True
        self._on_message_custom=on_message
    def _try_load_script(self) -> None:
        try:
            self._load_script()
        except Exception as e:
            self._print(f"Failed to load script: {e}")
    def _on_stop(self):
        self._stopping.set()
        
    def _try_start(self) -> None:
        if self._device is not None:
            return
        if self._device_id is not None:
            try:
                self._device = frida.get_device(self._device_id)
            except:
                self._update_status(f"Device '{self._device_id}' not found")
                self._exit(1)
                return
        elif (self._host is not None) or (self._device_type == "remote"):
            host = self._host
            print("remote")
            options = {}
            if self._keepalive_interval is not None:
                options["keepalive_interval"] = self._keepalive_interval

            if host is None and len(options) == 0:
                self._device = frida.get_remote_device()
            else:
                self._device = frida.get_device_manager().add_remote_device(
                    host if host is not None else "127.0.0.1", **options
                )
        elif self._device_type is not None:
            self._device = find_device(self._device_type)
            if self._device is None:
                return
        else:
            self._device = frida.get_local_device()
        self._device.on("output", self._schedule_on_output)
        self._device.on("lost", self._schedule_on_device_lost)
        self._attach_and_instrument()
    def _log(self, level: str, text: str):
        if level == "info":
            self._print(text)
        else:
            if level == "error":
                self._print(text, file=sys.stderr)
            else:
                self._print(text)
    def _unload_script(self):
        if self._script is None:
            return
        try:
            self._script.unload()
        except:
            pass
        self._script = None
    def _on_sigterm(self, n, f):
        self._reactor.cancel_io()
        self._exit(0)
    def _process_message(self, message ,data) -> None:
        #print("processing message")
        #print(message)
        message_type = message["type"]
        if message_type == "error":
            text = message.get("stack", message["description"])
            self._log("error", text)
            if self._exit_on_error:
                self._exit(1)
        else:
            self._on_message_custom(message["payload"],data,self)

    def _load_script(self) -> None:
        is_first_load = self._script is None

        assert self._session is not None
        script = self._session.create_script(name="kndl", source=self._script_text, runtime=self._runtime)
        script.set_log_handler(self._log)
        self._unload_script()
        self._script = script

        def on_message(message, data):
            if self.try_handle_bridge_request(message, self._script):
                return
            self._reactor.schedule(lambda: self._process_message(message, data))

        script.on("message", on_message)
        self._on_script_created(script)
        script.load()
    def try_handle_bridge_request(self, message, script):
        #print(message)
        if message["type"] != "send":
            return False

        payload = message.get("payload")
        if not isinstance(payload, dict):
            return False
        #print(payload)
        t = payload.get("type")
        if t != "frida:load-bridge":
            return False

        stem = payload["name"].lower()
        bridge = next(p for p in (Path(__file__).parent / "bridges").glob("*.js") if p.stem == stem)
        print("bridge posted")
        script.post(
            {
                "type": "frida:bridge-loaded",
                "filename": bridge.name,
                "source": bridge.read_text(encoding="utf-8"),
            }
        )

        return True
    def _perform_on_background_thread(self, f, timeout=None):
        result = [None, None]

        def work() -> None:
            with self._reactor.io_cancellable:
                try:
                    result[0] = f()
                except Exception as e:
                    result[1] = e

        worker = threading.Thread(target=work)
        worker.start()

        try:
            worker.join(timeout)
        except KeyboardInterrupt:
            self._reactor.cancel_io()

        if timeout is not None and worker.is_alive():
            self._reactor.cancel_io()
            while worker.is_alive():
                try:
                    worker.join()
                except KeyboardInterrupt:
                    pass

        error = result[1]
        if error is not None:
            raise error

        return result[0]
    def _attach_and_instrument(self):
        if self._target is None:
            print("Needs target")
            self._exit(1)
        if self._target is not None:
            target_type, target_value = self._target

            spawning = True
            try:
                if target_type == "identifier":
                    spawning = False
                    app_list = self._device.enumerate_applications()
                    app_identifier_lc = target_value.lower()
                    matching = [app for app in app_list if app.identifier.lower() == app_identifier_lc]
                    if len(matching) == 1 and matching[0].pid != 0:
                        attach_target = matching[0].pid
                    elif len(matching) > 1:
                        raise frida.ProcessNotFoundError(
                            "ambiguous identifier; it matches: %s"
                            % ", ".join([f"{process.identifier} (pid: {process.pid})" for process in matching])
                        )
                    else:
                        raise frida.ProcessNotFoundError("unable to find process with identifier '%s'" % target_value)
                elif target_type == "file":
                    argv = target_value
                    if not self._quiet:
                        self._update_status(f"Spawning `{' '.join(argv)}`...")

                    aux_kwargs = {}
                    if self._aux is not None:
                        aux_kwargs = dict([parse_aux_option(o) for o in self._aux])

                    self._spawned_pid = self._device.spawn(argv, stdio=self._stdio, **aux_kwargs)
                    self._spawned_argv = argv
                    attach_target = self._spawned_pid
                else:
                    attach_target = target_value
                    if not isinstance(attach_target, numbers.Number):
                        attach_target = self._device.get_process(attach_target).pid
                spawning = False
                self._attach(attach_target)
            except frida.OperationCancelledError:
                self._exit(0)
                return
            except Exception as e:
                if spawning:
                    self._update_status(f"Failed to spawn: {e}")
                else:
                    self._update_status(f"Failed to attach: {e}")
                self._exit(1)
                return
        self._start()
        self._started = True
    def _on_script_created(self, script: frida.core.Script):
        return 
    def _attach(self, pid: int) -> None:

        self._target_pid = pid
        assert self._device is not None
        self._session = self._device.attach(pid, realm=self._realm)
        self._session.on("detached", self._schedule_on_session_detached)

    def _start(self) -> None:
        self._load_script()
        assert self._script is not None
        self._ready.set()
        """
        override this method with the logic of your command, it will run after
        the class is fully initialized with a connected device/target if you
        required one.
        """
    def _stop(self) -> None:
        self._unload_script()

    def _print(self, *args, **kwargs):
        encoded_args = []
        encoding = sys.stdout.encoding or "UTF-8"
        if encoding == "UTF-8":
            encoded_args = list(args)
        else:
            for arg in args:
                if isinstance(arg, str):
                    encoded_args.append(arg.encode(encoding, errors="backslashreplace").decode(encoding))
                else:
                    encoded_args.append(arg)
        print(*encoded_args, **kwargs)
    def _show_message_if_no_device(self) -> None:
        if self._device is None:
            self._print("Waiting for USB device to appear...")
    def run(self):
        mgr = frida.get_device_manager()

        on_devices_changed = lambda: self._reactor.schedule(self._try_start)
        mgr.on("changed", on_devices_changed)

        self._reactor.schedule(self._try_start)
        self._reactor.schedule(self._show_message_if_no_device, delay=1)

        signal.signal(signal.SIGTERM, self._on_sigterm)

        self._reactor.run()

        if self._started:
            try:
                self._perform_on_background_thread(self._stop)
            except frida.OperationCancelledError:
                pass

        if self._session is not None:
            self._session.off("detached", self._schedule_on_session_detached)
            try:
                self._perform_on_background_thread(self._session.detach)
            except frida.OperationCancelledError:
                pass
            self._session = None

        if self._device is not None:
            self._device.off("output", self._schedule_on_output)
            self._device.off("lost", self._schedule_on_device_lost)

        mgr.off("changed", on_devices_changed)

        frida.shutdown()
        sys.exit(0)
    def _update_status(self, message) -> None:
            print( message )
    def _exit(self, exit_status: int) -> None:
        self._exit_status = exit_status
        self._reactor.stop()
    def _process_input(self, reactor: Reactor) -> None:
        try:
            while self._ready.wait(0.5) != True:
                if not reactor.is_running():
                    return
        except KeyboardInterrupt:
            self._reactor.cancel_io()
            return

        while True:
            try:
                if self._stopping.wait(1):
                    break
            except KeyboardInterrupt:
                self._reactor.cancel_io()
                return
    def _on_session_detached(self, reason: str, crash) -> None:
        if crash is None:
            message = reason[0].upper() + reason[1:].replace("-", " ")
        else:
            message = "Process crashed: " + crash.summary
        self._print( message)
        if crash is not None:
            self._print("\n***\n{}\n***".format(crash.report.rstrip("\n")))
        self._exit(1)





def on_message(payload, data,app):
    if isinstance(payload,dict):
        if payload["msg"]=="ready":
          del payload["msg"]
          print(json.dumps(payload))
          #print(f"DSN: {payload["dsn"]} secrets: {payload["secrets"]}")
          app._exit(0)
          
def main():
    global script_text
    targ=args.target
    if targ is None:
        targ=("identifier","com.amazon.kindle")
    app = MiniReactor(args.host,targ,script_text,on_message)
    app.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
