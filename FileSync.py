import os
import socket
import tqdm
import json
import time
import threading
import signal
import hashlib
import shutil
import sys


class Node():

    def __init__(self):

        # Global flag
        self.GLOBAL_FLAG = False

        # PORTS
        self.COMM_IN = 9822
        self.FILE_IN = 9823
        
        # IP range to scan (last octet)
        self.IP_RANGE_START = 190
        self.IP_RANGE_END = 220

        self.IP_CHAIN = {socket.gethostbyname_ex(socket.gethostname())[-1][-1]}

        # Exit flag
        self.exit_event = threading.Event()

        # Socket constants
        self.BUFFER_SIZE = 8192
        self.SEPARATOR = "<SEPARATOR>"

        self.ROOT_DIR = '\\files'
        self.ROOT = os.getcwd() + self.ROOT_DIR

        self.meta_time = 0

        # If a file system update was logged when the program was previously running, update self.meta_time
        if os.path.isfile(os.getcwd() + '\\metadata.txt'):
            with open(os.getcwd() + '\\metadata.txt', 'r') as f:
                self.meta_time = int(f.read())
            
        # dir_json_compare((os.getcwd() + '\\dir.json', os.getcwd() + '\\metadata.txt'), (os.getcwd() + '\\dir-new.json', os.getcwd() + '\\metadata-new.txt'))

        """
            Steps to be performed on start up
            1. self.connect_to_network() in order to update self.IP_CHAIN
            2. Run self.comm_listener() on a thread to give participate in IP_CHAIN updates, and receive file metadata updates
            3. Run self.generate_dir_json() on a thread, if generate_dir_json() returns True, an update has taken place.
               This update should broadcast the time of update (metadata.txt) and update details (dir.json) to all IPs
               on the self.IP_CHAIN.
            # 4. Run self.file_listener() on a thread to serve files to any clients on the network that request them
        """
        # Ping all local IPs 3 times in order to 
        self.connect_to_network(1)
        # self.ping()

        # Thread to participate in IP_CHAIN updates
        self.t_in = threading.Thread(target=self.comm_listener)
        self.t_in.start()

        # Thread to broadcast file system metadata updates and request files
        self.t_out = threading.Thread(target=self.client_logic)
        self.t_out.start()

        # Thread to listen for incoming files
        self.f_out = threading.Thread(target=self.file_listener)
        self.f_out.start()

        signal.signal(signal.SIGINT, self.signal_handler)

        # Listen for an exit event on the main thread
        while not self.exit_event.is_set():
            time.sleep(1)


    # Generates dir.json on file update and sends out file system metadata to devices on IP_CHAIN
    def client_logic(self):
        while not self.exit_event.is_set():
            # Global flag will be set to True if scheduled file modifications are taking place
            if self.GLOBAL_FLAG:
                print(f'GLOBAL_FLAG lock - client')
                return None
            update = self.generate_dir_json()
            print('Updated' if update else 'Already up to date')
            # Broadcast data from metadata.txt and dir.json to all devices on the IP_CHAIN
            if update:
                print('Broadcasting file system update')
                s = socket.socket()
                for address in self.IP_CHAIN:
                    if address != socket.gethostbyname_ex(socket.gethostname())[-1][-1]:
                        try:
                            print(f'Sending file updates to {address}:{self.FILE_IN}')
                            s.connect((address, self.FILE_IN))
                            #'1<SEPARATOR>{time.time_ns()}<SEPARATOR>{JSON_OBJECT_DIR}'
                            with open(os.getcwd() + "\\dir.json", 'r') as f:
                                json_payload = f.read()
                            s.send((f'1{self.SEPARATOR}{str(time.time_ns())}{self.SEPARATOR}{json_payload}').encode())
                        except Exception as e:
                            print(f'{address}:{self.FILE_IN} did not accept file metadata update !! {e}')

            # Wait 5 seconds in between checks
            time.sleep(5)



    # Kills threads on exit signal (CTRL + C)    
    def signal_handler(self, signum, frame):
        self.exit_event.set()
        # Send a kill message to the comm_listener() @port COMM_IN
        s = socket.socket()
        s.connect((socket.gethostbyname_ex(socket.gethostname())[-1][-1], self.COMM_IN))
        s.send('-1'.encode()) # Send exit signal to self.COMM_IN

        s = socket.socket()
        s.connect((socket.gethostbyname_ex(socket.gethostname())[-1][-1], self.FILE_IN))
        s.send('-1'.encode()) # Send exit signal to self.FILE_OUT
    
        self.t_in.join() # Exits comm in thread
        self.t_out.join() # Exits comm out thread
        self.f_out.join() # Exits file in thread
        print('Listeners and threads killed')


    # Read a nested json value -- dev function
    # pylint: disable=unused-argument
    def read_layer(self, json_dict, indices):
        access = json_dict
        for index in indices:
            access = access[index]
        return access

    # Return data stored in dir.json, if the file does not
    # exist, return an empty json
    def read_json(self, path):
        if not os.path.isfile(path):
            return {}
        with open(path, 'r') as json_file:
            return json.load(json_file)

    # Recursively goes through directory, gathering file names, their associated path, and the last time
    # that their content was modified. Create a json to be saved as 'dir.json'
    def find_endpoints(self, path, json_dict, layer):
        # json_dict = {}
        for file_name in os.listdir(path):
            # If there is no file extension, it is a subdirectory 
            if len(file_name.split('.')) == 1:
                # Add the subdirectory to json_dict
                split_layers = path.replace(os.getcwd() + "\\", "").split("\\")
                if type(split_layers) != list:
                    split_layers = [split_layers]
                split_layers.append(file_name)
                
                # json_dict = append_to_dict(json_dict, split_layers, {})
                if str(split_layers) not in json_dict:
                    json_dict[str(split_layers)] = {}
                # Call function and iterate through the subdirectory
                self.find_endpoints(os.path.join(path, file_name), json_dict, layer=layer+1)
            else:
                # Get the directories in between the file and the working directory
                split_layers = path.replace(os.getcwd() + "\\", "").split("\\")
                if type(split_layers) != list:
                    split_layers = [split_layers]
                # # Append the file and metadata to the json_dict
                # data = {file_name: [os.stat(os.path.join(path, file_name)).st_mtime]}

                # Hash file contents for a unique file signature
                md5 = hashlib.md5()
                with open(os.path.join(path, file_name), 'rb') as f:
                    while True:
                        chunk = f.read(self.BUFFER_SIZE)
                        if not chunk:
                            break
                        md5.update(chunk)

                # Append the file and metadata to the json_dict
                data = {file_name: [md5.hexdigest()]}
                
                # result.append((split_layers, data))
                # print(split_layers)
                if str(split_layers) not in json_dict:
                    json_dict[str(split_layers)] = {}
                # print(result[str(split_layers)])
                json_dict[str(split_layers)] = json_dict[str(split_layers)] | data

        return json_dict    

    # If dir.json does not exist, generate a blank dir.json. Otherwise
    # write the passed in data to dir.json
    def write_json(self, json_dict={}, path=os.getcwd()):
        with open(path + '\\dir.json', 'w') as json_file:
            json.dump(json_dict, json_file, sort_keys=True)

    # Iterate through the layers in the dict and append the data to the desired location
    def append_to_dict(self, json_dict, indices, data):
        access = json_dict

        for index in indices:
            # If the directory does not exist, create it
            if index not in access:
                access[index] = {}
                if index == indices[-1]:
                    access[index] = data
                    return json_dict
                # Go deeper into the json
                access = access[index]
            else:
                # If the directory exists, merge the existing contents
                # with the data that needs to be added
                if index == indices[-1]:
                    access[index] = access[index] | data
                    return json_dict
                # Go deeper into the json
                # print(index)
                access = access[index]

    """
    If the dir.json is not identical to the current hierarchical structure of the 
    root directory (along with identical metadata), then dir.json will be overwritten
    to correspond with the current directory.
    A metadata file will be generated at completion of the operation to store time of
    the original-last dir.json generation
    """
    def generate_dir_json(self, root=None):

        if root == None:
            root = self.ROOT

        generated = self.find_endpoints(root, {}, 0)
        # print(f'generated: {generated}')
        if generated != self.read_json(os.getcwd() + '\\dir.json'):
            self.write_json(generated)
            # Generate a time stamp to keep track of when this dir.json was generated
            with open('metadata.txt', 'w') as f:
                self.meta_time = time.time_ns()
                f.write(str(self.meta_time))
            return True 
        else:
            return False
        

    # Compare the two directories, output a list of modifications.
    # If the two directories are identical, output an empty list.
    # By default this function will not modify any files unless
    # sandbox is set to False.
    # Requests files from IP associated with other_dir
    def dir_json_compare(self, self_dir, other_dir, other_ip, sandbox=True):

        request = []
        
        json_dict_1 = self.read_json(self_dir[0])
        # json_dict_2 = self.read_json(dir[0])
        json_dict_2 = json.loads(other_dir[0])
        print(f'type(json_dict_2): {type(json_dict_2)}')

        self_dir_time = 0
        other_dir_time = other_dir[1]
        with open(self_dir[1], 'r') as f:
            self_dir_time = int(f.read())

        print(self_dir_time)
        print(other_dir_time)

        # This assumes that if two directories were created at the exact same time in ns
        # then self_dir is arbitrarily chosen to take precedence
        if json_dict_1 == json_dict_2 or self_dir_time > other_dir_time:
            return request
        else:
            """
                If other_dir is more current than self_dir
            """
            print('self_dir < other_dir')
            for subdirectory in json_dict_1:
                # If a subdirectory is not present in other_dir that is present in self_dir
                if subdirectory not in json_dict_2:
                    if not sandbox:
                        # Delete subdirectory and contents
                        request.append(['-', subdirectory, {}])

                    # print('-', subdirectory)
                    # print('-', subdirectory, json_dict_1[subdirectory])
            for subdirectory in json_dict_2:
                # If a subdirectory is not present in self_dir that is present in other_dir
                if subdirectory not in json_dict_1:
                    if len(json_dict_2[subdirectory]) == 0:
                        request.append(['+', subdirectory, {}])
                    for file in json_dict_2[subdirectory]:
                        if not sandbox: 
                            request.append(['+', subdirectory, file]) # Request file(s)

                else:
                    if json_dict_1[subdirectory] != json_dict_2[subdirectory]:
                        for file in json_dict_1[subdirectory]:
                            if file not in json_dict_2[subdirectory]:
                                if not sandbox:
                                    request.append(['-', subdirectory, file])
                                    pass # Delete file
                                # print("- %s {'%s': %s}" % (subdirectory, file, json_dict_1[subdirectory][file])) 
                        for file in json_dict_2[subdirectory]:
                            # Request file
                            if not sandbox: 
                                request.append(['+', subdirectory, file])
                                pass
            return request
                                

    # Send a specific file to a specific target machine on LAN
    def send(self, target_ip='192.168.254.199', file_name='data3.jpg', root=None):

        if root == None:
            root = self.ROOT

        file_path = root + file_name

        filesize = os.path.getsize(file_path)

        s = socket.socket()
        print(f"Connecting to {target_ip}:{self.FILE_IN}")
        s.connect((target_ip, self.FILE_IN))
        print("Connected.")

        s.send(f"{file_path}{self.SEPARATOR}{filesize}".encode())

        # progress = tqdm.tqdm(range(filesize), f"Sending {file_path}", unit='B', unit_scale=True, unit_divisor=1024)
        with open(file_path, 'rb') as f:
            while True:
                bytes_read = f.read(self.BUFFER_SIZE)
                if not bytes_read:
                    break
                s.sendall(bytes_read)
                # progress.update(len(bytes_read))
        s.close()

   





    """
    Used to send a request to a target ip, to request to join the IP_CHAIN
    
    """
    def ping(self, ip, port=None):

        if port == None:
            port = self.COMM_IN

        s = socket.socket()
        # Tested to have a 92% success rate on LAN
        s.settimeout(0.1)
        try:
            # Send self.IP_CHAIN
            s.connect((ip, port))
            s.send((f'0{self.SEPARATOR}{self.IP_CHAIN}').encode())
            # Get updated IP_CHAIN in response
            response = s.recv(self.BUFFER_SIZE).decode()
            data = response.replace('{', '').replace('}', '').replace("'", '').replace(' ', '').split(',')
            for address in data:
                self.IP_CHAIN.add(address)
            print(f'Updated IP_CHAIN: {self.IP_CHAIN}')
            s.close()
            return True
        except Exception as e:
            print(f'{ip}:{port} did not respond !! {e}')
            # print(f'Error: {e}')
            # return False
            

    # Scan the desired IP range by pinging all targets at the communication port
    def connect_to_network(self, attempts=1, port=None):

        # If 0 attempts is sent, do not attempt to connect to the network
        if attempts == 0:
            return None

        if port == None:
            port = self.COMM_IN

        # Ping all ips 'attempts' times in order to prevent from timeouts
        # resulting in invalid data
        for i in range(attempts):
            for i in range(self.IP_RANGE_START, self.IP_RANGE_END):
                ip = '192.168.254.%s' % i
                if self.ping(ip, port):
                    return None



    """
    FILE LISTENER
    File listener will listen for 
    1. File system updates from other machines
    2. Compare file system data
    3. Request/ send files (lock client thread to prevent sending updates in the middle of updating own file system)
    """
    def file_listener(self, root=None):
        # Loop as long as the exit event (ctrl + c) is not sent
        while not self.exit_event.is_set():        
                        
            if root == None:
                root = self.ROOT

            s = socket.socket()
            s.bind(('0.0.0.0', self.FILE_IN))
            s.listen(5)
            print("Listening as %s:%d for files" % (socket.gethostbyname_ex(socket.gethostname())[-1][-1], self.FILE_IN))
            
            try:
                client_socket = s.accept()

                # '0<SEPARATOR>{[filepath, filepath2, filepath3]}<SEPARATOR>filename.ext<SEPARATOR>filesize'
                received = client_socket[0].recv(self.BUFFER_SIZE).decode().split(self.SEPARATOR)
                other_ip = client_socket[1][0]
                # -1 Exit call
                if received[0] == '-1':
                    client_socket[0].close()
                    s.close()
                    return None
                if received[0] == 'FILE-REQ':
                    # Split the request into individual files
                    split_data = received[1][2:-1].replace('}', '').split(', {')
                    self.send_files(client_socket, split_data, other_ip)
                # 1: Update file system (request comes from self.client_logic())
                # Request format: '1<SEPARATOR>{time.time_ns()}<SEPARATOR>{JSON_OBJECT_DIR}'
                if received[0] == '1':
                    request = self.dir_json_compare((os.getcwd() + '\\dir.json', os.getcwd() + '\\metadata.txt'), (received[2], int(received[1])), other_ip, False)

                    # If the request is not empty, lock threads -> delete and request files
                    if request != []:
                        # Lock threads
                        self.GLOBAL_FLAG = True

                        files_needed = []
                        # Iterate through and decipher each requested operation 
                        # to attain matching file systems
                        for operation in request:
                            op_path = os.getcwd()
                            path_list = operation[1].replace('[', '').replace(']', '').replace("'", '').replace(' ', '').split(',')
                            for path_fragment in path_list: 
                                op_path = os.path.join(op_path, path_fragment)

                            # Delete from local directory
                            if operation[0] == '-':
                                if operation[2] == {}: # Delete subdirectory and all contents
                                    shutil.rmtree(op_path)
                                else: # Delete file
                                    os.remove(os.path.join(op_path, operation[2]))
                            # Request files to add to local directory
                            if operation[0] == '+':
                                # If not an empty subdirectory, add the file to the request
                                if operation[2] != {}: 
                                    files_needed.append({operation[1]: operation[2]})
                                # Otherwise generate the empty subdirectory
                                else: 
                                    os.mkdir(op_path)

                        # Close previous socket connection
                        s.close()
                        # Request files if needed
                        if files_needed != []:
                            print(f'file request to be sent: {files_needed}')
                            self.request_files(files_needed, other_ip)
                            
            except Exception as e:
                print(f'File listener exception: {e}')
            finally:
                client_socket[0].close()
                s.close()
            
            # Unlock the client thread to allow file system checks/ updates to continue
            self.GLOBAL_FLAG = False
        


    """
    1. REQUEST FILE(S)
    2. RECIEVE FILE(S) 
    :param files_needed: list of files needed along with their relative path and file name
    :param target_ip: target_ip is the ip of the device that has the files 
    """
    def request_files(self, files_needed, target_ip):
        try:
            self.GLOBAL_FLAG = True
            s = socket.socket()
            print(f'FILE-REQ{self.SEPARATOR}{files_needed}')
            s.connect((target_ip, self.FILE_IN))

            # Send a request for the files that are needed in order to have matching files
            s.send(f'FILE-REQ{self.SEPARATOR}{files_needed}'.encode())
            s.close()

            # Listen for incoming files
            try:
                s = socket.socket()
                s.bind(('0.0.0.0', self.FILE_IN))
                s.listen(5)
                print('LISTEN FOR INCOMING FILES')
                while True:
                    client_socket = s.accept()
                    
                    chunk = client_socket[0].recv(self.BUFFER_SIZE)
                    # print(f'chunk not decoded: {chunk}')
                    chunk = chunk.decode().split(self.SEPARATOR)
                    # If files are done sending break out of loop and match last update time
                    if chunk[0] == '<EXIT>':
                        # Make the metadata.txt time match with the device that sent the update
                        with open(os.getcwd() + '\\metadata.txt', 'w') as f:
                            f.write(chunk[1])
                        client_socket[0].close()
                        s.close()
                        break
                    
                    # Store data into local variables
                    relative_path = chunk[1].split('\\')[0:-1]
                    file_size = int(chunk[2])
                    file_name = chunk[1].split('\\')[-1]
                    
                    # If the directory does not exist, make it
                    path_accumulator = os.getcwd()
                    for path_fragment in relative_path:
                        path_accumulator = os.path.join(path_accumulator, path_fragment)
                        if not os.path.exists(path_accumulator):
                            os.mkdir(path_accumulator)
                    
                    # Write file bytes to their designated path as they are sent
                    with open(os.path.join(os.getcwd(), chunk[1]), 'wb') as f:
                        while True:
                            bytes_read = client_socket[0].recv(self.BUFFER_SIZE)
                            if not bytes_read:
                                break
                            f.write(bytes_read)
                
            except Exception as e:
                s.close()
                print(f'File recv exception {e}')
        except Exception as e:
            s.close()
            print(f'File request exception {e}')
        finally:
            s.close()

        self.GLOBAL_FLAG = False


    """
    1. LISTEN FOR FILE(S) REQUEST
    2. SENDS FILE(S) TO REQUESTEE
    send_files() will send any amount of files to the device that requested them
    """
    def send_files(self, client_socket, request, other_ip):
        
        try:
        
            # Create new socket for sending files
            s = socket.socket()


            # Further format the request data to generate the local file path
            for item in request:
                path_raw, file_name_raw = item.split(':')
                # Further format request string
                path = path_raw.replace('"', '').replace('[', '').replace(']', '').replace("'", '').replace(' ', '').split(',')
                file_name = file_name_raw.replace("'", '').replace(' ', '')

                # Generate local, absolute path
                local_path = os.getcwd()
                # Generate relative path
                rel_path = ''
                for path_fragment in path:
                    local_path = os.path.join(local_path, path_fragment)
                    rel_path = os.path.join(rel_path, path_fragment)

                # EMPTY DIRECTORY -- GENERATE DIR BEFORE SENDING FILE REQUEST
                if file_name == '{':
                    os.mkdir(rel_path)
                    s.close() 
                    continue
                
                s.close() 


                # SEND FILE
                file_location = os.path.join(local_path, file_name)
                if os.path.isfile(file_location):
                    s = socket.socket()
                    s.connect((other_ip, self.FILE_IN))
                    filesize = os.path.getsize(file_location)
                    # Send file meta data
                    payload = f'9{self.SEPARATOR}{os.path.join(rel_path, file_name)}{self.SEPARATOR}{filesize}{self.SEPARATOR}'
                    for i in range(self.BUFFER_SIZE - len(payload)):
                        payload += '0'
                    s.send(payload.encode())
                    
                    # Send file bytes
                    with open(file_location, 'rb') as f:
                        while True:
                            bytes_read = f.read(self.BUFFER_SIZE)
                            if not bytes_read:
                                break
                            s.sendall(bytes_read)
                    s.close()
                
            
            # Send file transfer terminate signal
            s = socket.socket()
            s.connect((other_ip, self.FILE_IN))

            with open('metadata.txt', 'r') as f:
                timestamp = f.read()
                s.send(f'<EXIT>{self.SEPARATOR}{timestamp}'.encode())
                s.close()

        


        except Exception as e:
            print(f'Exception: {e}')
            client_socket[0].close()
            s.close()
        finally:
            client_socket[0].close()
            s.close()
            print('Connection closed')

    """
    COMM LISTENER
    Comm listener will
    Listen for devices wanting to join the network and add them to the IP_CHAIN
    """
    def comm_listener(self):

        # Continuously run this listener
        while not self.exit_event.is_set():
            s = socket.socket()
            s.bind(('0.0.0.0', self.COMM_IN))
            s.listen(5)
            print("Listening as %s:%d for communication" % (socket.gethostbyname_ex(socket.gethostname())[-1][-1], self.COMM_IN))

            try:
                client_socket = s.accept()

                # Format of requests will be '0<SEPARATOR>['ip0', 'ip2', 'ip3'] 
                # or '1<SEPARATOR>{time.time_ns()}<SEPARATOR>{JSON_OBJECT_DIR}'
                received = client_socket[0].recv(self.BUFFER_SIZE).decode().split(self.SEPARATOR)
                other_ip = client_socket[1][0]
                # 0: Update IP_CHAIN (devices on the file sharing network)
                if received[0] == '0':
                    
                    print(f'Add {other_ip} to the network')
                    data = received[1].replace('{', '').replace('}', '').replace("'", '').replace(' ', '').split(',')
                    if len(data) == 1:
                        self.IP_CHAIN.add(data[0])
                    elif len(data) > 1:
                        for ip in data:
                            self.IP_CHAIN.add(ip)
                    client_socket[0].send(str(self.IP_CHAIN).encode())
                    print(self.IP_CHAIN)
                   
                # -1 Exit call
                if received[0] == '-1':
                    client_socket[0].close()
                    s.close()
                    return None
            except Exception as e:
                print(f'!! Comm listener error: {e}')
            finally:
                s.close()
                client_socket[0].close()

            

if __name__ == '__main__':
   Node()
