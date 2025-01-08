import base64           # Used for base64 encoding/decoding of packet data
from scapy.all import ( # Scapy library provides easy packet crafting and parsing
    IP, TCP, Raw, raw
)
import socket           # Standard library for network connections (sockets)


def print_banner(): #Prints an ASCII art banner for the challenge, along with a brief introduction to the "Shake My Hand Challenge."
    # The 'r' prefix keeps the raw string formatting intact, making it easier
    # to display backslashes and special characters in ASCII art.
    print(r"""
╔══════════════════════════════════════════════════════════════════════╗
║ █████╗ ██████╗ ███╗   ███╗██╗██████╗  █████╗ ██╗                    ║
║██╔══██╗██╔══██╗████╗ ████║██║██╔══██╗██╔══██╗██║                    ║
║███████║██║  ██║██╔████╔██║██║██████╔╝███████║██║                    ║
║██╔══██║██║  ██║██║╚██╔╝██║██║██╔══██╗██╔══██║██║                    ║
║██║  ██║██████╔╝██║ ╚═╝ ██║██║██║  ██║██║  ██║███████╗               ║
║╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝               ║
║                                                                      ║
║                ━━━━━━━━━━━━ SYN-ACKbar's ━━━━━━━━━━━━                ║
║                [ Shake My Hand Challenge Walkthrough ]                ║
║                                                                      ║
║        "Come all ye saints and SYNers" - Admiral SYN-ACKbar          ║
╚══════════════════════════════════════════════════════════════════════╝
             ▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀
             █▓▒░ PRESS ENTER TO CONTINUE ░▒▓█
             ▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄▀▄ 
""")
    input("") #Wait for user to press enter before continuing
    print("""
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀[ TCP HANDSHAKE THEORY ]▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀

Every time you connect to a website or server, a TCP handshake occurs behind
the scenes. This three-way process ensures both sides can reliably communicate:

╔═[ 1 ]═══════════════════════════════════════════════════╗
║     [CLIENT]         ──SYN (SEQ=x)───>         [SERVER] ║
║                                                         ║
║     "Hey, can we talk? My sequence number is x"         ║
╚═════════════════════════════════════════════════════════╝
╔═[ 2 ]═══════════════════════════════════════════════════╗
║     [CLIENT]    <──SYN-ACK (SEQ=y,ACK=x+1)──   [SERVER] ║
║                                                         ║
║     "Sure! My sequence is y, and I got your x"          ║
╚═════════════════════════════════════════════════════════╝
╔═[ 3 ]═══════════════════════════════════════════════════╗
║     [CLIENT]         ──ACK (ACK=y+1)───>       [SERVER] ║
║                                                         ║
║     "Perfect! Connection established!"                   ║
╚═════════════════════════════════════════════════════════╝

In this challenge, we'll manually perform each step of this handshake
to better understand how TCP connections work. We'll use Scapy to craft
each packet (see script comments for further details).""")

def log(msg, level=0, newline=False): ##Logs a message to the console, allowing for an adjustable indentation level.
    indent = "  " * level
    if newline:
        print(f"\n{indent}[*] {msg}")
    else:
        print(f"{indent}[*] {msg}")

def get_connection_details(): #Prompts the user for the challenge server address and port. Sets default to "shake-my-hand.chal.irisc.tf:10501".
    default = "shake-my-hand.chal.irisc.tf:10501"
    print("\nPress enter to accept default challenge address (shake-my-hand.chal.irisc.tf:10501) or enter custom below:")
    print("> ", end='', flush=True)
    addr = input().strip()  # Read user input

    # If user hits enter, they get the default address:port
    if not addr:
        addr = default

    # Checks to ensure that address address contains a colon for host and port
    if ':' in addr:
        host, port_str = addr.split(':', 1)
        try:
            port = int(port_str)  # Convert the port string to an integer so it can be used in entwork connection
        except ValueError:
            raise ValueError("Invalid port number")
    else:
        raise ValueError("Please provide both address and port in format host:port")

    return host, port


class ChallengeConnection: 
    """
    Manages the script creating a TCP connection to the challenge server.
    The user's IP in the Network Simulator changes on each connection. This reads from the banner to determine the server/client IP.
    """
    def __init__(self):
        host, port = get_connection_details() # Get connection details from user input
        log(f"Connecting to {host}:{port}...")

        # Create a socket for the connection (IPv4, TCP)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((host, port))
        except Exception as e:
            log(f"Connection failed: {str(e)}")
            raise

        self.buffer = ""      # Temporary buffer to store incoming data
        self.target_ip = None # Will hold the server/challenge IP from the challenge connection banner
        self.my_ip = None     # Will hold the client IP from the challenge connection banner

        # The server's banner is read until we see "--[ Layer 3 ]", then reads IPs from it
        data = self.recv_until("--[ Layer 3 ]")
        self.parse_ips(data)

    def parse_ips(self, data): #Parses the text of the initial banner to find lines containing "Challenge IP:" and "Your IP:" and stores them in self.target_ip and self.my_ip.
        for line in data.splitlines():
            if "Challenge IP:" in line:
                # Everything after "Challenge IP:" is the server's IP
                self.target_ip = line.split(": ")[1].strip()
            elif "Your IP:" in line:
                # Everything after "Your IP:" is our assigned IP
                self.my_ip = line.split(": ")[1].strip()

        if not self.target_ip or not self.my_ip:
            raise ValueError("Could not parse IP addresses from banner")

    def recv_until(self, marker): #Reads data from the socket until a specific marker is found, then returns the data read.
        data = ""
        while marker not in data: #Keep reading until we see the marker
            chunk = self.sock.recv(4096).decode() #Read up to 4096 bytes from the socket
            if not chunk:
                raise ConnectionError("Connection closed by server")
            print(chunk, end='')  # Echo the received data to the console
            data += chunk #Append the chunk to our data
        return data #Return the data read up to the marker

    def readline(self): #Reads a line of data from the server, ignoring lines that start with '>' or 'Adding'.
        while True:
            # If we don't have a newline in our buffer, read more from socket
            while '\n' not in self.buffer: #If we don't have a newline in our buffer, read more from socket
                data = self.sock.recv(4096).decode('utf-8') 
                if not data:
                    return None  # Connection closed
                print(data, end='')  # Echo to the screen
                self.buffer += data

            # Split at the first newline
            line, self.buffer = self.buffer.split('\n', 1)
            line = line.strip()  # Remove extra whitespace
            if line and not line.startswith('>') and not line.startswith('Adding'):
                return line  # Return the non-empty, relevant line

    def write(self, data): #Sends a command or data to the server via the socket, appending a newline. Also echoes the command to the user.
        print(f"\n>>> {data}")
        self.sock.send(f"{data}\n".encode('utf-8'))

    def close(self): #Closes the socket connection to the challenge server.
        self.sock.close()


def parse_packet(b64_packet): #Decodes a base64-encoded packet and parses it into a Scapy IP packet object.
    # Decode from base64, then parse with IP(...) to get a Scapy packet
    return IP(base64.b64decode(b64_packet))


def decode_and_show(b64_packet): #Decodes a base64 packet, logs details about IP/TCP layers, sequence/ack numbers, flags, and payload. Returns the Scapy packet object.
    try:
        pkt = parse_packet(b64_packet)
        log("Packet Contents:", level=1, newline=True)

        # Show IP metadata with no extra newlines
        log(f"Source IP: {pkt[IP].src}", 2, newline=False)
        log(f"Dest IP: {pkt[IP].dst}", 2, newline=False)

        # TCP info with no extra newlines
        if TCP in pkt:
            log(f"TCP Flags: {pkt[TCP].flags}", 2, newline=False)
            log(f"Sequence: {pkt[TCP].seq}", 2, newline=False)
            log(f"Ack: {pkt[TCP].ack}", 2, newline=False)

        # Payload with no extra newlines
        if Raw in pkt:
            try:
                payload_str = bytes(pkt[Raw]).decode()
            except UnicodeDecodeError:
                payload_str = repr(bytes(pkt[Raw]))
            log(f"Payload: {payload_str}", 2, newline=False)

        # Add final newline after packet contents
        #print("")
        return pkt

    except Exception as e:
        log(f"Error decoding packet: {e}", newline=True)
        return None

def create_syn(my_ip, target_ip): #
    # Inform the user about the SYN packet creation
    log("Creating SYN packet with flags=S. This indicates we're initiating the handshake.")

    # Create a Scapy IP/TCP packet:
    #   - IP(...) sets up source/destination IP addresses.
    #   - TCP(..., flags="S") sets the SYN flag for initial connection request.
    #   - seq=1000 is our starting sequence number for demonstration.
    pkt = IP(src=my_ip, dst=target_ip)/TCP(
        sport=12345,    # Arbitrary source port
        dport=9999,     # Challenge port
        flags="S",      # SYN flag
        seq=1000        # Our chosen initial sequence
    )

    # Convert to raw bytes, then base64 for transmission
    return base64.b64encode(raw(pkt)).decode()


def create_ack(my_ip, target_ip, server_seq, server_ack): #Creates an ACK packet to acknowledge the server's SYN-ACK, completing the TCP handshake.
    # Log the creation of an ACK packet
    log("Creating ACK packet (flags=A) to complete the 3-way handshake.")

    # Sequence is set to what the server last acknowledged (server_ack).
    # We acknowledge the server's sequence with server_seq + 1.
    pkt = IP(src=my_ip, dst=target_ip)/TCP(
        sport=12345,
        dport=9999,
        flags="A",            # ACK flag
        seq=server_ack,       # Advance our sequence to what the server last acked
        ack=server_seq + 1    # Acknowledge the server's SYN sequence
    )

    return base64.b64encode(raw(pkt)).decode() # Return base64-encoded packet for transmission


def create_response(my_ip, target_ip, my_seq, server_ack, payload): ##Creates a TCP packet with PSH+ACK (flags=PA) to send data to the server.
    log(f"Creating a data packet (flags=PA) with payload {payload} to answer the server.") 

    # Build IP + TCP (PSH+ACK) packet
    pkt = IP(src=my_ip, dst=target_ip)/TCP( 
        sport=12345,
        dport=9999,
        seq=my_seq,
        ack=server_ack,
        flags="PA"  # This represents PSH + ACK
    )/payload

    return base64.b64encode(raw(pkt)).decode()

def print_step_header(step_num):
    print(f"""
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
█ ▀▄▀▄▀▄  MISSION {step_num}/6  ▄▀▄▀▄▀ █
█ ▌▐▌▐▌  LOADING...  ▐▌▐▌▐▌ █ 
█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█
    """)

def print_victory_banner():
    print(r"""
▀▄▀▄▀▀▄▀▄▀▄▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▄▀▄▀▄▀▄▀▄▀

██╗   ██╗ ██████╗ ██╗   ██╗    ██████╗ ██╗██████╗     ██╗████████╗██╗
╚██╗ ██╔╝██╔═══██╗██║   ██║    ██╔══██╗██║██╔══██╗    ██║╚══██╔══╝██║
 ╚████╔╝ ██║   ██║██║   ██║    ██║  ██║██║██║  ██║    ██║   ██║   ██║
  ╚██╔╝  ██║   ██║██║   ██║    ██║  ██║██║██║  ██║    ██║   ██║   ╚═╝
   ██║   ╚██████╔╝╚██████╔╝    ██████╔╝██║██████╔╝    ██║   ██║   ██╗
   ╚═╝    ╚═════╝  ╚═════╝     ╚═════╝ ╚═╝╚═════╝     ╚═╝   ╚═╝   ╚═╝

▄▀▄▀▄▀▄▀▄▀▄▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▄▄▀▄▀▄▀▄▀
""")

def main(): #Main function that orchestrates the TCP handshake challenge.
    """
    Main challenge flow:
    1. Print banner and logs about the challenge.
    2. Create a ChallengeConnection to handle communication and gather IP info.
    3. Send a SYN packet (create_syn) to initiate the handshake.
    4. Receive SYN-ACK from server, decode, display it.
    5. Send ACK (create_ack) to finish handshake.
    6. Receive a prompt from server and parse the data.
    7. Send a response (create_response) with "yes" to request the flag.
    8. Receive the final packet with the flag data, display it to the user.
    """
    print_banner()

    conn = None # Initialize connection variable to None
    try:
        # Create and connect to the challenge server
        conn = ChallengeConnection()
        log(f"Connected - Target IP: {conn.target_ip}, Your IP: {conn.my_ip}", level=1, newline=True)

        # Step 1: Build and show SYN packet to initiate connection
        print_step_header(1)
        log("Step 1: Let's start the TCP handshake by creating and sending a SYN packet.", newline=True)
        log("SYN is the first stage of the handshake (SYN -> SYN-ACK -> ACK).", level=1, newline=True)
        syn_b64 = create_syn(conn.my_ip, conn.target_ip) #Create SYN packet
        log("Below is a decoded view of the SYN packet so you can see IPs, flags, and SEQ number:", newline=True)
        decode_and_show(syn_b64)

        # Prompt user to send it
        cmd = input(f"\n> Press enter to send the base64-encoded SYN packet with `emit {syn_b64}`: ")
        conn.write(f"emit {syn_b64}") #Send the SYN packet to the server with the challenge's emit command

        # Wait for SYN-ACK from server
        print_step_header(2)
        log("Step 2: Now we expect the server to reply with a SYN-ACK, meaning it acknowledges our SYN and sends its own SYN.", newline=True)
        log("We'll receive and decode that packet to examine its SEQ and ACK numbers.", level=1, newline=True)
        cmd = input("\n> Press enter to send the `recv` command to simulate receiving the SYN-ACK packet: ")
        conn.write("recv")
        synack_b64 = conn.readline()       # Read the next line, should be base64 packet
        synack_pkt = decode_and_show(synack_b64)  # Decode and show response

        # Step 3: Build and send ACK
        print_step_header(3)
        log("Step 3: Let's complete the handshake by sending an ACK for the server's SYN.", newline=True)
        log("This ensures both sides agree on the initial SEQ numbers, finalizing the connection.", level=1, newline=True)
        server_seq = synack_pkt[TCP].seq
        server_ack = synack_pkt[TCP].ack
        ack_b64 = create_ack(conn.my_ip, conn.target_ip, server_seq, server_ack)
        log("Decoded ACK packet to confirm we're acknowledging the server's SYN:", newline=True)
        decode_and_show(ack_b64)

        cmd = input(f"\n> Press enter to send base64-encoded ACK packet with `emit {ack_b64}`: ")
        conn.write(f"emit {ack_b64}")

        # Step 4: Check for server prompt or data
        print_step_header(4)
        log("Step 4: The handshake should be established now! The server might send a prompt or additional data.", newline=True)
        cmd = input("\n> Press enter to send the `recv` command and see if the server sends a prompt: ")
        conn.write("recv")
        prompt_b64 = conn.readline()      # Possibly the "Print flag? [yes|no]" prompt
        prompt_pkt = decode_and_show(prompt_b64)

        # If there's a raw payload, log it
        if Raw in prompt_pkt:
            log("It looks like the server is asking if we want to print the flag: 'Print flag? [yes|no]'")

        # Step 5: Send "yes" to request the flag
        print_step_header(5)
        log("Step 5: We'll answer 'yes' with a PSH+ACK packet, sending data immediately and staying in sync with the server's sequence.", newline=True)
        data_len = len(prompt_pkt[Raw]) if Raw in prompt_pkt else 0
        new_ack = prompt_pkt[TCP].seq + data_len  # Acknowledge what's in the prompt
        my_seq = server_ack                       # Our seq is what the server acked

        yes_b64 = create_response(conn.my_ip, conn.target_ip, my_seq, new_ack, b"yes\n")
        log("Decoded view of our 'yes' packet:", newline=True)
        decode_and_show(yes_b64)

        cmd = input(f"\n> Press enter to send the base64-encoded command for yes, `emit {yes_b64}`: ")
        conn.write(f"emit {yes_b64}")

        # Step 6: Receive the flag
        print_step_header(6)
        log("Step 6: We expect the server to send the flag now that we've answered 'yes'.", newline=True)
        cmd = input("\n> Press enter to send the `recv` command and get the final packet which should contain the flag: ")
        conn.write("recv")
        flag_b64 = conn.readline()      # This should be the flag packet
        flag_pkt = decode_and_show(flag_b64)

        # If there's a readable payload, show it to the user
        if Raw in flag_pkt:
            flag_data = bytes(flag_pkt[Raw]).decode(errors="replace")
            print("\n" + "=" * 60)
            print(flag_data)
            print("=" * 60)

        log("You've just completed a manual TCP three-way handshake and retrieved the challenge flag!", level=1)
        print_victory_banner()

    except Exception as e:
        # Any errors during this process get logged
        log(f"Error: {str(e)}")
    finally:
        # If we established a connection, close it gracefully
        if conn:
            conn.close()


# If this script is run directly (rather than imported), call main()
if __name__ == "__main__":
    main()