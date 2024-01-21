import threading
import subprocess
import time

PROJECT_ID = "epfl-dse"
UDP_PORT = 4242

PACKETS_PER_SECOND = 20


class Peer:
    def __init__(self, name, zone):
        self.ip = None
        self.name = name
        self.zone = zone

    def create(self):
        # Create the VM on Google Cloud
        subprocess.run(f"""gcloud compute instances create {self.name} \
            --project {PROJECT_ID} \
            --zone {self.zone} \
            --image-family ubuntu-2204-lts \
            --image-project ubuntu-os-cloud \
            --machine-type=n2-standard-2 \
        """, shell=True)

        time.sleep(30)

        # Update the system and install dependencies
        self.run_command("sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get install -y unzip")
    
    def stop(self):
        subprocess.run(f"""gcloud compute instances stop {self.name} \
            --project {PROJECT_ID} \
            --zone {self.zone} \
        """, shell=True)

    def delete(self):
        subprocess.run(f"""gcloud compute instances delete {self.name} \
            --project {PROJECT_ID} \
            --zone {self.zone} \
            --quiet \
        """, shell=True)

    def get_ip(self):
        if self.ip is not None:
            return self.ip
        self.ip = subprocess.check_output(f"""gcloud compute instances describe {self.name} \
            --project {PROJECT_ID} \
            --zone {self.zone} \
            --format 'value(networkInterfaces[0].accessConfigs[0].natIP)' \
        """, shell=True, text=True).strip()
        return self.ip
    
    def run_command(self, command):
        subprocess.run(f"""gcloud compute ssh {self.name} \
            --project {PROJECT_ID} \
            --zone {self.zone} \
            --command '{command}' \
        """, shell=True)

peers = {
    'paris': Peer('peer-paris', 'europe-west9-a'),
    'zurich': Peer('peer-zurich', 'europe-west6-a'),
    'berlin': Peer('peer-berlin', 'europe-west10-c'),
    'las-vegas': Peer('peer-las-vegas', 'europe-west4-a'),
    'sao-paulo': Peer('peer-sao-paulo', 'southamerica-east1-b'),
    'doha': Peer('peer-doha', 'me-central1-a'),
    'hong-kong': Peer('peer-hong-kong', 'asia-east2-a'),
    'sydney': Peer('peer-sydney', 'australia-southeast1-b'),
}

neighbors = {
    'paris': ['zurich', 'berlin', 'las-vegas'],
    'zurich': ['paris', 'berlin', 'doha'],
    'berlin': ['paris', 'zurich', 'hong-kong'],
    'las-vegas': ['paris', 'sao-paulo'],
    'sao-paulo': ['las-vegas', 'doha'],
    'doha': ['sao-paulo', 'zurich', 'hong-kong', 'sydney'],
    'hong-kong': ['berlin', 'doha', 'sydney'],
    'sydney': ['hong-kong', 'doha']
}

# Create all the peers
for _, p in peers.items():
    p.create()

# Prepare the peers
for loc, p in peers.items():
    print(loc + ': ' + p.get_ip())

for loc, p in peers.items():
    p.run_command("wget https://www.adrienvannson.fr/vm-peer.zip && unzip -o vm-peer.zip && chmod +x vm-peer")

# Start the peers
def start_peer(name):
    ip_neighbors = ' '.join([peers[n].get_ip() + ':4242' for n in neighbors[name]])
    peers[name].run_command(f"nohup ./vm-peer {peers[name].get_ip()} 4242 {PACKETS_PER_SECOND} {len(peers)} {len(neighbors[name])} " + ip_neighbors + " > output 2>&1 &")

threads = [threading.Thread(target=start_peer, args=(name,)) for name in peers]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()

# Stop the peers
for _, p in peers.items():
    p.stop()