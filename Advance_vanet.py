"""
Advanced VANET Security Simulation
---------------------------------
Features:
1. Hybrid Cryptography (ECDSA + AES-GCM)
2. Dynamic Trust Management
3. Geographical Routing
4. Attack Simulations (Sybil, Wormhole, Greyhole)
5. Performance Monitoring
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import random
import time
import math
import pandas as pd
from dataclasses import dataclass
from typing import Dict, List, Tuple
import matplotlib.pyplot as plt
import os
# ========================
# Core Security Components
# ========================

class CryptoEngine:
    @staticmethod
    def generate_ec_keys():
        """Generate ECDSA key pair for digital signatures"""
        return ec.generate_private_key(ec.SECP384R1(), default_backend())

    @staticmethod
    def generate_rsa_keys():
        """Generate RSA key pair for encryption"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    @staticmethod
    def derive_aes_key(shared_secret: bytes, salt: bytes = b'vanet_salt') -> bytes:
        """Derive AES key using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(shared_secret)

    @staticmethod
    def aes_encrypt(message: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt with AES-GCM"""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return iv, ciphertext, encryptor.tag

    @staticmethod
    def aes_decrypt(iv: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> bytes:
        """Decrypt with AES-GCM"""
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

# =================
# Vehicle Class
# =================

@dataclass
class VehicleState:
    position: Tuple[float, float] = (0.0, 0.0)
    speed: float = 0.0
    direction: float = 0.0  # radians
    timestamp: float = time.time()

class Vehicle:
    def __init__(self, vehicle_id: str, is_malicious: bool = False):
        self.id = vehicle_id
        self.state = VehicleState()
        self.is_malicious = is_malicious
        
        # Cryptographic identities
        self.ec_private = CryptoEngine.generate_ec_keys()
        self.ec_public = self.ec_private.public_key()
        self.rsa_private = CryptoEngine.generate_rsa_keys()
        self.rsa_public = self.rsa_private.public_key()
        
        # Session management
        self.session_keys = {}  # {peer_id: (key, expiry)}
        self.message_log = []
        self.trust_scores = {}  # {peer_id: score}
        
    def update_position(self, delta_time: float):
        """Update vehicle position based on movement model"""
        dx = self.state.speed * math.cos(self.state.direction) * delta_time
        dy = self.state.speed * math.sin(self.state.direction) * delta_time
        self.state.position = (
            self.state.position[0] + dx,
            self.state.position[1] + dy
        )
        self.state.timestamp = time.time()
    
    def establish_session(self, peer_public_key) -> bytes:
        """ECDHE key exchange"""
        shared_key = self.ec_private.exchange(
            ec.ECDH(),
            peer_public_key
        )
        session_key = CryptoEngine.derive_aes_key(shared_key)
        return session_key
    
    def sign_message(self, message: bytes) -> bytes:
        """Sign message with ECDSA"""
        return self.ec_private.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
    
    def verify_signature(self, message: bytes, signature: bytes, public_key) -> bool:
        """Verify ECDSA signature"""
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False
    
    def encrypt_message(self, peer_id: str, plaintext: str) -> Tuple[bytes, bytes, bytes, bytes]:
        """End-to-end encrypted communication"""
        if peer_id not in self.session_keys:
            raise ValueError("No session established with this peer")
        
        key, _ = self.session_keys[peer_id]
        iv, ciphertext, tag = CryptoEngine.aes_encrypt(plaintext.encode(), key)
        return iv, ciphertext, tag
    
    def create_beacon(self) -> Dict:
        """Create periodic safety beacon"""
        beacon = {
            'type': 'beacon',
            'sender': self.id,
            'position': self.state.position,
            'speed': self.state.speed,
            'direction': self.state.direction,
            'timestamp': self.state.timestamp
        }
        return beacon

# =====================
# Trust Management
# =====================

class TrustManager:
    def __init__(self):
        self.trust_db = {}  # {vehicle_id: TrustRecord}
    
    def update_trust(self, vehicle_id: str, interaction_positive: bool):
        if vehicle_id not in self.trust_db:
            self.trust_db[vehicle_id] = {'score': 0.5, 'count': 0}
        
        record = self.trust_db[vehicle_id]
        if interaction_positive:
            record['score'] = min(1.0, record['score'] + 0.05)
        else:
            record['score'] = max(0.0, record['score'] - 0.2)
        record['count'] += 1
    
    def get_trust_score(self, vehicle_id: str) -> float:
        return self.trust_db.get(vehicle_id, {'score': 0.0})['score']
    
    def should_accept(self, vehicle_id: str) -> bool:
        return self.get_trust_score(vehicle_id) > 0.3

# =====================
# Attack Simulations
# =====================

class AttackSimulator:
    @staticmethod
    def sybil_attack(attacker: Vehicle, num_fake: int = 3) -> List[Vehicle]:
        """Create fake vehicle identities"""
        return [
            Vehicle(f"Sybil_{attacker.id}_{i}", is_malicious=True)
            for i in range(num_fake)
        ]
    
    @staticmethod
    def greyhole_attack(vehicle: Vehicle, drop_prob: float = 0.5) -> bool:
        """Selectively drop packets"""
        return random.random() < drop_prob
    
    @staticmethod
    def wormhole_attack(sender: Vehicle, receiver: Vehicle, tunnel_length: float = 1000.0):
        """Simulate message tunneling"""
        original_distance = math.dist(sender.state.position, receiver.state.position)
        if original_distance > tunnel_length:
            # Simulate unrealistic fast propagation
            return {
                'type': 'wormhole',
                'original_sender': sender.id,
                'tunnel_length': tunnel_length,
                'timestamp': time.time()
            }
        return None

# =====================
# Network Simulation
# =====================

class VANETSimulator:
    def __init__(self):
        self.vehicles = {}
        self.trust = TrustManager()
        self.attack_prob = 0.2  # Probability of attack occurring
        self.metrics = {
            'messages_sent': 0,
            'messages_dropped': 0,
            'attack_attempts': 0,
            'detected_attacks': 0
        }
    
    def add_vehicle(self, vehicle: Vehicle):
        self.vehicles[vehicle.id] = vehicle
    
    def simulate_movement(self, delta_time: float):
        for vehicle in self.vehicles.values():
            vehicle.update_position(delta_time)
    
    def send_message(self, sender_id: str, recipient_id: str, message: str) -> bool:
        if sender_id not in self.vehicles or recipient_id not in self.vehicles:
            return False
        
        sender = self.vehicles[sender_id]
        recipient = self.vehicles[recipient_id]
        
        # Establish session if needed
        if recipient_id not in sender.session_keys:
            session_key = sender.establish_session(recipient.ec_public)
            sender.session_keys[recipient_id] = (session_key, time.time() + 3600)  # 1hr expiry
            recipient.session_keys[sender_id] = (session_key, time.time() + 3600)
        
        # Encrypt message
        iv, ciphertext, tag = sender.encrypt_message(recipient_id, message)
        
        # Simulate network transmission
        if random.random() < 0.1:  # 10% packet loss
            self.metrics['messages_dropped'] += 1
            return False
        
        # Check for attacks
        if sender.is_malicious or random.random() < self.attack_prob:
            self.metrics['attack_attempts'] += 1
            if random.random() < 0.7:  # 70% detection rate
                self.metrics['detected_attacks'] += 1
                return False
        
        # Decrypt message
        key, _ = recipient.session_keys[sender_id]
        try:
            plaintext = CryptoEngine.aes_decrypt(iv, ciphertext, tag, key)
            self.trust.update_trust(sender_id, True)
            self.metrics['messages_sent'] += 1
            return True
        except:
            self.trust.update_trust(sender_id, False)
            return False
    
    def broadcast_beacon(self, sender_id: str) -> int:
        """Flooding-based beacon propagation"""
        if sender_id not in self.vehicles:
            return 0
        
        sender = self.vehicles[sender_id]
        beacon = sender.create_beacon()
        neighbors = self.get_neighbors(sender_id, 300)  # 300m range
        
        successful = 0
        for neighbor in neighbors:
            if self.send_message(sender_id, neighbor.id, str(beacon)):
                successful += 1
        
        return successful
    
    def get_neighbors(self, vehicle_id: str, max_distance: float) -> List[Vehicle]:
        """Get vehicles within communication range"""
        if vehicle_id not in self.vehicles:
            return []
        
        source = self.vehicles[vehicle_id]
        neighbors = []
        
        for vid, vehicle in self.vehicles.items():
            if vid == vehicle_id:
                continue
                
            distance = math.dist(source.state.position, vehicle.state.position)
            if distance <= max_distance:
                neighbors.append(vehicle)
        
        return neighbors
    
    def generate_report(self) -> pd.DataFrame:
        """Generate performance metrics report"""
        return pd.DataFrame({
            'Metric': [
                'Messages Sent',
                'Messages Dropped',
                'Attack Attempts',
                'Detected Attacks',
                'Detection Rate'
            ],
            'Value': [
                self.metrics['messages_sent'],
                self.metrics['messages_dropped'],
                self.metrics['attack_attempts'],
                self.metrics['detected_attacks'],
                self.metrics['detected_attacks'] / max(1, self.metrics['attack_attempts'])
            ]
        })

# =====================
# Demo Execution
# =====================

def main():
    print("=== Advanced VANET Security Simulation ===")
    
    # Initialize simulation
    sim = VANETSimulator()
    
    # Create legitimate vehicles
    for i in range(5):
        v = Vehicle(f"V{i+1}")
        v.state.position = (random.uniform(0, 1000), random.uniform(0, 1000))
        v.state.speed = random.uniform(5, 30)  # m/s
        v.state.direction = random.uniform(0, 2*math.pi)
        sim.add_vehicle(v)
    
    # Create attacker
    attacker = Vehicle("Attacker", is_malicious=True)
    attacker.state.position = (500, 500)
    sim.add_vehicle(attacker)
    
    # Simulate network operation
    for _ in range(10):  # 10 simulation steps
        sim.simulate_movement(1.0)  # 1 second intervals
        
        # Normal communication
        for i in range(5):
            sender = f"V{random.randint(1,5)}"
            receiver = f"V{random.randint(1,5)}"
            if sender != receiver:
                sim.send_message(sender, receiver, f"Test message at {time.time()}")
        
        # Beacon broadcasts
        for v in sim.vehicles.values():
            if not v.is_malicious:
                sim.broadcast_beacon(v.id)
        
        # Simulate attacks
        if random.random() < 0.3:  # 30% chance of attack
            attack_type = random.choice(["sybil", "greyhole", "wormhole"])
            
            if attack_type == "sybil":
                fake_nodes = AttackSimulator.sybil_attack(attacker)
                for node in fake_nodes:
                    sim.add_vehicle(node)
            
            elif attack_type == "greyhole":
                AttackSimulator.greyhole_attack(attacker)
            
            elif attack_type == "wormhole":
                target = random.choice(list(sim.vehicles.values()))
                if target.id != attacker.id:
                    AttackSimulator.wormhole_attack(attacker, target)
    
    # Generate report
    report = sim.generate_report()
    print("\nSimulation Report:")
    print(report)
    
    # Visualization
    plt.figure(figsize=(10, 5))
    report.plot(x='Metric', y='Value', kind='bar', legend=False)
    plt.title("VANET Security Metrics")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()