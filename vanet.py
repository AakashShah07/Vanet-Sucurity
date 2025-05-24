from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import hashlib
import random
import time

class Vehicle:
    """Vehicle class for VANET with cryptographic capabilities"""
    def __init__(self, vehicle_id):
        self.id = vehicle_id
        # Generate cryptographic keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
    def sign_message(self, message):
        """Sign a message using private key"""
        return self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
    def verify_signature(self, message, signature, sender_public_key):
        """Verify a received message"""
        try:
            sender_public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
            
    def create_secure_message(self, content):
        """Create message with hash and signature"""
        message = {
            'sender': self.id,
            'content': content,
            'timestamp': time.time()
        }
        # Convert to string for hashing
        message_str = str(message)
        # Generate hash
        message_hash = hashlib.sha256(message_str.encode()).hexdigest()
        # Sign the hash
        signature = self.sign_message(message_hash)
        return message, message_hash, signature
    
class VANETSimulator:
    def __init__(self):
        self.vehicles = {}
        self.messages = []
        
    def add_vehicle(self, vehicle_id):
        self.vehicles[vehicle_id] = Vehicle(vehicle_id)
        
    def send_message(self, sender_id, recipient_id, content):
        """Simulate secure message transmission"""
        if sender_id not in self.vehicles or recipient_id not in self.vehicles:
            return False
            
        sender = self.vehicles[sender_id]
        recipient = self.vehicles[recipient_id]
        
        # Create secure message
        message, message_hash, signature = sender.create_secure_message(content)
        
        # Simulate transmission
        print(f"\nVehicle {sender_id} sending to {recipient_id}:")
        print(f"Original message: {message}")
        
        # Verify at recipient side
        is_valid = recipient.verify_signature(
            message_hash,
            signature,
            sender.public_key
        )
        
        if is_valid:
            print("✅ Message verified successfully!")
            self.messages.append({
                'sender': sender_id,
                'recipient': recipient_id,
                'content': content,
                'status': 'valid'
            })
            return True
        else:
            print("❌ Message verification failed! Possible attack!")
            self.messages.append({
                'sender': sender_id,
                'recipient': recipient_id,
                'content': content,
                'status': 'invalid'
            })
            return False
            
    def simulate_attack(self, attacker_id, recipient_id, fake_content):
        """Simulate a malicious message injection"""
        if attacker_id not in self.vehicles or recipient_id not in self.vehicles:
            return False
            
        print(f"\n🚨 Attack simulation: {attacker_id} trying to impersonate another vehicle")
        
        # Attacker creates fake message
        fake_message = {
            'sender': "V1",  # Pretending to be V1
            'content': fake_content,
            'timestamp': time.time()
        }
        fake_message_str = str(fake_message)
        fake_hash = hashlib.sha256(fake_message_str.encode()).hexdigest()
        
        # Sign with attacker's own key (not V1's key)
        attacker = self.vehicles[attacker_id]
        fake_signature = attacker.sign_message(fake_hash)
        
        # Recipient verification
        recipient = self.vehicles[recipient_id]
        real_v1 = self.vehicles["V1"]
        is_valid = recipient.verify_signature(
            fake_hash,
            fake_signature,
            real_v1.public_key  # Using V1's real public key
        )
        
        if not is_valid:
            print("🔥 Attack detected! Signature verification failed!")
            return False
        else:
            print("💀 Attack succeeded! (This would be bad in real life)")
            return True