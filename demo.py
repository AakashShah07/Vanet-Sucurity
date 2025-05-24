from vanet import VANETSimulator
import time
import hashlib
def main():
    print("🚗 VANET Security Demonstration 🚗")
    print("--------------------------------")
    
    # Setup network
    net = VANETSimulator()
    net.add_vehicle("V1")
    net.add_vehicle("V2")
    net.add_vehicle("Attacker")
    
    # Normal communication
    print("\n=== Normal Secure Communication ===")
    net.send_message("V1", "V2", "Emergency brake ahead!")
    time.sleep(1)
    net.send_message("V2", "V1", "Acknowledged, slowing down")
    
    # Attack simulation
    print("\n=== Attack Simulation ===")
    net.simulate_attack("Attacker", "V2", "Fake emergency: Clear road ahead!")
    
    # Tampered message simulation
    print("\n=== Message Tampering Simulation ===")
    # This would require intercepting and modifying in transit
    # For demo, we'll just create an invalid signature
    v1 = net.vehicles["V1"]
    message, _, good_signature = v1.create_secure_message("Real traffic update")
    print(f"Original message: {message}")
    
    # Tamper with the message
    message['content'] = "Fake traffic update"
    print(f"Tampered message: {message}")
    
    # Verification should fail
    v2 = net.vehicles["V2"]
    message_str = str(message)
    message_hash = hashlib.sha256(message_str.encode()).hexdigest()
    is_valid = v2.verify_signature(
        message_hash,
        good_signature,  # Using original signature
        v1.public_key
    )
    
    print("✅ Valid" if is_valid else "❌ Tampering detected!")

if __name__ == "__main__":
    main()