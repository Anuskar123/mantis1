import hashlib
import zlib

# MANTIS Phase 7: Fourth Algorithm (Bloom Filter for IP Blacklisting)
# First Principles Implementation

class BloomFilter:
    def __init__(self, size=1000, hash_count=3):
        """
        Initializes a Probabilistic Bloom Filter.
        Args:
            size (int): Size of the bit array (Default 1000 bits).
            hash_count (int): Number of hash functions to use (Default 3).
        """
        self.size = size
        self.hash_count = hash_count
        # Initialize a bit array (all zeros)
        # In Python, we can simulate a bit array using a boolean list or bytearray
        self.bit_array = [0] * size
        
    def _hashes(self, item):
        """
        Generates 'k' hash values for a given item.
        We simulate different hash functions by salting the input string.
        """
        hashes = []
        item_str = str(item)
        
        # Hash 1: CRC32
        h1 = zlib.crc32(item_str.encode('utf-8')) % self.size
        hashes.append(h1)
        
        # Hash 2: MD5 (Simulated via hashlib, taking first few bytes)
        h2_full = hashlib.md5(item_str.encode('utf-8')).hexdigest()
        h2 = int(h2_full, 16) % self.size
        hashes.append(h2)
        
        # Hash 3: Custom Simple Hash (Sum of ASCII values + Shift)
        h3_val = 0
        for char in item_str:
            h3_val = (h3_val << 5) + ord(char)
        h3 = h3_val % self.size
        hashes.append(h3)
        
        return hashes[:self.hash_count]

    def add(self, item):
        """
        Adds an item to the Bloom Filter.
        """
        for index in self._hashes(item):
            self.bit_array[index] = 1 # Set the bit to True

    def check(self, item):
        """
        Checks if an item is likely in the set.
        Returns True if PROBABLY present.
        Returns False if DEFINITELY NOT present.
        """
        for index in self._hashes(item):
            if self.bit_array[index] == 0:
                return False # If any bit is 0, it's definitely not here.
        return True

# ==========================================
# TEST HARNESS
# ==========================================
if __name__ == "__main__":
    print("[*] Testing Bloom Filter (Probabilistic Data Structure)...")
    
    # Create the filter
    bf = BloomFilter(size=100, hash_count=3)
    
    # Add Malicious IPs (Simulating Threat Intel Feed)
    bad_ips = ["192.168.1.100", "10.0.0.5", "172.16.0.1"]
    print(f"[*] Adding to Blacklist: {bad_ips}")
    for ip in bad_ips:
        bf.add(ip)
        
    # Check IPs
    test_ips = ["192.168.1.100", "8.8.8.8", "10.0.0.5", "127.0.0.1"]
    
    for ip in test_ips:
        result = bf.check(ip)
        status = "BLACKLISTED!" if result else "Clean"
        print(f"   Check IP: {ip.ljust(15)} -> {status}")
