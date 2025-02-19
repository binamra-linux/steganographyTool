import unittest
import os
from PIL import Image
import mysql.connector
from updated import Steganography, UserAuth, DB_CONFIG

class TestSteganographySystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n=== Starting Steganography System Tests ===")
        # Initialize database connection for testing
        cls.auth = UserAuth()
        # Create a sample image for testing
        cls.input_image = "test_input.png"
        cls.output_image_lsb = "test_output_lsb.png"
        cls.output_image_hex = "test_output_hex.png"
        cls.secret_message = "Hello, Steganography!"
        cls.test_username = "test_user"
        cls.test_password = "test_password123"
        
        # Create test image
        img = Image.new('RGB', (100, 100), color=(255, 255, 255))
        img.save(cls.input_image)
        print("✓ Test environment setup completed")
        
        # Initialize steganography object
        cls.stego = Steganography()

    def setUp(self):
        # Clean up any existing test user
        try:
            self.auth.cursor.execute("DELETE FROM message_history WHERE user_id IN (SELECT id FROM users WHERE username = %s)", (self.test_username,))
            self.auth.cursor.execute("DELETE FROM users WHERE username = %s", (self.test_username,))
            self.auth.db.commit()
        except mysql.connector.Error:
            self.auth.db.rollback()

    @classmethod
    def tearDownClass(cls):
        print("\n=== Cleaning Up Test Environment ===")
        # Remove test files
        for file in [cls.input_image, cls.output_image_lsb, cls.output_image_hex]:
            if os.path.exists(file):
                os.remove(file)
        
        # Clean up database
        cls.auth.close()
        print("✓ Cleanup completed")
        print("\n=== Test Suite Completed ===")

    def test_1_database_connection(self):
        print("\nTest 1: Database Connection")
        try:
            self.assertIsNotNone(self.auth.db)
            self.assertIsNotNone(self.auth.cursor)
            
            # Test if tables exist
            self.auth.cursor.execute("SHOW TABLES")
            tables = [table[0] for table in self.auth.cursor.fetchall()]
            self.assertIn('users', tables)
            self.assertIn('message_history', tables)
            print("✓ Database connection successful")
            print("✓ Required tables exist")
        except AssertionError as e:
            print("✗ Database connection test failed:", str(e))
            raise

    def test_2_user_registration_and_login(self):
        print("\nTest 2: User Registration and Login")
        try:
            # Test registration
            registration_result = self.auth.register(self.test_username, self.test_password)
            self.assertTrue(registration_result)
            print("✓ User registration successful")
            
            # Test login
            user = self.auth.login(self.test_username, self.test_password)
            self.assertIsNotNone(user)
            self.assertEqual(user[1], self.test_username)
            print(" User login successful")
            
            # Test duplicate registration
            duplicate_registration = self.auth.register(self.test_username, self.test_password)
            self.assertFalse(duplicate_registration)
            print("✓ Duplicate registration prevented")
        except AssertionError as e:
            print("✗ User authentication test failed:", str(e))
            raise

    def test_3_lsb_steganography(self):
        print("\nTest 3: LSB Steganography")
        try:
            self.stego.encode_image(self.input_image, self.secret_message, 
                                  self.output_image_lsb, method="lsb")
            self.assertTrue(os.path.exists(self.output_image_lsb))
            print("✓ LSB encoding successful")
            
            decoded_message = self.stego.decode_image(self.output_image_lsb, method="lsb")
            self.assertEqual(decoded_message, self.secret_message)
            print("✓ LSB decoding successful")
        except AssertionError as e:
            print("✗ LSB steganography test failed:", str(e))
            raise

    def test_4_hex_steganography(self):
        print("\nTest 4: HEX Steganography")
        try:
            self.stego.encode_image(self.input_image, self.secret_message, 
                                  self.output_image_hex, method="hex")
            self.assertTrue(os.path.exists(self.output_image_hex))
            print("✓ HEX encoding successful")
            
            decoded_message = self.stego.decode_image(self.output_image_hex, method="hex")
            self.assertEqual(decoded_message, self.secret_message)
            print("✓ HEX decoding successful")
        except AssertionError as e:
            print("✗ HEX steganography test failed:", str(e))
            raise


if __name__ == '__main__':
    unittest.main()