import os
import time
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def test_connection():
    try:
        print("\n=== Initializing Gemini API ===")
        # Configure the Gemini API
        genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
        
        # Initialize the model
        model = genai.GenerativeModel('gemini-1.5-pro')
        print("✓ API Initialized Successfully")
        
        print("\n=== Starting Conversation with Gemini ===")
        
        # Start a chat session
        chat = model.start_chat(history=[])
        
        # First message
        print("\nUser: Tell me a short, interesting fact about artificial intelligence.")
        response1 = chat.send_message("Tell me a short, interesting fact about artificial intelligence.")
        print("\nGemini:", response1.text)
        
        # Wait for 2 seconds
        time.sleep(2)
        
        # Second message
        print("\nUser: Can you explain that in more detail?")
        response2 = chat.send_message("Can you explain that in more detail?")
        print("\nGemini:", response2.text)
        
        # Wait for 2 seconds
        time.sleep(2)
        
        # Third message
        print("\nUser: What are some real-world applications of this technology?")
        response3 = chat.send_message("What are some real-world applications of this technology?")
        print("\nGemini:", response3.text)
        
        print("\n=== Test Complete ===")
        return True
    except Exception as e:
        print("\nError connecting to Gemini API:", str(e))
        return False

if __name__ == "__main__":
    test_connection() 