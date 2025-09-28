from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re  # We'll include the detector class directly
import uvicorn

# Include the detector class directly in main.py
class SimplePhisingDetector:
    def __init__(self):
        # List of suspicious websites/domains
        self.bad_domains = [
            'bit.ly', 'tinyurl.com',
            'secure-bank-update', 'urgent-verification',
            'free-money', 'prize-winner'
        ]
        
        # List of legitimate websites
        self.good_domains = [
            'google.com', 'sbi.co.in',
            'icicibank.com', 'amazon.in', 'paytm.com'
        ]
        
        # Scam message patterns
        self.scam_words = {
            'urgent': ['urgent', 'immediate', 'expires today', 'act now'],
            'money': ['you have won', 'prize money', 'free money', 'claim now'],
            'banking': ['account suspended', 'verify account', 'update kyc'],
            'phishing': ['click here', 'verify identity', 'confirm details']
        }

        print("Detector Brain Created")

    def check_url(self, url):
        print(f"Checking the url: {url}")

        if not url:
            return {
                'message': "Please Enter the URL!", 
                'score': 0, 
                'warnings': []
            }

        url = url.lower()
        danger_score = 0
        warnings = []

        # Is it a bad domain in url
        for bad_domain in self.bad_domains:
            if bad_domain in url:
                danger_score += 3
                warnings.append(f"⚠️ Contains suspicious domain: {bad_domain}")

        # Is it a good_domain
        is_good_domain = False
        for good_domain in self.good_domains:
            if good_domain in url:
                is_good_domain = True
                break

        # Does it use HTTPS (secure connection)?
        if not url.startswith('https://'):
            danger_score += 2
            warnings.append("⚠️ Not using secure HTTPS connection")

        # check whether url contains any IP address instead of domain
        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            danger_score += 4
            warnings.append("🚨 Using IP address instead of domain name")

        # Now let decide how dangerous this url is
        if is_good_domain and danger_score <= 1:
            result = "✅ SAFE: This appears to be a legitimate website"
        elif danger_score >= 5:
            result = "🚨 DANGER: This URL is highly suspicious!"
        elif danger_score >= 2:
            result = "⚠️ WARNING: This URL has some red flags"
        else:
            result = "❓ UNKNOWN: Be cautious with this URL"

        return {
            'message': result,
            'score': danger_score,
            'warnings': warnings
        }

    def check_messages(self, message):
        print("Analysing the message.....")

        if not message:
            return {
                'message': 'Please Enter The Message!', 
                'score': 0, 
                'patterns': []
            }
        
        message = message.lower()
        danger_score = 0
        found_patterns = []

        # Check each category of scam words
        for category, words in self.scam_words.items():
            for word in words:
                if word in message:
                    danger_score += 2
                    found_patterns.append(f"{category.title()}: '{word}'")

        # Check for phone numbers (scammers often include phone numbers)
        if re.search(r'\d{10}', message):
            danger_score += 1
            found_patterns.append("Phone number detected")

        # Check for generic greetings (sign of mass scam messages)
        if 'dear coustmer' in message or 'dear sir' in message:
            danger_score += 1
            found_patterns.append("Generic greeting (not personalized)")
            
        # Decide danger level
        if danger_score >= 6:
            result = "🚨 DANGER: This message shows multiple scam signs!"
        elif danger_score >= 3:
            result = "⚠️ WARNING: This message has suspicious elements"
        elif danger_score >= 1:
            result = "❓ CAUTION: Some concerning patterns found"
        else:
            result = "✅ SAFE: Message appears relatively safe"

        return {
            'message': result,
            'score': danger_score,
            'patterns': found_patterns
        }

# Create FastAPI app
app = FastAPI(title="PhishAlert API", version="1.0")

# Allow frontend to connect (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, change to your frontend URL
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize your detector
detector = SimplePhisingDetector()

# Define what data we expect from frontend
class URLRequest(BaseModel):
    url: str

class MessageRequest(BaseModel):
    message: str

# API Routes - Match the frontend expectations
@app.get("/")
async def root():
    return {"message": "PhishAlert API is running! 🛡️"}

@app.post("/check-url")  # Changed from /api/check-url to /check-url
async def check_url(request: URLRequest):
    try:
        result = detector.check_url(request.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/check-message")  # Changed from /api/check-message to /check-message
async def check_message(request: MessageRequest):
    try:
        result = detector.check_messages(request.message)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Run the server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)