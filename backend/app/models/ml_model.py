

import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import numpy as np

class PhishingDetector:
    """
    ML-based phishing detection using:
    - Random Forest Classifier (200 trees, max_depth=20)
    - TF-IDF Vectorization (1000 features, 1-4 grams)
    """
    
    def __init__(self, model_path='data/trained_model.pkl'):
        self.model_path = model_path
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 4),  # Unigrams to 4-grams
            stop_words='english',
            lowercase=True,
            strip_accents='unicode'
        )
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        self.is_trained = False
        
        # Try to load existing model
        self._load_model()
    
    def _get_training_data(self):
        """
        Generate comprehensive training dataset
        Returns: (texts, labels) where label 1 = phishing, 0 = legitimate
        """
        
        # PHISHING SAMPLES (Label = 1)
        phishing_samples = [
            # Account suspension scams
            "urgent your account has been suspended verify immediately to restore access",
            "action required your paypal account will be closed verify now",
            "warning your bank account is locked click here to unlock",
            "suspended account verify your identity within 24 hours",
            "your account has been compromised reset password immediately",
            "final notice your account will be terminated verify now",
            "security alert unusual activity detected confirm identity",
            "account verification required click link immediately",
            
            # Prize/lottery scams
            "congratulations you won 1 million dollars claim your prize now",
            "you are the lucky winner click to collect your reward",
            "claim your prize today limited time offer expires soon",
            "winner notification you have been selected for cash prize",
            "lottery win confirm your details to receive payment",
            "you won click here to claim your reward immediately",
            "congratulations winner claim prize before expiry",
            
            # Banking alerts
            "urgent bank notification verify your credit card details",
            "unusual activity detected on your account confirm transaction",
            "your card has been blocked update information immediately",
            "refund pending click here to claim your money back",
            "payment failed update your billing information now",
            "bank alert verify your account to prevent closure",
            "credit card suspended update details immediately",
            
            # Tax/government scams
            "irs tax refund pending claim your refund today",
            "government grant awarded verify eligibility immediately",
            "tax notice urgent action required click to respond",
            "refund approved from revenue department claim now",
            "tax refund waiting confirm details to receive money",
            
            # Generic phishing patterns
            "verify your email address click this link immediately",
            "update your payment method to avoid service interruption",
            "confirm your identity to prevent account closure",
            "reset your password your account security is at risk",
            "click here to validate your credentials urgent",
            "limited time offer act now before it expires",
            "your package delivery failed update address immediately",
            "security alert unusual login attempt verify activity",
            "account verification required click link to confirm",
            "update required your information is outdated verify now",
            
            # Advanced phishing
            "dear valued customer urgent security update required",
            "this is final notice verify within 48 hours",
            "immediate attention needed your account at risk",
            "you have 1 pending refund claim it before expiry",
            "wire transfer failed resubmit bank details",
            "upgrade your account today special discount expires tonight",
            "confirm subscription renewal to avoid charges",
            "your order has been shipped track package click here",
            "invoice attached please review and pay immediately",
            "password reset requested click to confirm change",
            
            # Social engineering
            "help i am stranded send money urgently",
            "investment opportunity guaranteed returns act fast",
            "your friend sent you money claim it now",
            "charity donation request help people in need",
            "job offer work from home earn thousands weekly",
            
            # More variations with urgency
            "suspended verify suspended account verify click now",
            "urgent urgent verify account immediately click here",
            "winner prize claim lottery won congratulations act now",
            "bank account locked update verify credit card details",
            "refund pending tax irs claim money transfer immediately",
            "confirm payment details expired update billing information",
            "security breach detected reset password click link",
            "winner selected claim reward before midnight expires",
        ]
        
        # LEGITIMATE SAMPLES (Label = 0)
        legitimate_samples = [
            # Order confirmations
            "your order has been confirmed delivery expected in 3-5 days",
            "thank you for your purchase order number 12345",
            "order shipped tracking number available in your account",
            "receipt for your recent purchase thank you for shopping",
            "your subscription has been renewed thank you",
            "order confirmation your items are being prepared",
            "shipment notification your package is on the way",
            
            # Meeting invitations
            "meeting scheduled for tomorrow at 2pm please confirm attendance",
            "invitation team sync call next week",
            "reminder project review meeting on friday",
            "calendar invite quarterly planning session",
            "you have been invited to join the webinar",
            "meeting request from john for next monday",
            "conference call scheduled please join at 3pm",
            
            # Newsletters
            "weekly newsletter latest updates and announcements",
            "monthly digest top articles and news from our blog",
            "new features released check out what is new",
            "product updates and improvements this month",
            "company newsletter employee spotlight and events",
            "newsletter subscribe to receive weekly updates",
            "blog post notification new article published",
            
            # System notifications
            "your password was successfully changed",
            "login from new device notification for your security",
            "two factor authentication enabled on your account",
            "subscription renewed automatically thank you",
            "account settings updated successfully",
            "profile information updated confirmation",
            "notification settings changed as requested",
            
            # Professional emails
            "project status update all tasks on track",
            "quarterly report attached for your review",
            "invoice for services rendered payment terms net 30",
            "contract renewal discussion next steps",
            "performance review scheduled please prepare documents",
            "team meeting notes from yesterday session",
            "project milestone completed moving to next phase",
            
            # Customer service
            "thank you for contacting support ticket number assigned",
            "your issue has been resolved please confirm",
            "feedback request help us improve our service",
            "appointment confirmed see you soon",
            "shipping notification your package is on the way",
            "support ticket update we are working on your request",
            "customer service response to your inquiry",
            
            # Social updates
            "someone liked your post check it out",
            "you have new connections on linkedin",
            "weekly activity summary from your network",
            "comment on your post view conversation",
            "friend request pending review profile",
            "photo tagged notification from friend",
            "group invitation join our community",
            
            # Normal correspondence
            "meeting notes attached for reference",
            "following up on our conversation last week",
            "document shared with you view and edit access",
            "event reminder seminar starts in one hour",
            "welcome to the team orientation schedule attached",
            "thank you for attending the session yesterday",
            "project files shared in team folder",
            
            # Educational
            "course enrollment confirmed access materials online",
            "assignment due date reminder submit by friday",
            "grade posted for recent exam view results",
            "new course available registration now open",
            "library notification book hold ready for pickup",
            "class schedule updated check your timetable",
            "assignment feedback available review comments",
            
            # General updates
            "software update available install at convenience",
            "maintenance scheduled system downtime tonight",
            "new policy announcement please review document",
            "benefits enrollment period opens next month",
            "holiday schedule office closed next week",
            "system upgrade completed new features available",
            "newsletter subscription confirmed welcome aboard",
        ]
        
        # Combine and create labels
        texts = phishing_samples + legitimate_samples
        labels = [1] * len(phishing_samples) + [0] * len(legitimate_samples)
        
        return texts, labels
    
    def train(self, save_model=True):
        """Train the ML model on phishing dataset"""
        print("📚 Loading training data...")
        texts, labels = self._get_training_data()
        
        print(f"📊 Dataset: {len(texts)} samples ({sum(labels)} phishing, {len(labels)-sum(labels)} legitimate)")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        print("🔄 Vectorizing text with TF-IDF...")
        X_train_vec = self.vectorizer.fit_transform(X_train)
        X_test_vec = self.vectorizer.transform(X_test)
        
        print("🌲 Training Random Forest Classifier (200 trees)...")
        self.model.fit(X_train_vec, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_vec)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\n✅ Model Training Complete!")
        print(f"📈 Accuracy: {accuracy*100:.2f}%")
        print("\n📊 Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        self.is_trained = True
        
        # Save model
        if save_model:
            self._save_model()
        
        return accuracy
    
    def predict_phishing(self, text):
        """
        Predict if text is phishing
        Returns: probability of being phishing (0-1)
        """
        if not self.is_trained:
            # Return fallback score based on keywords if model not trained
            return self._fallback_prediction(text)
        
        try:
            text_vec = self.vectorizer.transform([text])
            probability = self.model.predict_proba(text_vec)[0][1]  # Prob of phishing class
            return float(probability)
        except:
            return self._fallback_prediction(text)
    
    def _fallback_prediction(self, text):
        """Simple keyword-based fallback prediction"""
        text_lower = text.lower()
        phishing_keywords = [
            'verify', 'urgent', 'suspended', 'click here', 'winner',
            'claim', 'prize', 'congratulations', 'act now', 'limited time',
            'confirm', 'update', 'reset', 'locked', 'blocked'
        ]
        
        keyword_count = sum(1 for keyword in phishing_keywords if keyword in text_lower)
        return min(keyword_count / 10, 0.95)  # Cap at 95%
    
    def _save_model(self):
        """Save trained model to disk"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump({
                    'vectorizer': self.vectorizer,
                    'model': self.model
                }, f)
            print(f"💾 Model saved to {self.model_path}")
        except Exception as e:
            print(f"⚠️ Failed to save model: {e}")
    
    def _load_model(self):
        """Load trained model from disk"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.vectorizer = data['vectorizer']
                    self.model = data['model']
                    self.is_trained = True
                print(f"✅ Model loaded from {self.model_path}")
                return True
        except Exception as e:
            print(f"ℹ️ No existing model found, will train new model")
        return False

# Test the model if run directly
if __name__ == "__main__":
    detector = PhishingDetector()
    detector.train()
    
    # Test samples
    test_cases = [
        "urgent verify your account suspended click immediately",
        "your order has been shipped tracking number available",
        "congratulations you won the lottery claim prize now",
        "meeting scheduled for tomorrow at 3pm"
    ]
    
    print("\n🧪 Testing Model:")
    for text in test_cases:
        prob = detector.predict_phishing(text)
        label = "PHISHING" if prob > 0.5 else "LEGITIMATE"
        print(f"{label} ({prob*100:.1f}%): {text[:60]}...")
