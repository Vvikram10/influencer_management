# create_db.py
from app import app
from extensions import db
from models import User, Sponsor, Influencer, Campaign, SponsorAdRequest,SponsorInfluencerRequest

# with app.app_context():
#     db.create_all()
#     print("Database created!")



with app.app_context():
    db.drop_all()
    print("Database dropped")
