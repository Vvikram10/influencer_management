from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from extensions import db

# Assuming your models are as follows:

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # admin, sponsor, influencer
    flagged = db.Column(db.Boolean, default=False)  # Flagged status

    # Relationships
    sponsors = db.relationship('Sponsor', backref='creator', cascade="all, delete", lazy=True)
    influencers = db.relationship('Influencer', backref='creator', cascade="all, delete", lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Sponsor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_sponsor_user'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    industry = db.Column(db.String(100))
    budget = db.Column(db.Float)
    description = db.Column(db.Text)
    image = db.Column(db.String(200))

    # Relationship to User model
    user = db.relationship('User', backref=db.backref('sponsored_campaigns', lazy=True))

    def __repr__(self):
        return f'<Sponsor {self.title}>'

class Influencer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    profile_picture = db.Column(db.String(200))
    category = db.Column(db.String(100))
    reach = db.Column(db.String(100))
    niche = db.Column(db.String(100))
    description = db.Column(db.Text)
    platform_presence = db.Column(db.String(200))

    # Relationship to User model
    user = db.relationship('User', backref=db.backref('influenced_campaigns', lazy=True))

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    image = db.Column(db.String(200))
    niche = db.Column(db.String(100))
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    budget = db.Column(db.Float)
    goal = db.Column(db.String(150))
    visibility = db.Column(db.String(50))
    status = db.Column(db.String(50), default="Not Started")  # Track campaign status
    completion_percentage = db.Column(db.Float, default=0.0)  # Store completion percentage

    sponsor = db.relationship('Sponsor', backref=db.backref('campaigns', cascade='all, delete-orphan'))
    sponsor_ad_requests = db.relationship('SponsorAdRequest', backref='campaign_related_requests', cascade='all, delete-orphan')
    sponsor_influencer_requests = db.relationship('SponsorInfluencerRequest', backref='campaign_related_influencer_requests', cascade='all, delete-orphan')
    @property
    def progress_percentage(self):
        now = datetime.utcnow().date()
        if self.start_date and self.end_date:
            if self.start_date.date() == self.end_date.date():
                return 100 if now == self.start_date.date() else 0
            
            if now < self.start_date.date():
                return 0
            if now > self.end_date.date():
                return 100
            total_duration = (self.end_date - self.start_date).days
            elapsed_duration = (now - self.start_date.date()).days
            return int((elapsed_duration / total_duration) * 100) if total_duration > 0 else 0
        return 0

    def update_status_and_completion(self):
        progress = self.progress_percentage
        self.completion_percentage = progress

        if progress == 0:
            self.status = "Not Started"
        elif 0 < progress < 100:
            self.status = "In Progress"
        else:
            self.status = "Completed"

        db.session.commit()

class SponsorAdRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencer.id'), nullable=False)
    message = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='Pending')
    date_sent = db.Column(db.DateTime, default=datetime.utcnow)

    campaign = db.relationship('Campaign', backref='sponsor_ad_requests_related')
    sponsor = db.relationship('Sponsor', backref='sponsor_ad_requests')
    influencer = db.relationship('Influencer', backref='sponsor_ad_requests')

    def __repr__(self):
        return f'<SponsorAdRequest {self.id}>'

class SponsorInfluencerRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencer.id'), nullable=False)
    message = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='Pending')
    payment_amount = db.Column(db.Float, nullable=True)  # New field for payment amount
    date_sent = db.Column(db.DateTime, default=datetime.utcnow)

    campaign = db.relationship('Campaign', backref='sponsor_influencer_requests_related')
    sponsor = db.relationship('Sponsor', backref='sponsor_influencer_requests')
    influencer = db.relationship('Influencer', backref='sponsor_influencer_requests')

    def __repr__(self):
        return f'<SponsorInfluencerRequest {self.id}>'