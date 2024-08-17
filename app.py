from datetime import datetime
from sqlite3 import IntegrityError
from flask_login import current_user
import os
from sqlalchemy import func
from werkzeug.utils import secure_filename
from flask import Flask, abort, request, redirect, url_for, render_template, flash
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import SponsorInfluencerRequest, db, User, Sponsor, Influencer, Campaign, SponsorAdRequest
from extensions import db
from flask import session
from models import User, Sponsor, Influencer, Campaign, SponsorAdRequest

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite.db'
app.config['SECRET_KEY'] = 'your_secret_key'





# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'


migrate = Migrate(app, db) 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



#start here


@app.route('/')
def home():
    return render_template('index.html')
# Register Admin Sponsor Influenser
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        user = User(username=username, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('home'))
    
    return render_template('register.html')

# Login Admin
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user:
            if user.flagged:
                flash('Your account has been flagged. Please contact support.','danger')
                return redirect(url_for('admin_login'))

            if check_password_hash(user.password, password):
                if user.role == 'admin':  # Check if the user is an admin
                    login_user(user)
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('Access denied: Admins only.','danger')
            else:
                flash('Invalid credentials','danger')
        else:
            flash('User not found.','danger')
    return render_template('admin/admin_login.html')



@app.route('/admin_logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('admin_login'))


@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied: Admins only.')
        return redirect(url_for('user_login'))
    
    search_query = request.args.get('search', '')  # Get search query from the URL
    if search_query:
        users = User.query.filter(User.username.ilike(f'%{search_query}%')).all()
    else:
        users = User.query.all()

    total_users = User.query.count()
    num_sponsors = User.query.filter_by(role='sponsor').count()
    num_influencers = User.query.filter_by(role='influencer').count()
    num_admins = User.query.filter_by(role='admin').count()
    num_flagged_users = User.query.filter_by(flagged=True).count()
    num_unflagged_users = User.query.filter_by(flagged=False).count()
    num_active_users = User.query.filter_by(flagged=False).count()  # Assuming unflagged means active

    # Pass data to the template
    return render_template('admin/admin_dashboard.html', 
                           total_users=total_users,
                           num_sponsors=num_sponsors,
                           num_influencers=num_influencers,
                           num_admins=num_admins,
                           num_flagged_users=num_flagged_users,
                           num_unflagged_users=num_unflagged_users,
                           total_active_users=num_active_users,
                           users=users,
                           search_query=search_query)


# Flag User

@app.route('/user_flag/<int:user_id>/<action>', methods=['POST'])
@login_required
def user_flag(user_id, action):
    if current_user.role != 'admin':
        flash('Only admins can flag or unflag users.')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)

    if action == 'flag':
        user.flagged = True
        flash(f'{user.role.capitalize()} {user.username} has been flagged.')
    elif action == 'unflag':
        user.flagged = False
        flash(f'{user.role.capitalize()} {user.username} has been unflagged.')
    else:
        flash('Invalid action specified.')
        return redirect(url_for('admin_dashboard'))

    db.session.commit()
    return redirect(url_for('admin_dashboard'))

# Update User
@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
        db.session.commit()
        flash('User updated successfully')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/edit_user.html', user=user)


# Delete User
@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Handle related records
    Sponsor.query.filter_by(user_id=user_id).delete()
    Influencer.query.filter_by(user_id=user_id).delete()

    # Now delete the user
    db.session.delete(user)
    db.session.commit()

    flash('User deleted successfully')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_view_influencers', methods=['GET', 'POST'])
@login_required
def admin_view_influencers():
    search_category = request.args.get('category', '')
    search_niche = request.args.get('niche', '')

    # Filtering influencers based on search criteria
    influencers = Influencer.query.filter(
        Influencer.category.ilike(f"%{search_category}%"),
        Influencer.niche.ilike(f"%{search_niche}%")
    ).all()

    return render_template('admin/admin_view_influencers.html', influencers=influencers)

# Admin sponsor details graph
@app.route('/admin_view_sponsors')
@login_required
def admin_view_sponsors():
    search_query = request.args.get('search', '')  # Get the search query from the request

    if search_query:
        # Filter sponsors by the search query if provided
        sponsors = Sponsor.query.filter(Sponsor.title.ilike(f'%{search_query}%')).all()
    else:
        # Fetch all sponsors if no search query is provided
        sponsors = Sponsor.query.all()
    
    # Initialize the dictionary for campaigns by sponsor
    campaigns_by_sponsor = {}

    # Fetch campaigns and group them by sponsor
    for sponsor in sponsors:
        campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
        campaigns_by_sponsor[sponsor.id] = campaigns
    
    # Count the total number of sponsors
    total_sponsors = len(sponsors)
    
    # Render the template with the filtered sponsors
    return render_template('admin/admin_view_sponsors.html', sponsors=sponsors, total_sponsors=total_sponsors, campaigns_by_sponsor=campaigns_by_sponsor)


@app.route('/campaigns_summary')
def campaigns_summary():
    # Query for total campaigns by status
    status_counts = db.session.query(Campaign.status, db.func.count(Campaign.id)).group_by(Campaign.status).all()
    status_counts_dict = dict(status_counts) or {}

    # Query for detailed campaign progress
    campaigns = Campaign.query.all()
    campaign_details = [{
        'title': campaign.title,
        'progress': campaign.progress_percentage,
        'status': campaign.status,
        'start_date': campaign.start_date.strftime('%Y-%m-%d') if campaign.start_date else 'N/A',
        'end_date': campaign.end_date.strftime('%Y-%m-%d') if campaign.end_date else 'N/A'
    } for campaign in campaigns]
    
    # Prepare progress ranges for the chart
    progress_ranges = {'0-20': 0, '21-40': 0, '41-60': 0, '61-80': 0, '81-100': 0}
    for campaign in campaigns:
        progress = campaign.progress_percentage
        if 0 <= progress <= 20:
            progress_ranges['0-20'] += 1
        elif 21 <= progress <= 40:
            progress_ranges['21-40'] += 1
        elif 41 <= progress <= 60:
            progress_ranges['41-60'] += 1
        elif 61 <= progress <= 80:
            progress_ranges['61-80'] += 1
        elif 81 <= progress <= 100:
            progress_ranges['81-100'] += 1

    return render_template(
        'admin/campaigns_summary.html',
        status_counts=status_counts_dict,
        progress_ranges=progress_ranges,
        campaign_details=campaign_details
    )

@app.route('/requests_summary')
def requests_summary():
    # Fetch all ad requests
    ad_requests = SponsorAdRequest.query.all()

    # Calculate status counts
    ad_requests_statuses = {
        'accepted': SponsorAdRequest.query.filter_by(status='Accepted').count(),
        'rejected': SponsorAdRequest.query.filter_by(status='Rejected').count(),
        'pending': SponsorAdRequest.query.filter_by(status='Pending').count(),
        'in_progress': SponsorAdRequest.query.filter_by(status='In Progress').count(),
        'completed': SponsorAdRequest.query.filter_by(status='Completed').count()
    }

    return render_template('admin/requests_summary.html', ad_requests=ad_requests, ad_requests_statuses=ad_requests_statuses)



#Login User

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user is a sponsor
        sponsor_user = User.query.filter_by(username=username, role="sponsor").first()
        
        if sponsor_user and check_password_hash(sponsor_user.password, password):
            if sponsor_user.flagged:
                flash('Your account has been flagged. Please contact support.','danger')
                return redirect(url_for('login'))

            # Log in the sponsor user
            login_user(sponsor_user)
            session["user_name"] = sponsor_user.username
            session["role"] = sponsor_user.role
            session["user_id"] = sponsor_user.id
            
            flash("Login successful!", "success")
            return redirect(url_for('sponsor_dashboard'))

        # Check if the user is an influencer
        influencer_user = User.query.filter_by(username=username, role="influencer").first()

        if influencer_user and check_password_hash(influencer_user.password, password):
            if influencer_user.flagged:
                flash('Your account has been flagged. Please contact support.','danger')
                return redirect(url_for('login'))

            # Log in the influencer user
            login_user(influencer_user)
            session["user_name"] = influencer_user.username
            session["role"] = influencer_user.role
            session["user_id"] = influencer_user.id

            flash("Login successful!", "success")
            return redirect(url_for('influencer_dashboard'))

        else:
            flash('Invalid User name or password', 'danger')

    return render_template('login.html')


# create Sponsor
@app.route('/create_sponsor', methods=['GET', 'POST'])
@login_required
def create_sponsor():
    if request.method == 'POST':
        title = request.form['title']
        industry = request.form['industry']
        budget = request.form['budget']
        description = request.form['description']
        
        # Handling file upload
        image_path = None
        if 'image' in request.files:
            image = request.files['image']
            if image.filename != '':
                # Save the file and set image_path
                image_path = f"images/{secure_filename(image.filename)}"
                image.save(os.path.join(app.root_path, 'static', image_path))
        
        # Create the sponsor with the image path
        sponsor = Sponsor(user_id=current_user.id, title=title, industry=industry, budget=budget, description=description, image=image_path)
        db.session.add(sponsor)
        db.session.commit()
        flash('Sponsor created successfully')
        return redirect(url_for('sponsor_dashboard'))
    
    return render_template('sponsor/create_sponsor.html')


@app.route('/sponsor_dashboard')
@login_required
def sponsor_dashboard():
    if "user_name" in session and session["role"] == "sponsor":
        # Fetch the sponsor's information from the database
        sponsor = Sponsor.query.filter_by(user_id=session["user_id"]).first()

        if not sponsor:
            flash("Sponsor profile not found. Please create a profile first.")
            return redirect(url_for('create_sponsor'))

        # Fetch campaigns created by this sponsor
        campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()

        # Campaign data
        campaign_data = [
            {
                "id": campaign.id,
                "title": campaign.title,
                "status": campaign.status,
                "completion_percentage": campaign.completion_percentage,
                "start_date": campaign.start_date,
                "end_date": campaign.end_date
            }
            for campaign in campaigns
        ]

        return render_template(
            "sponsor/sponsor_dashboard.html", 
            sponsor=sponsor, 
            campaigns=campaigns, 
            user_name=session["user_name"],
            role=session["role"],
            campaign_data=campaign_data
        )
    
    flash("Please Login!", "failed")
    return redirect(url_for('login'))


# Update Sponsor
@app.route('/update_sponsor/<int:sponsor_id>', methods=['GET', 'POST'])
@login_required
def update_sponsor(sponsor_id):
    sponsor = Sponsor.query.get_or_404(sponsor_id)
    if request.method == 'POST':
        sponsor.title = request.form['title']
        sponsor.industry = request.form['industry']
        sponsor.budget = request.form['budget']
        sponsor.description = request.form['description']
        
        # Handling file upload
        if 'image' in request.files:
            image = request.files['image']
            if image.filename != '':
                # Save the file and update sponsor.image
                image_path = f"images/{image.filename}"
                image.save(os.path.join(app.root_path, 'static', image_path))
                sponsor.image = image_path
        
        db.session.commit()
        flash('Sponsor updated successfully')
        return redirect(url_for('sponsor_dashboard'))
    
    return render_template('sponsor/update_sponsor.html', sponsor=sponsor)


# Delete Sponsor


@app.route('/confirm_delete_sponsor/<int:sponsor_id>', methods=['GET'])
@login_required
def confirm_delete_sponsor(sponsor_id):
    sponsor = Sponsor.query.get_or_404(sponsor_id)
    return render_template('sponsor/confirm_delete.html', sponsor=sponsor)

@app.route('/delete_sponsor/<int:sponsor_id>', methods=['POST'])
@login_required
def delete_sponsor(sponsor_id):
    sponsor = Sponsor.query.get_or_404(sponsor_id)
    db.session.delete(sponsor)
    db.session.commit()
    flash('Sponsor deleted successfully')
    return redirect(url_for('home'))


# Create Influencer

@app.route('/create_influencer', methods=['GET', 'POST'])
@login_required
def create_influencer():
    if request.method == 'POST':
        category = request.form['category']
        reach = request.form['reach']
        niche = request.form['niche']
        description = request.form['description']
        platform_presence = request.form['platform_presence']
        
        # Handling file upload
        profile_picture_path = None
        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            if profile_picture.filename != '':
                # Save the file and set profile_picture_path
                profile_picture_path = f"images/{secure_filename(profile_picture.filename)}"
                profile_picture.save(os.path.join(app.root_path, 'static', profile_picture_path))
        
        # Create the influencer with the profile picture path
        influencer = Influencer(
            user_id=current_user.id,
            profile_picture=profile_picture_path,
            category=category,
            reach=reach,
            niche=niche,
            description=description,
            platform_presence=platform_presence
        )
        db.session.add(influencer)
        db.session.commit()
        flash('Influencer profile created successfully')
        return redirect(url_for('influencer_dashboard'))

    return render_template('influencer/create_influencer.html')

 # Update Influencer

@app.route('/update_influencer/<int:influencer_id>', methods=['GET', 'POST'])
@login_required
def update_influencer(influencer_id):
    influencer = Influencer.query.get_or_404(influencer_id)
    if request.method == 'POST':
        # Handle form data
        influencer.category = request.form['category']
        influencer.reach = request.form['reach']
        influencer.niche = request.form['niche']
        influencer.description = request.form['description']
        influencer.platform_presence = request.form['platform_presence']

        # Handle file upload
        new_profile_picture = request.files.get('new_profile_picture')
        if new_profile_picture and new_profile_picture.filename != '':
            # Save the new image file
            image_path = f"images/{secure_filename(new_profile_picture.filename)}"
            new_profile_picture.save(os.path.join(app.root_path, 'static', image_path))
            influencer.profile_picture = image_path

        db.session.commit()
        flash('Influencer profile updated successfully')
        return redirect(url_for('influencer_dashboard'))

    return render_template('influencer/update_influencer.html', influencer=influencer)


# Delete Influencer
@app.route('/confirm_delete_influencer/<int:influencer_id>', methods=['GET'])
@login_required
def confirm_delete_influencer(influencer_id):
    influencer = Influencer.query.get_or_404(influencer_id)
    return render_template('influencer/confirm_delete.html', influencer=influencer)


@app.route('/delete_influencer/<int:influencer_id>', methods=['POST'])
@login_required
def delete_influencer(influencer_id):
    influencer = Influencer.query.get_or_404(influencer_id)

    # Remove related ad requests
    SponsorAdRequest.query.filter_by(influencer_id=influencer_id).delete()
    SponsorInfluencerRequest.query.filter_by(influencer_id=influencer_id).delete()

    # Delete the influencer
    db.session.delete(influencer)

    try:
        db.session.commit()
        flash('Influencer deleted successfully')
    except IntegrityError as e:
        db.session.rollback()
        flash('Error deleting influencer: IntegrityError')
        print(f'IntegrityError: {e}')

    return redirect(url_for('home'))


@app.route('/influencer_dashboard')
@login_required
def influencer_dashboard():
    if "user_name" in session and "role" in session:
        if session["role"] == "influencer":
            user_id = session["user_id"]

            # Fetch influencer information
            influencer = Influencer.query.filter_by(user_id=user_id).first()
            if not influencer:
                flash("Influencer profile not found.")
                return redirect(url_for('create_influencer'))
            
            # Fetch pending ad requests
            pending_requests = SponsorAdRequest.query.filter_by(influencer_id=influencer.id, status='pending').all()
            has_pending_requests = bool(pending_requests)

            return render_template(
                'influencer/influencer_dashboard.html',
                influencer=influencer,
                pending_requests=pending_requests,
                has_pending_requests=has_pending_requests
            )
        else:
            flash("You must be logged in as an influencer to view this page.", 'danger')
            return redirect(url_for('login'))

    flash("You must be logged in to view this page.", 'danger')
    return redirect(url_for('login'))


# Campaign 

@app.route('/create_campaign', methods=['GET', 'POST'])
@login_required
def create_campaign():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description')
        image = request.files.get('image')
        niche = request.form.get('niche')
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        budget = float(request.form['budget'])
        goal = request.form['goal']
        visibility = request.form['visibility']

        if "user_name" in session and session["role"] == "sponsor":
            user_id = session["user_id"]
            sponsor = Sponsor.query.filter_by(user_id=user_id).first()
            if sponsor:
                sponsor_id = sponsor.id
            else:
                flash('Sponsor not found!', 'error')
                return redirect(url_for('create_campaign'))

            # Handle the image upload
            image_path = None
            if image and image.filename != '':
                image_path = f"images/{secure_filename(image.filename)}"
                image.save(os.path.join(app.root_path, 'static', image_path))

            new_campaign = Campaign(
                title=title,
                description=description,
                image=image_path,
                niche=niche,
                start_date=start_date,
                end_date=end_date,
                budget=budget,
                goal=goal,
                visibility=visibility,
                sponsor_id=sponsor_id
            )

            db.session.add(new_campaign)
            db.session.commit()
            flash('Campaign created successfully!', 'success')
            return redirect(url_for('list_campaigns'))

        else:
            flash('You must be a sponsor to create a campaign.', 'danger')
            return redirect(url_for('login'))

    return render_template('campaign/create_campaign.html')

@app.route('/list_campaigns', methods=['GET'])
@login_required
def list_campaigns():
    if "user_name" in session and session["role"] == "sponsor":
        user_id = session["user_id"]
        sponsor = Sponsor.query.filter_by(user_id=user_id).first()
        if sponsor:
            campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
            return render_template('campaign/list_campaigns.html', campaigns=campaigns)
        else:
            flash('Sponsor not found!', 'error')
            return redirect(url_for('create_campaign'))
    else:
        flash('You must be a sponsor to view campaigns.', 'danger')
        return redirect(url_for('login'))

   

@app.route('/campaign_details/<int:campaign_id>')
@login_required
def campaign_details(campaign_id):
    if "user_name" in session and session["role"] == "sponsor":
        user_id = session["user_id"]

        # Fetch the sponsor associated with the user_id
        sponsor = Sponsor.query.filter_by(user_id=user_id).first()

        if sponsor:
            # Fetch the campaign
            campaign = Campaign.query.get_or_404(campaign_id)
            
            # Check if the campaign belongs to the sponsor
            if campaign.sponsor_id == sponsor.id:
                return render_template('campaign/campaign_detail.html', campaign=campaign)
            else:
                flash('You do not have permission to view this campaign.', 'danger')
                return redirect(url_for('list_campaigns'))
        else:
            flash('Sponsor not found.', 'danger')
            return redirect(url_for('login'))
    
    flash('You must be logged in as a sponsor to view campaign details.', 'danger')
    return redirect(url_for('login'))


# Update a campaign
@app.route('/update_campaign/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def update_campaign(campaign_id):
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description')
        image = request.files.get('image')
        niche = request.form.get('niche')
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        budget = float(request.form['budget'])
        goal = request.form['goal']
        visibility = request.form['visibility']

        if "user_name" in session and session["role"] == "sponsor":
            user_id = session["user_id"]
            sponsor = Sponsor.query.filter_by(user_id=user_id).first()
            if sponsor:
                campaign = Campaign.query.get_or_404(campaign_id)
                if campaign.sponsor_id == sponsor.id:
                    if image and image.filename != '':
                        image_path = f"images/{secure_filename(image.filename)}"
                        image.save(os.path.join(app.root_path, 'static', image_path))
                        campaign.image = image_path

                    campaign.title = title
                    campaign.description = description
                    campaign.niche = niche
                    campaign.start_date = start_date
                    campaign.end_date = end_date
                    campaign.budget = budget
                    campaign.goal = goal
                    campaign.visibility = visibility

                    db.session.commit()
                    flash('Campaign updated successfully!', 'success')
                    return redirect(url_for('campaign_details', campaign_id=campaign.id))
                else:
                    flash('You do not have permission to update this campaign.', 'danger')
                    return redirect(url_for('list_campaigns'))
            else:
                flash('Sponsor not found.', 'danger')
                return redirect(url_for('login'))

    else:
        campaign = Campaign.query.get_or_404(campaign_id)
        if "user_name" in session and session["role"] == "sponsor":
            user_id = session["user_id"]
            sponsor = Sponsor.query.filter_by(user_id=user_id).first()
            if sponsor and campaign.sponsor_id == sponsor.id:
                return render_template('campaign/update_campaign.html', campaign=campaign)
            else:
                flash('You do not have permission to update this campaign.', 'danger')
                return redirect(url_for('list_campaigns'))

        flash('You must be logged in as a sponsor to update campaign details.', 'danger')
        return redirect(url_for('login'))

@app.route('/delete_campaign/<int:campaign_id>', methods=['POST'])
@login_required
def delete_campaign(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    if campaign:
        # Optionally handle related records first
        SponsorAdRequest.query.filter_by(campaign_id=campaign_id).delete()
        
        db.session.delete(campaign)
        try:
            db.session.commit()
            flash('Campaign deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error deleting campaign: {str(e)}', 'danger')
    else:
        flash('Campaign not found.', 'danger')

    return redirect(url_for('list_campaigns'))


 






# Search campaigns
@app.route('/search_campaigns', methods=['GET'])
def search_campaigns():
    # Get the query parameter from the request
    query = request.args.get('q', '').strip()
    
    if query:
        # Search campaigns by title or niche using a case-insensitive search
        search_results = Campaign.query.filter(
            Campaign.title.ilike(f'%{query}%') |
            Campaign.niche.ilike(f'%{query}%')
        ).all()
    else:
        # If no query, return a message or handle it as needed
        # For example, you could render a message or an empty list
        search_results = []
        flash('Please enter a search query to find campaigns.')  # Optional: Add a flash message if using Flask
        # Alternatively, you might redirect to a different page or handle this in the template
    
    return render_template('campaign/list_campaigns.html', campaigns=search_results)


# SponsorAdrequest 

# Sending request with campain and influensor 


@app.route('/manage_adrequest', methods=['GET', 'POST'])
@login_required
def manage_adrequest():
    if request.method == 'POST':
        # Handle the form submission
        user_id = session.get("user_id")
        if not user_id:
            flash('You must be logged in to send requests.', 'danger')
            return redirect(url_for('login'))
        
        sponsor = Sponsor.query.filter_by(user_id=user_id).first()
        if sponsor:
            campaign_id = request.form.get('campaign_id')
            influencer_id = request.form.get('influencer_id')
            campaign = Campaign.query.filter_by(id=campaign_id, sponsor_id=sponsor.id).first()
            influencer = Influencer.query.filter_by(id=influencer_id).first()
            if campaign and influencer:
                # Create a new request
                message = request.form.get('message')
                new_request = SponsorAdRequest(
                    campaign_id=campaign_id,
                    influencer_id=influencer_id,
                    sponsor_id=sponsor.id,
                    message=message,
                    status='pending'  # or any initial status
                )
                db.session.add(new_request)
                db.session.commit()
                flash('Request sent successfully!', 'success')
                return redirect(url_for('manage_adrequest'))
            else:
                flash('Campaign or Influencer not found, or you do not have permission.', 'error')
        else:
            flash('Sponsor not found!', 'error')
            return redirect(url_for('login'))
    
    # Handle the GET request
    user_id = session.get("user_id")
    if not user_id:
        flash('You must be logged in to view this page.', 'danger')
        return redirect(url_for('login'))
    
    sponsor = Sponsor.query.filter_by(user_id=user_id).first()
    if sponsor:
        campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
        influencers = Influencer.query.all()  # Adjust as needed
        return render_template('Adrequest/manage_adrequest.html', campaigns=campaigns, influencers=influencers)
    else:
        flash('Sponsor not found!', 'error')
        return redirect(url_for('list_campaigns'))

# sponsor view status
@app.route('/view_adrequests', methods=['GET'])
@login_required
def view_adrequests():
    user_id = session.get("user_id")
    if not user_id:
        flash('You must be logged in to view this page.', 'danger')
        return redirect(url_for('login'))
    
    sponsor = Sponsor.query.filter_by(user_id=user_id).first()
    if not sponsor:
        flash('Sponsor not found!', 'error')
        return redirect(url_for('login'))
    
    # Fetch only the sponsor's ad requests
    requests = SponsorAdRequest.query.filter_by(sponsor_id=sponsor.id).all()
    
    return render_template('Adrequest/view_adrequests.html', requests=requests)


    flash("Please Login!", "failed")
    return redirect(url_for("login"))


#Influenser view status and responds

@app.route('/manage_influencer_adrequests', methods=['GET', 'POST'])
@login_required
def manage_influencer_adrequests():
    if session.get("role") == "influencer":
        influencer = Influencer.query.filter_by(user_id=session["user_id"]).first()
        
        if not influencer:
            flash("Influencer profile not found.", "error")
            return redirect(url_for('create_influencer'))

        if request.method == 'POST':
            request_id = request.form.get("request_id")
            action = request.form.get("action")

            ad_request = SponsorAdRequest.query.filter_by(id=request_id, influencer_id=influencer.id).first()

            if not ad_request:
                flash("Error: Ad request not found.", "error")
                return redirect(url_for("manage_influencer_adrequests"))

            if action == 'accept':
                ad_request.status = 'Accepted'
            elif action == 'reject':
                ad_request.status = 'Rejected'
            else:
                flash("Error: Invalid action.", "error")
                return redirect(url_for("manage_influencer_adrequests"))

            try:
                db.session.commit()
                flash(f"Ad request {action}ed successfully.", "success")
            except Exception as e:
                error_message = str(e).split("\n")[0]
                flash(f"Error: {error_message}", "error")
                db.session.rollback()

            return redirect(url_for("manage_influencer_adrequests"))

        ad_requests = SponsorAdRequest.query.filter_by(influencer_id=influencer.id).all()

        ad_requests_with_details = []
        for ad_request in ad_requests:
            sponsor = Sponsor.query.get(ad_request.sponsor_id)
            campaign = Campaign.query.get(ad_request.campaign_id)
            ad_requests_with_details.append({
                'id': ad_request.id,
                'status': ad_request.status,
                'sponsor_id': ad_request.sponsor_id,
                'campaign_id': ad_request.campaign_id,
                'sponsor_name': sponsor.user.username if sponsor and sponsor.user else 'Unknown',
                'campaign_title': campaign.title if campaign else 'Unknown',
                'campaign_budget': campaign.budget if campaign else 'Unknown',  # Include budget here
                'message': ad_request.message
            })

        return render_template(
            "Adrequest/manage_influencer_adrequests.html",
            ad_requests=ad_requests_with_details
        )

    flash("Please Login!", "failed")
    return redirect(url_for("login"))



    flash("Please Login!", "failed")
    return redirect(url_for("login"))

# view campaign details stauts
#influencer side view 
@app.route('/view_campaign/<int:campaign_id>')
@login_required
def view_campaign(campaign_id):
    # Fetch the campaign based on the ID
    campaign = Campaign.query.get_or_404(campaign_id)
    
    # Calculate the progress percentage
    progress_percentage = campaign.progress_percentage
    
    # Update status and completion based on progress
    campaign.update_status_and_completion()

    # Render the template with additional campaign details
    return render_template('Adrequest/view_campaign.html', 
                           campaign=campaign, 
                           progress_percentage=progress_percentage)

# SponsorInfluensorRequest

@app.route('/send_influensor_request', methods=['GET', 'POST'])
@login_required
def send_influensor_request():
    if request.method == 'POST':
        user_id = current_user.id
        influencer = Influencer.query.filter_by(user_id=user_id).first()
        
        if influencer:
            campaign_id = request.form.get('campaign_id')
            message = request.form.get('message')
            payment_amount = request.form.get('payment_amount')
            
            campaign = Campaign.query.filter_by(id=campaign_id).first()
            if campaign:
                sponsor = Sponsor.query.filter_by(id=campaign.sponsor_id).first()
                if sponsor:
                    # Ensure influencer_id is not None
                    if influencer.id is None:
                        flash('Influencer ID is missing!', 'error')
                        return redirect(url_for('send_influensor_request'))

                    new_request = SponsorInfluencerRequest(
                        campaign_id=campaign_id,
                        influencer_id=influencer.id,
                        sponsor_id=sponsor.id,
                        message=message,
                        status='Pending',
                        payment_amount=payment_amount
                    )
                    
                    db.session.add(new_request)
                    db.session.commit()
                    
                    flash('Request sent successfully!', 'success')
                    return redirect(url_for('send_influensor_request'))
                else:
                    flash('Sponsor not found for the selected campaign.', 'error')
            else:
                flash('Campaign not found.', 'error')
        
        else:
            flash('Influencer not found!', 'error')
            return redirect(url_for('login'))
    
    if not current_user.is_authenticated:
        flash('You must be logged in to view this page.', 'danger')
        return redirect(url_for('login'))
    
    influencer = Influencer.query.filter_by(user_id=current_user.id).first()
    if influencer:
        # Fetch all campaigns
        campaigns = Campaign.query.all()
        return render_template('SponsorInfluencerRequest/send_influensor_request.html', campaigns=campaigns)
    else:
        flash('Influencer not found!', 'error')
        return redirect(url_for('send_influensor_request'))


@app.route('/receive_requests', methods=['GET'])
@login_required
def receive_requests():
    user_id = current_user.id

    # Determine if the user is an influencer or sponsor
    influencer = Influencer.query.filter_by(user_id=user_id).first()
    sponsor = Sponsor.query.filter_by(user_id=user_id).first()

    if influencer:
        # Fetch all requests where the influencer is the recipient
        requests = SponsorInfluencerRequest.query.filter_by(influencer_id=influencer.id).all()
        # Fetch and attach details for each request (relationships handle this)
        return render_template('SponsorInfluencerRequest/receive_requests.html', requests=requests, user_type='influencer')

    elif sponsor:
        # Fetch all requests where the sponsor is the sender
        requests = SponsorInfluencerRequest.query.filter_by(sponsor_id=sponsor.id).all()
        # Fetch and attach details for each request (relationships handle this)
        return render_template('SponsorInfluencerRequest/receive_requests.html', requests=requests, user_type='sponsor')

    else:
        flash('User not found!', 'error')
        return redirect(url_for('login'))

@app.route('/accept_request/<int:request_id>', methods=['POST'])
@login_required
def accept_request(request_id):
    ad_request = SponsorInfluencerRequest.query.get_or_404(request_id)
    
    if ad_request:
        ad_request.status = 'Accepted'
        db.session.commit()
        flash('Request accepted successfully.', 'success')
    else:
        flash('Request not found.', 'error')
    
    return redirect(url_for('receive_requests'))

@app.route('/reject_request/<int:request_id>', methods=['POST'])
@login_required
def reject_request(request_id):
    ad_request = SponsorInfluencerRequest.query.get_or_404(request_id)
    
    if ad_request:
        ad_request.status = 'Rejected'
        db.session.commit()
        flash('Request rejected successfully.', 'success')
    else:
        flash('Request not found.', 'error')
    
    return redirect(url_for('receive_requests'))


@app.route('/view_influencer_requests', methods=['GET'])
@login_required
def view_influencer_requests():
    user_id = current_user.id
    influencer = Influencer.query.filter_by(user_id=user_id).first()
    
    if influencer:
        # Fetch all requests where the influencer is the recipient
        requests = SponsorInfluencerRequest.query.filter_by(influencer_id=influencer.id).all()
        
        # Fetch sponsor details for each request
        requests_with_sponsors = []
        for request in requests:
            sponsor = Sponsor.query.filter_by(id=request.sponsor_id).first()
            requests_with_sponsors.append({
                'request': request,
                'sponsor_name': sponsor.user.username if sponsor else 'Unknown'
            })
        
        return render_template('SponsorInfluencerRequest/view_influencer_requests.html', requests=requests_with_sponsors)
    
    else:
        flash('Influencer not found!', 'error')
        return redirect(url_for('login'))


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Load expiration date from environment or config
EXPIRATION_DATE = os.getenv('EXPIRATION_DATE', '2024-08-20')  

def is_expired():
    try:
        expiration_date = datetime.strptime(EXPIRATION_DATE, '%Y-%m-%d')
        return datetime.now() > expiration_date
    except ValueError:
        return False

@app.before_request
def check_expiration():
    if is_expired() and request.endpoint not in ['maintenance']:
        return redirect(url_for('maintenance'))

@app.route('/maintenance')
def maintenance():
    return render_template('maintenance.html')

if __name__ == '__main__':
    app.run(debug=True)
