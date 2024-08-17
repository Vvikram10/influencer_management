It is Influencer management and sponsorship platform using Flask Jinja 2 SQlite3
First you should create virtual environment to run project
cmd-> python -m venv virtual
now activate virtual environment 
cmd windows -> virtual\Scripts\activate
now install requirements like -
cmd : 1. pip install Flask Flask-SQLAlchemy 
      2. pip install Flask-Login Flask-Migrate
      3. now migrate database using cmd
          1. Flask db init
          2. Flask db migrate -m "initial migrate"
          3. Flask db upgrade 
           now run -> python app.py


At last important things i have mentioned in mentinence part at end of app.py so plz make sure when someone use this code plz increase date from current date so that you dont have face any problem to run project.....

Good Luck and Thank you for visiting...
