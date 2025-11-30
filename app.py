from flask import Flask, render_template

# Create the Flask application instance
app = Flask(__name__)

# Define the route for the home page ('/')
@app.route('/')
def hello_world():
    return render_template('index.html')

# This runs the application
if __name__ == '__main__':
    app.run(debug=True)